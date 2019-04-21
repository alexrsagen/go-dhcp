package ifnet

import (
	"errors"
	"net"
	"syscall"
	"unsafe"
)

func (c *UDPConn) Close() error {
	if c.fd != 0 {
		if err := syscall.Closesocket(c.fd); err != nil {
			return err
		}

		if err := syscall.WSACleanup(); err != nil {
			return err
		}
	}

	return nil
}

func (c *UDPConn) WriteToUDP(p []byte, raddr *net.UDPAddr) (int, error) {
	buf := &syscall.WSABuf{
		Len: uint32(len(p)),
	}
	if len(p) > 0 {
		buf.Buf = &p[0]
	}

	var sent uint32
	if err := syscall.WSASendto(c.fd, buf, 1, &sent, 0, sockaddrFromAddr(raddr), nil, nil); err != nil {
		return 0, err
	}

	return int(sent), nil
}

func (c *UDPConn) ReadFromUDP(b []byte) (int, *net.UDPAddr, error) {
	bufs := make([]syscall.WSABuf, 1)
	var src syscall.RawSockaddrAny
	var recvd, flags uint32
	var srclen int32

	if err := syscall.WSARecvFrom(c.fd, &bufs[0], 1, &recvd, &flags, &src, &srclen, nil, nil); err != nil {
		return 0, nil, err
	}

	raddr, err := src.Sockaddr()
	if err != nil {
		return 0, nil, err
	}
	addr := sockaddrToAddr(c.network, raddr)
	if _, ok := addr.(*net.UDPAddr); !ok {
		return 0, nil, errors.New("invalid source address")
	}

	if cap(b) < int(recvd) {
		return 0, addr.(*net.UDPAddr), errors.New("buffer too small")
	}
	sl := struct {
		addr     uintptr
		len, cap int
	}{uintptr(unsafe.Pointer(bufs[0].Buf)), int(bufs[0].Len), int(bufs[0].Len)}
	copy(b, *(*[]byte)(unsafe.Pointer(&sl)))

	return int(recvd), addr.(*net.UDPAddr), nil
}

// ListenUDP acts like net.ListenUDP, with the following exceptions:
//
// - It additionally takes a local interface to listen on
// - You may listen on an unspecified address (0.0.0.0/32 or ::/128)
func ListenUDP(network string, laddr *net.UDPAddr, lif *net.Interface) (*UDPConn, error) {
	data := &syscall.WSAData{}
	err := syscall.WSAStartup(8, data)
	if err != nil {
		return nil, err
	}

	syscall.ForkLock.RLock()
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, syscall.IPPROTO_UDP)
	c := &UDPConn{conn: conn{
		network: network,
		fd:      fd,
	}}
	if err != nil {
		c.Close()
		syscall.ForkLock.RUnlock()
		return nil, err
	}
	syscall.CloseOnExec(fd)
	syscall.ForkLock.RUnlock()

	var optval byte
	optval = 1
	var optlen int32
	optlen = 1
	if err := syscall.Setsockopt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, &optval, optlen); err != nil {
		c.Close()
		return nil, err
	}
	if err := syscall.Setsockopt(fd, syscall.SOL_SOCKET, syscall.SO_BROADCAST, &optval, optlen); err != nil {
		c.Close()
		return nil, err
	}
	// if err := syscall.Getsockopt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, &optval, &optlen); err != nil {
	// 	c.Close()
	// 	return nil, err
	// }
	// fmt.Println(optval)

	if err = syscall.Bind(fd, sockaddrFromAddr(laddr)); err != nil {
		c.Close()
		return nil, err
	}

	return c, nil
}
