package ifnet

import (
	"net"
	"syscall"
)

type conn struct {
	fd      syscall.Handle
	network string
}

type Conn interface {
	Close() error
}

type UDPConn struct {
	conn
}

func sockaddrFromAddr(addr net.Addr) syscall.Sockaddr {
	switch addr.(type) {
	case *net.UDPAddr:
		if ip := addr.(*net.UDPAddr).IP.To4(); ip != nil {
			addr4 := &syscall.SockaddrInet4{
				Port: addr.(*net.UDPAddr).Port,
			}
			copy(addr4.Addr[:4], ip)
			return syscall.Sockaddr(addr4)
		} else if ip := addr.(*net.UDPAddr).IP.To16(); ip != nil {
			addr6 := &syscall.SockaddrInet6{
				Port: addr.(*net.UDPAddr).Port,
			}
			copy(addr6.Addr[:16], ip)
			return syscall.Sockaddr(addr6)
		}
	case *net.TCPAddr:
		if ip := addr.(*net.TCPAddr).IP.To4(); ip != nil {
			addr4 := &syscall.SockaddrInet4{
				Port: addr.(*net.TCPAddr).Port,
			}
			copy(addr4.Addr[:4], ip)
			return syscall.Sockaddr(addr4)
		} else if ip := addr.(*net.TCPAddr).IP.To16(); ip != nil {
			addr6 := &syscall.SockaddrInet6{
				Port: addr.(*net.TCPAddr).Port,
			}
			copy(addr6.Addr[:16], ip)
			return syscall.Sockaddr(addr6)
		}
	}

	return nil
}

func sockaddrToAddr(network string, addr syscall.Sockaddr) net.Addr {
	switch addr.(type) {
	case *syscall.SockaddrInet4:
		switch network {
		case "udp", "udp4":
			return net.Addr(&net.UDPAddr{
				IP:   addr.(*syscall.SockaddrInet4).Addr[:4],
				Port: addr.(*syscall.SockaddrInet4).Port,
			})
		case "tcp", "tcp4":
			return net.Addr(&net.TCPAddr{
				IP:   addr.(*syscall.SockaddrInet4).Addr[:4],
				Port: addr.(*syscall.SockaddrInet4).Port,
			})
		}
	case *syscall.SockaddrInet6:
		switch network {
		case "udp", "udp6":
			return net.Addr(&net.UDPAddr{
				IP:   addr.(*syscall.SockaddrInet6).Addr[:16],
				Port: addr.(*syscall.SockaddrInet6).Port,
			})
		case "tcp", "tcp6":
			return net.Addr(&net.TCPAddr{
				IP:   addr.(*syscall.SockaddrInet6).Addr[:16],
				Port: addr.(*syscall.SockaddrInet6).Port,
			})
		}
	}

	return nil
}
