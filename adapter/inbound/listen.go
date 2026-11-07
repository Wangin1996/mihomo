package inbound

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"syscall"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/component/keepalive"
	"github.com/metacubex/mihomo/component/mptcp"

	"github.com/metacubex/tfo-go"
)

var (
	globalTFO   = atomic.NewBool(false)
	globalMPTCP = atomic.NewBool(false)
)

func SetTfo(open bool) {
	globalTFO.Store(open)
}

func Tfo() bool {
	return globalTFO.Load()
}

func SetMPTCP(open bool) {
	globalMPTCP.Store(open)
}

func MPTCP() bool {
	return globalMPTCP.Load()
}

type ListenConfig struct {
	routeMark  int
	listenMode string
}

func NewListenConfig() *ListenConfig {
	return &ListenConfig{}
}

func (l *ListenConfig) SetRouteMark(mark int) {
	l.routeMark = mark
}

func (l *ListenConfig) SetListenMode(mode string) {
	l.listenMode = mode
}

func (l ListenConfig) newListenConfig() *tfo.ListenConfig {
	lc := tfo.ListenConfig{DisableTFO: !Tfo()}
	keepalive.SetNetListenConfig(&lc.ListenConfig)
	mptcp.SetNetListenConfig(&lc.ListenConfig, MPTCP())
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if l.routeMark != 0 {
			err := sockopt.RawConnMark(c, l.routeMark)
			if err != nil {
				return err
			}
		}
		return nil
	}
	return &lc
}

func (l ListenConfig) Listen(ctx context.Context, network, address string) (net.Listener, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}
	network = resolveListenNetwork(network, address, l.listenMode)
	return l.newListenConfig().Listen(ctx, network, address)
}

func (l ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}
	network = resolveListenNetwork(network, address, l.listenMode)
	return l.newListenConfig().ListenPacket(ctx, network, address)
}

func resolveListenNetwork(network, address, listenMode string) string {
	switch network {
	case "tcp", "udp":
	default:
		return network
	}
	switch listenMode {
	case "all", "dual":
		return network
	case "ipv4":
		return network + "4"
	case "ipv6":
		return network + "6"
	}
	if host, _, err := net.SplitHostPort(address); err == nil && host != "" {
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.Is4() {
				return network + "4"
			}
			if ip.Is6() {
				return network + "6"
			}
		}
	}
	return network
}

func preResolve(network, address string) (string, error) {
	switch network { // like net.Resolver.internetAddrList but filter domain to avoid call net.Resolver.lookupIPAddr
	case "tcp", "tcp4", "tcp6", "udp", "udp4", "udp6", "ip", "ip4", "ip6":
		if host, port, err := net.SplitHostPort(address); err == nil {
			switch host {
			case "localhost":
				switch network {
				case "tcp6", "udp6", "ip6":
					address = net.JoinHostPort("::1", port)
				default:
					address = net.JoinHostPort("127.0.0.1", port)
				}
			case "": // internetAddrList can handle this special case
				break
			default:
				if _, err := netip.ParseAddr(host); err != nil { // not ip
					return "", fmt.Errorf("invalid network address: %s", address)
				}
			}
		}
	}
	return address, nil
}
