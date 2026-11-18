package inbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
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

	ipv6ProbeOnce sync.Once
	ipv6Supported = true
)

// SupportsIPv6 reports whether the kernel has a usable IPv6 stack for binding.
func SupportsIPv6() bool {
	ipv6ProbeOnce.Do(func() {
		pc, err := net.ListenPacket("udp6", "[::]:0")
		if err != nil {
			if isIPv6UnsupportedError(err) {
				ipv6Supported = false
			}
			return
		}
		_ = pc.Close()
	})
	return ipv6Supported
}

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
	routeMark    int
	listenMode   string
	disableMPTCP bool
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

func (l *ListenConfig) SetDisableMPTCP(disable bool) {
	l.disableMPTCP = disable
}

func (l ListenConfig) newListenConfig() *tfo.ListenConfig {
	lc := tfo.ListenConfig{DisableTFO: !Tfo()}
	keepalive.SetNetListenConfig(&lc.ListenConfig)
	mptcp.SetNetListenConfig(&lc.ListenConfig, !l.disableMPTCP && MPTCP())
	lc.Control = func(network, address string, c syscall.RawConn) error {
		if network == "tcp6" || network == "udp6" {
			switch l.listenMode {
			case "all", "dual":
				_ = sockopt.RawConnSetV6Only(c, false)
			case "ipv6":
				_ = sockopt.RawConnSetV6Only(c, true)
			}
		}
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
	resolvedNet := resolveListenNetwork(network, address, l.listenMode)
	lis, err := l.newListenConfig().Listen(ctx, resolvedNet, address)
	if err != nil && (l.listenMode == "all" || l.listenMode == "dual") {
		if fallbackNet, fallbackAddr, ok := dualStackIPv4Fallback(resolvedNet, address, err); ok {
			fallbackLC := l
			fallbackLC.listenMode = "ipv4"
			return fallbackLC.newListenConfig().Listen(ctx, fallbackNet, fallbackAddr)
		}
	}
	return lis, err
}

func (l ListenConfig) ListenPacket(ctx context.Context, network, address string) (net.PacketConn, error) {
	address, err := preResolve(network, address)
	if err != nil {
		return nil, err
	}
	resolvedNet := resolveListenNetwork(network, address, l.listenMode)
	pc, err := l.newListenConfig().ListenPacket(ctx, resolvedNet, address)
	if err != nil && (l.listenMode == "all" || l.listenMode == "dual") {
		if fallbackNet, fallbackAddr, ok := dualStackIPv4Fallback(resolvedNet, address, err); ok {
			fallbackLC := l
			fallbackLC.listenMode = "ipv4"
			return fallbackLC.newListenConfig().ListenPacket(ctx, fallbackNet, fallbackAddr)
		}
	}
	return pc, err
}

func dualStackIPv4Fallback(resolvedNet, address string, err error) (string, string, bool) {
	if !isIPv6UnsupportedError(err) {
		return "", "", false
	}
	host, port, splitErr := net.SplitHostPort(address)
	if splitErr != nil {
		return "", "", false
	}
	if host != "" && host != "::" {
		if ip, parseErr := netip.ParseAddr(host); parseErr != nil || !ip.IsUnspecified() {
			return "", "", false
		}
	}
	switch resolvedNet {
	case "tcp", "tcp6":
		return "tcp4", net.JoinHostPort("0.0.0.0", port), true
	case "udp", "udp6":
		return "udp4", net.JoinHostPort("0.0.0.0", port), true
	default:
		return "", "", false
	}
}

func isIPv6UnsupportedError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EAFNOSUPPORT) ||
		errors.Is(err, syscall.EPROTONOSUPPORT) ||
		errors.Is(err, syscall.EADDRNOTAVAIL) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "address family not supported") ||
		strings.Contains(msg, "protocol not supported") ||
		strings.Contains(msg, "no suitable address found")
}

func resolveListenNetwork(network, address, listenMode string) string {
	var baseNet string
	switch network {
	case "tcp", "tcp4", "tcp6":
		baseNet = "tcp"
	case "udp", "udp4", "udp6":
		baseNet = "udp"
	default:
		return network
	}
	switch listenMode {
	case "all", "dual":
		return baseNet
	case "ipv4":
		return baseNet + "4"
	case "ipv6":
		return baseNet + "6"
	}
	if network == "tcp4" || network == "tcp6" || network == "udp4" || network == "udp6" {
		return network
	}
	if host, _, err := net.SplitHostPort(address); err == nil && host != "" {
		if ip, err := netip.ParseAddr(host); err == nil {
			if ip.Is4() {
				return baseNet + "4"
			}
			if ip.Is6() {
				return baseNet + "6"
			}
		}
	}
	return baseNet
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
