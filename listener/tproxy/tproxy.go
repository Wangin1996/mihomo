package tproxy

import (
	"context"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/keepalive"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/transport/socks5"
)

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
}

// RawAddress implements C.Listener
func (l *Listener) RawAddress() string {
	return l.addr
}

// Address implements C.Listener
func (l *Listener) Address() string {
	return l.listener.Addr().String()
}

// Close implements C.Listener
func (l *Listener) Close() error {
	l.closed = true
	return l.listener.Close()
}

func (l *Listener) handleTProxy(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	target := socks5.ParseAddrToSocksAddr(conn.LocalAddr())
	keepalive.TCPKeepAlive(conn)
	// TProxy's conn.LocalAddr() is target address, so we set from l.listener
	additions = append([]inbound.Addition{inbound.WithInAddr(l.listener.Addr())}, additions...)
	tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.TPROXY, additions...))
}

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithConfig(addr, inbound.NewListenConfig(), tunnel, additions...)
}

func NewWithConfig(addr string, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-TPROXY"),
			inbound.WithSpecialRules(""),
		}
	}
	// Golang will then enable mptcp support for listeners by default when the major version of go.mod is 1.24 or higher.
	// This can cause tproxy to malfunction on certain Linux kernel versions, so we force to disable mptcp for tproxy.
	if ilc, ok := lc.(*inbound.ListenConfig); ok && ilc != nil {
		copied := *ilc
		copied.SetDisableMPTCP(true)
		lc = &copied
	} else if lc == nil {
		ilc := inbound.NewListenConfig()
		ilc.SetDisableMPTCP(true)
		lc = ilc
	}
	l, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return nil, err
	}

	tl, ok := l.(*net.TCPListener)
	if !ok {
		_ = l.Close()
		return nil, fmt.Errorf("unexpected tproxy tcp listener type: %T", l)
	}
	rc, err := tl.SyscallConn()
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	err = setsockopt(rc, l.Addr().String())
	if err != nil {
		_ = l.Close()
		return nil, err
	}

	rl := &Listener{
		listener: l,
		addr:     addr,
	}

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				if rl.closed {
					break
				}
				continue
			}
			go rl.handleTProxy(c, tunnel, additions...)
		}
	}()

	return rl, nil
}
