package socks

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/component/auth"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	authStore "github.com/metacubex/mihomo/listener/auth"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/socks4"
	"github.com/metacubex/mihomo/transport/socks5"

	"github.com/metacubex/tls"
)

const handshakeTimeout = 15 * time.Second

type Listener struct {
	listener net.Listener
	addr     string
	closed   bool
	authMu   sync.RWMutex
	store    auth.AuthStore
}

type listenerAuthStore struct {
	l *Listener
}

func (s listenerAuthStore) Authenticator() auth.Authenticator {
	s.l.authMu.RLock()
	store := s.l.store
	s.l.authMu.RUnlock()
	if store == nil {
		return nil
	}
	return store.Authenticator()
}

func (s listenerAuthStore) SetAuthenticator(authenticator auth.Authenticator) {
	s.l.authMu.Lock()
	if s.l.store != nil {
		s.l.store.SetAuthenticator(authenticator)
	}
	s.l.authMu.Unlock()
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

func defaultConfig(addr string) LC.AuthServer {
	return LC.AuthServer{Enable: true, Listen: addr, AuthStore: authStore.Default}
}

func New(addr string, tunnel C.Tunnel, additions ...inbound.Addition) (*Listener, error) {
	return NewWithConfig(defaultConfig(addr), inbound.NewListenConfig(), tunnel, additions...)
}

func NewWithConfig(config LC.AuthServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	isDefault := false
	if len(additions) == 0 {
		isDefault = true
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SOCKS"),
			inbound.WithSpecialRules(""),
		}
	}

	l, err := lc.Listen(context.Background(), "tcp", config.Listen)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil && l != nil {
			_ = l.Close()
		}
	}()

	tlsConfig := &tls.Config{Time: ntp.Now}
	var realityBuilder *reality.Builder

	if config.Certificate != "" && config.PrivateKey != "" {
		certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
		if err != nil {
			return nil, err
		}
		tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			return certLoader()
		}

		if config.EchKey != "" {
			err = ech.LoadECHKey(config.EchKey, tlsConfig)
			if err != nil {
				return nil, err
			}
		}
	}
	tlsConfig.ClientAuth = ca.ClientAuthTypeFromString(config.ClientAuthType)
	if len(config.ClientAuthCert) > 0 {
		if tlsConfig.ClientAuth == tls.NoClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		}
	}
	if tlsConfig.ClientAuth == tls.VerifyClientCertIfGiven || tlsConfig.ClientAuth == tls.RequireAndVerifyClientCert {
		pool, err := ca.LoadCertificates(config.ClientAuthCert)
		if err != nil {
			return nil, err
		}
		tlsConfig.ClientCAs = pool
	}
	if config.RealityConfig.PrivateKey != "" {
		if tlsConfig.GetCertificate != nil {
			return nil, errors.New("certificate is unavailable in reality")
		}
		if tlsConfig.ClientAuth != tls.NoClientCert {
			return nil, errors.New("client-auth is unavailable in reality")
		}
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}

	if realityBuilder != nil {
		l = realityBuilder.NewListener(l)
	} else if tlsConfig.GetCertificate != nil {
		l = tls.NewListener(l, tlsConfig)
	}

	sl = &Listener{
		listener: l,
		addr:     config.Listen,
		store:    config.AuthStore,
	}
	go func() {
		for {
			c, acceptErr := l.Accept()
			if acceptErr != nil {
				if sl.closed {
					break
				}
				continue
			}
			sl.authMu.RLock()
			currentStore := sl.store
			sl.authMu.RUnlock()
			var connStore auth.AuthStore = listenerAuthStore{l: sl}
			if isDefault || currentStore == authStore.Default { // only apply on default listener
				if !inbound.IsRemoteAddrDisAllowed(c.RemoteAddr()) {
					_ = c.Close()
					continue
				}
				if inbound.SkipAuthRemoteAddr(c.RemoteAddr()) {
					connStore = authStore.Nil
				}
			}
			go handleSocks(c, tunnel, connStore, additions...)
		}
	}()

	return sl, nil
}

func (l *Listener) UpdateAuthStore(store auth.AuthStore) {
	l.authMu.Lock()
	l.store = store
	l.authMu.Unlock()
}

func handleSocks(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	bufConn := N.NewBufferedConn(conn)
	head, err := bufConn.Peek(1)
	if err != nil {
		conn.Close()
		return
	}

	switch head[0] {
	case socks4.Version:
		HandleSocks4(bufConn, tunnel, store, additions...)
	case socks5.Version:
		HandleSocks5(bufConn, tunnel, store, additions...)
	default:
		conn.Close()
	}
}

func HandleSocks4(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	var authenticator auth.Authenticator
	if store != nil {
		authenticator = store.Authenticator()
	}
	addr, _, user, err := socks4.ServerHandshake(conn, authenticator)
	if err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	additions = append(additions, inbound.WithInUser(user))
	tunnel.HandleTCPConn(inbound.NewSocket(socks5.ParseAddr(addr), conn, C.SOCKS4, additions...))
}

func HandleSocks5(conn net.Conn, tunnel C.Tunnel, store auth.AuthStore, additions ...inbound.Addition) {
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	var authenticator auth.Authenticator
	if store != nil {
		authenticator = store.Authenticator()
	}
	target, command, user, err := socks5.ServerHandshake(conn, authenticator)
	if err != nil {
		conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	if command == socks5.CmdUDPAssociate {
		defer conn.Close()
		io.Copy(io.Discard, conn)
		return
	}
	additions = append(additions, inbound.WithInUser(user))
	tunnel.HandleTCPConn(inbound.NewSocket(target, conn, C.SOCKS5, additions...))
}
