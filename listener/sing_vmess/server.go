package sing_vmess

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/reality"
	"github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/listener/tlsmirror"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/gun"
	"github.com/metacubex/mihomo/transport/mekya"
	"github.com/metacubex/mihomo/transport/mkcp"
	mihomoVMess "github.com/metacubex/mihomo/transport/vmess"

	"github.com/metacubex/http"
	"github.com/metacubex/mhurl"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/tls"
	"golang.org/x/exp/slices"
)

const defaultHandshakeTimeout = 15 * time.Second

var handshakeTimeoutNs atomic.Int64

func init() {
	handshakeTimeoutNs.Store(int64(defaultHandshakeTimeout))
}

func handshakeTimeout() time.Duration {
	return time.Duration(handshakeTimeoutNs.Load())
}

// SetHandshakeTimeout overrides the VMess handshake read timeout and returns a restore function.
func SetHandshakeTimeout(d time.Duration) func() {
	prev := handshakeTimeoutNs.Swap(int64(d))
	return func() {
		handshakeTimeoutNs.Store(prev)
	}
}

type Listener struct {
	closed     bool
	config     LC.VmessServer
	listeners  []net.Listener
	httpServer *http.Server
	handler    *sing.ListenerHandler
	service    *Service[string]
	usersMu    sync.RWMutex
}

var _listener *Listener

func New(config LC.VmessServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-VMESS"),
			inbound.WithSpecialRules(""),
		}
		defer func() {
			if err == nil {
				_listener = sl
			}
		}()
	}
	defer func() {
		if err != nil && sl != nil {
			_ = sl.Close()
			sl = nil
		}
	}()
	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.VMESS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}
	if config.MekyaConfig.Enable {
		if config.MKCPConfig.Enable {
			return nil, errors.New("mkcp-config is unavailable in mekya")
		}
		if config.WsPath != "" || config.GrpcServiceName != "" {
			return nil, errors.New("ws and grpc are unavailable in mekya")
		}
	}

	service := NewService[string](h, ntp.Now, true)
	err = service.UpdateUsers(
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.Username
		}),
		common.Map(config.Users, func(it LC.VmessUser) string {
			return it.UUID
		}),
		common.Map(config.Users, func(it LC.VmessUser) int {
			return it.AlterID
		}))
	if err != nil {
		return nil, err
	}

	err = service.Start()
	if err != nil {
		return nil, err
	}

	sl = &Listener{config: config, handler: h, service: service}

	httpServer := &http.Server{
		ReadHeaderTimeout: handshakeTimeout(),
		IdleTimeout:       30 * time.Second,
		Protocols:         new(http.Protocols),
	}
	tlsConfig := &tls.Config{Time: ntp.Now}
	var shadowTLSBuilder *shadowtls.Builder
	var restlsBuilder *restls.Builder
	var jlsBuilder *jls.Builder
	var realityBuilder *reality.Builder
	var tlsMirrorBuilder *tlsmirror.Builder

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
	if tlsConfig.ClientAuth != tls.NoClientCert && tlsConfig.GetCertificate == nil {
		return nil, errors.New("client-auth requires certificate")
	}
	securityModes := make([]string, 0, 6)
	if tlsConfig.GetCertificate != nil {
		securityModes = append(securityModes, "certificate")
	}
	if config.RealityConfig.PrivateKey != "" {
		securityModes = append(securityModes, "reality")
	}
	if config.TLSMirrorConfig.PrimaryKey != "" {
		securityModes = append(securityModes, "tlsmirror")
	}
	tcpOnlySecurityMode := ""
	if config.ShadowTLS.Enable {
		securityModes = append(securityModes, "shadow-tls")
		tcpOnlySecurityMode = "ShadowTLS"
	}
	if config.ResTLS.Enable {
		securityModes = append(securityModes, "res-tls")
		tcpOnlySecurityMode = "Restls"
	}
	if config.JLSConfig.Enable {
		securityModes = append(securityModes, "jls")
		tcpOnlySecurityMode = "JLS"
	}
	if len(securityModes) > 1 {
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
	}
	if config.MKCPConfig.Enable && tcpOnlySecurityMode != "" {
		return nil, errors.New(tcpOnlySecurityMode + " only supports TCP transports")
	}
	if config.RealityConfig.PrivateKey != "" {
		realityBuilder, err = config.RealityConfig.Build(tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.TLSMirrorConfig.PrimaryKey != "" {
		tlsMirrorBuilder = tlsmirror.Config{
			PrimaryKey:                    config.TLSMirrorConfig.PrimaryKey,
			Dest:                          config.TLSMirrorConfig.Dest,
			Proxy:                         config.TLSMirrorConfig.Proxy,
			ExplicitNonceCipherSuites:     config.TLSMirrorConfig.ExplicitNonceCipherSuites,
			DeferInstanceDerivedWriteTime: config.TLSMirrorConfig.DeferInstanceDerivedWriteTime.Build(),
			TransportLayerPadding:         config.TLSMirrorConfig.TransportLayerPadding.Build(),
			ConnectionEnrolment:           config.TLSMirrorConfig.ConnectionEnrolment.Build(),
			SequenceWatermarkingEnabled:   config.TLSMirrorConfig.SequenceWatermarkingEnabled,
		}.Build(tunnel)
		h.Tunnel = tlsMirrorBuilder.WrapTunnel(tunnel)
	}
	if config.ShadowTLS.Enable {
		shadowTLSBuilder, err = shadowtls.New(config.ShadowTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.ResTLS.Enable {
		restlsBuilder = restls.New(config.ResTLS, tunnel)
	}
	if config.JLSConfig.Enable {
		jlsBuilder, err = jls.New(config.JLSConfig, tunnel)
		if err != nil {
			return nil, err
		}
	}
	if config.WsPath != "" {
		httpMux := http.NewServeMux()
		httpMux.HandleFunc(config.WsPath, func(w http.ResponseWriter, r *http.Request) {
			conn, err := mihomoVMess.StreamUpgradedWebsocketConn(w, r)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			sl.HandleConn(conn, tunnel, additions...)
		})
		httpServer.Handler = httpMux
		httpServer.Protocols.SetHTTP1(true)
		tlsConfig.NextProtos = append(tlsConfig.NextProtos, "http/1.1")
	}
	if config.GrpcServiceName != "" {
		httpServer.Handler = gun.NewServerHandler(gun.ServerOption{
			ServiceName: config.GrpcServiceName,
			ConnHandler: func(conn net.Conn) {
				sl.HandleConn(conn, tunnel, additions...)
			},
			HttpHandler: httpServer.Handler,
		})
		httpServer.Protocols.SetHTTP2(true)
		// SetUnencryptedHTTP2 to ensure we can work in plain http2 and some tls conn is not *tls.Conn (like *reality.Conn)
		//
		// Enable HTTP/2 support unconditionally on the server.
		//
		// Note that this usage is limited to our own net/http fork
		// The standard library also needs to mask the tls.Conn type for the conn returned by the Listener.
		// see: https://github.com/golang/go/issues/79293#issuecomment-4426393534
		httpServer.Protocols.SetUnencryptedHTTP2(true)
		tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...) // h2 must before http/1.1
	}
	if config.MekyaConfig.Enable {
		if !slices.Contains(tlsConfig.NextProtos, "http/1.1") {
			tlsConfig.NextProtos = append([]string{"http/1.1"}, tlsConfig.NextProtos...)
		}
		if !slices.Contains(tlsConfig.NextProtos, "h2") {
			tlsConfig.NextProtos = append([]string{"h2"}, tlsConfig.NextProtos...)
		}
	}

	if httpServer.Handler != nil {
		sl.httpServer = httpServer
	}
	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		//TCP
		var l net.Listener
		if config.MKCPConfig.Enable {
			var pc net.PacketConn
			pc, err = lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				return nil, err
			}
			l, err = mkcp.Listen(context.Background(), pc, config.MKCPConfig.Build())
			if err != nil {
				_ = pc.Close()
				return nil, err
			}
		} else {
			l, err = lc.Listen(context.Background(), "tcp", addr)
			if err != nil {
				return nil, err
			}
		}
		if shadowTLSBuilder != nil {
			l = shadowTLSBuilder.NewListener(l)
		} else if restlsBuilder != nil {
			l = restlsBuilder.NewListener(l)
		} else if jlsBuilder != nil {
			l = jlsBuilder.NewListener(l)
		} else if tlsMirrorBuilder != nil {
			l = tlsMirrorBuilder.NewListener(l)
		} else if realityBuilder != nil {
			l = realityBuilder.NewListener(l)
		} else if tlsConfig.GetCertificate != nil {
			l = tls.NewListener(l, tlsConfig)
		}
		if config.MekyaConfig.Enable {
			rawL := l
			l, err = mekya.Listen(context.Background(), l, config.MekyaConfig.Build())
			if err != nil {
				_ = rawL.Close()
				return nil, err
			}
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			if httpServer.Handler != nil {
				_ = httpServer.Serve(l)
				return
			}
			for {
				c, acceptErr := l.Accept()
				if acceptErr != nil {
					if sl.closed {
						break
					}
					continue
				}

				go sl.HandleConn(c, tunnel)
			}
		}()
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	if l.httpServer != nil {
		if err := l.httpServer.Close(); err != nil {
			retErr = err
		}
	}
	for _, lis := range l.listeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	l.usersMu.RLock()
	service := l.service
	l.usersMu.RUnlock()
	if service != nil {
		err := service.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	l.usersMu.RLock()
	defer l.usersMu.RUnlock()
	return l.config.String()
}

func equalVmessUsers(left, right []LC.VmessUser) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func (l *Listener) UpdateUsers(users []LC.VmessUser) error {
	userNames := make([]string, 0, len(users))
	userUUIDs := make([]string, 0, len(users))
	alterIDs := make([]int, 0, len(users))
	for _, user := range users {
		userNames = append(userNames, user.Username)
		userUUIDs = append(userUUIDs, user.UUID)
		alterIDs = append(alterIDs, user.AlterID)
	}

	l.usersMu.Lock()
	defer l.usersMu.Unlock()
	if equalVmessUsers(l.config.Users, users) {
		return nil
	}
	if l.service == nil {
		return errors.New("vmess service is not initialized")
	}
	if err := l.service.UpdateUsers(userNames, userUUIDs, alterIDs); err != nil {
		return err
	}
	l.config.Users = append([]LC.VmessUser(nil), users...)
	return nil
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	if l.service == nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout()))
	ctx := sing.WithAdditions(context.TODO(), additions...)
	err := l.service.NewConnection(ctx, conn, metadata.Metadata{
		Protocol: "vmess",
		Source:   metadata.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleVmess(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.service != nil {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return false
}

func ParseVmessURL(s string) (addr, username, password string, err error) {
	u, err := mhurl.Parse(s) // we need multiple hosts url supports
	if err != nil {
		return
	}

	addr = u.Host
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	return
}
