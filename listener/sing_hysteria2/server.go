package sing_hysteria2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/ca"
	"github.com/metacubex/mihomo/component/ech"
	"github.com/metacubex/mihomo/component/resolver"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/inner"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/tuic/common"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httputil"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/sing-quic/hysteria2"
	"github.com/metacubex/sing-quic/hysteria2/realm"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/tls"
)

type Listener struct {
	closed       bool
	config       LC.Hysteria2Server
	configMu     sync.RWMutex
	udpListeners []net.PacketConn
	services     []*hy2Service[string]
}

func validateMasqueradeHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return errors.New("empty masquerade host")
	}
	lower := strings.TrimSuffix(strings.ToLower(trimmed), ".")
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return fmt.Errorf("disallowed masquerade host %q: localhost is forbidden", host)
	}
	if addr, err := netip.ParseAddr(trimmed); err == nil {
		ip := addr.Unmap()
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("disallowed masquerade host %q: loopback, private, link-local, or unspecified IP is forbidden", host)
		}
	}
	return nil
}

func New(config LC.Hysteria2Server, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (sl *Listener, err error) {
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-HYSTERIA2"),
			inbound.WithSpecialRules(""),
		}
	}
	defer func() {
		if err != nil && sl != nil {
			_ = sl.Close()
			sl = nil
		}
	}()

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.HYSTERIA2,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl = &Listener{config: config}

	tlsConfig := &tls.Config{
		Time:       ntp.Now,
		MinVersion: tls.VersionTLS13,
	}
	certLoader, err := ca.NewTLSKeyPairLoader(config.Certificate, config.PrivateKey)
	if err != nil {
		return nil, err
	}
	tlsConfig.GetCertificate = func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return certLoader()
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

	if config.EchKey != "" {
		err = ech.LoadECHKey(config.EchKey, tlsConfig)
		if err != nil {
			return nil, err
		}
	}
	if len(config.ALPN) > 0 {
		tlsConfig.NextProtos = config.ALPN
	} else {
		tlsConfig.NextProtos = []string{"h3"}
	}

	var salamanderPassword string
	var geckoPassword string
	var geckoMinPacketSize, geckoMaxPacketSize int
	if len(config.Obfs) > 0 {
		if config.ObfsPassword == "" {
			return nil, errors.New("missing obfs password")
		}
		switch config.Obfs {
		case hysteria2.ObfsTypeSalamander:
			salamanderPassword = config.ObfsPassword
		case hysteria2.ObfsTypeGecko:
			geckoPassword = config.ObfsPassword
			geckoMinPacketSize = config.ObfsMinPacketSize
			geckoMaxPacketSize = config.ObfsMaxPacketSize
		default:
			return nil, fmt.Errorf("unknown obfs type: %s", config.Obfs)
		}
	}
	var masqueradeHandler http.Handler
	if config.Masquerade != "" {
		masqueradeURL, err := url.Parse(config.Masquerade)
		if err != nil {
			return nil, E.Cause(err, "parse masquerade URL")
		}
		switch strings.ToLower(masqueradeURL.Scheme) {
		case "file":
			return nil, errors.New("file scheme is forbidden in hysteria2 masquerade")
		case "http", "https":
			if err := validateMasqueradeHost(masqueradeURL.Hostname()); err != nil {
				return nil, err
			}
			masqueradeHandler = &httputil.ReverseProxy{
				Rewrite: func(r *httputil.ProxyRequest) {
					r.SetURL(masqueradeURL)
					r.Out.Host = r.In.Host
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					w.WriteHeader(http.StatusBadGateway)
				},
				Transport: &http.Transport{
					// fellow hysteria2's code skip verify
					TLSClientConfig: &tls.Config{
						InsecureSkipVerify: true,
					},
					// from http.DefaultTransport
					ForceAttemptHTTP2:     true,
					MaxIdleConns:          100,
					IdleConnTimeout:       90 * time.Second,
					TLSHandshakeTimeout:   10 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return inner.HandleTcp(tunnel, address, "")
					},
				},
			}
		default:
			return nil, E.New("unknown masquerade URL scheme: ", masqueradeURL.Scheme)
		}
	}
	var realmOptions *realm.Options
	if config.RealmOpts.Enable {
		httpTLSClientConfig, err := ca.GetTLSConfig(ca.Option{
			TLSConfig: &tls.Config{
				ServerName:         config.RealmOpts.SNI,
				InsecureSkipVerify: config.RealmOpts.SkipCertVerify,
				NextProtos:         config.RealmOpts.ALPN,
			},
			Fingerprint:    config.RealmOpts.Fingerprint,
			NameCertVerify: config.RealmOpts.NameCertVerify,
			Certificate:    config.RealmOpts.Certificate,
			PrivateKey:     config.RealmOpts.PrivateKey,
		})
		if err != nil {
			return nil, err
		}
		realmOptions = &realm.Options{
			ServerURL:   config.RealmOpts.ServerURL,
			Token:       config.RealmOpts.Token,
			RealmID:     config.RealmOpts.RealmID,
			STUNServers: config.RealmOpts.STUNServers,
			HTTPClient: &http.Client{Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					return inner.HandleTcp(tunnel, address, config.RealmOpts.Proxy)
				},
				TLSClientConfig: httpTLSClientConfig,
				// from http.DefaultTransport
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}},
			Resolver: func(ctx context.Context, host string, ipv4, ipv6 bool) ([]netip.Addr, error) {
				if ipv4 && !ipv6 {
					return resolver.LookupIPv4WithResolver(ctx, host, resolver.ProxyServerHostResolver)
				} else if ipv6 && !ipv4 {
					return resolver.LookupIPv6WithResolver(ctx, host, resolver.ProxyServerHostResolver)
				}
				return resolver.LookupIPWithResolver(ctx, host, resolver.ProxyServerHostResolver)
			},
			Logger: log.SingLogger,
		}
	}

	if config.UdpMTU == 0 {
		// "1200" from quic-go's MaxDatagramSize
		// "-3" from quic-go's DatagramFrame.MaxDataLen
		config.UdpMTU = 1200 - 3
	}

	quicConfig := &quic.Config{
		InitialStreamReceiveWindow:     config.InitialStreamReceiveWindow,
		MaxStreamReceiveWindow:         config.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: config.InitialConnectionReceiveWindow,
		MaxConnectionReceiveWindow:     config.MaxConnectionReceiveWindow,
	}

	service, err := newHy2Service[string](serviceOptions{
		Context:               context.Background(),
		Logger:                log.SingLogger,
		SendBPS:               utils.StringToBps(config.Up),
		ReceiveBPS:            utils.StringToBps(config.Down),
		SalamanderPassword:    salamanderPassword,
		GeckoPassword:         geckoPassword,
		GeckoMinPacketSize:    geckoMinPacketSize,
		GeckoMaxPacketSize:    geckoMaxPacketSize,
		TLSConfig:             tlsConfig,
		QUICConfig:            quicConfig,
		IgnoreClientBandwidth: config.IgnoreClientBandwidth,
		UDPTimeout:            sing.UDPTimeout,
		Handler:               h,
		MasqueradeHandler:     masqueradeHandler,
		UdpMTU:                config.UdpMTU,
		RealmOptions:          realmOptions,
		SetBBRCongestion: func(quicConn *quic.Conn) {
			common.SetCongestionController(quicConn, "bbr", config.CWND, config.BBRProfile)
		},
	})
	if err != nil {
		return nil, err
	}

	userNameList := make([]string, 0, len(config.Users))
	userPasswordList := make([]string, 0, len(config.Users))
	for name, password := range config.Users {
		userNameList = append(userNameList, name)
		userPasswordList = append(userPasswordList, password)
	}
	service.UpdateUsers(userNameList, userPasswordList)

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr
		_service := *service
		addrService := &_service // shares atomic userMap pointer across addresses

		var ul net.PacketConn
		ul, err = lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			return nil, err
		}

		if reuseErr := sockopt.UDPReuseaddr(ul); reuseErr != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", reuseErr)
		}

		sl.udpListeners = append(sl.udpListeners, ul)
		sl.services = append(sl.services, addrService)

		if err = addrService.Start(ul); err != nil {
			return nil, err
		}
	}

	return sl, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, service := range l.services {
		err := service.Close()
		if err != nil {
			retErr = err
		}
	}
	for _, lis := range l.udpListeners {
		err := lis.Close()
		if err != nil {
			retErr = err
		}
	}
	return retErr
}

func (l *Listener) Config() string {
	l.configMu.RLock()
	defer l.configMu.RUnlock()
	return l.config.String()
}

func (l *Listener) UpdateUsers(users map[string]string) {
	userNameList := make([]string, 0, len(users))
	userPasswordList := make([]string, 0, len(users))
	usersCopy := make(map[string]string, len(users))
	for name, password := range users {
		userNameList = append(userNameList, name)
		userPasswordList = append(userPasswordList, password)
		usersCopy[name] = password
	}
	l.configMu.Lock()
	if len(l.services) > 0 {
		l.services[0].UpdateUsers(userNameList, userPasswordList)
	}
	l.config.Users = usersCopy
	l.configMu.Unlock()
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}
