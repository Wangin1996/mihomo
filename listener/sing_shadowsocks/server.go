package sing_shadowsocks

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	"github.com/metacubex/mihomo/common/sockopt"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/restls"
	embedSS "github.com/metacubex/mihomo/listener/shadowsocks"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/listener/sing"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/ntp"
	"github.com/metacubex/mihomo/transport/kcptun"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"

	shadowsocks "github.com/metacubex/sing-shadowsocks"
	"github.com/metacubex/sing-shadowsocks/shadowaead"
	"github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	M "github.com/metacubex/sing/common/metadata"
	"github.com/metacubex/sing/common/network"
)

const handshakeTimeout = 15 * time.Second

type serviceHolder struct {
	svc shadowsocksService
}

type Listener struct {
	closed       bool
	config       LC.ShadowsocksServer
	listeners    []net.Listener
	udpListeners []net.PacketConn
	service      atomic.Pointer[serviceHolder]
	updateMu     sync.Mutex
	simpleObfs   func(net.Conn) net.Conn
}

type shadowsocksService interface {
	NewConnection(context.Context, net.Conn, M.Metadata) error
	NewPacket(context.Context, network.PacketConn, *buf.Buffer, M.Metadata) error
}

func (l *Listener) currentService() shadowsocksService {
	if holder := l.service.Load(); holder != nil {
		return holder.svc
	}
	return nil
}

type ssHandler struct {
	*sing.ListenerHandler
	defaultUser string
}

func (h *ssHandler) applyDefaultUser(ctx context.Context) context.Context {
	if h.defaultUser != "" {
		if _, loaded := auth.UserFromContext[string](ctx); !loaded {
			ctx = auth.ContextWithUser(ctx, h.defaultUser)
		}
	}
	return ctx
}

func (h *ssHandler) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	_ = conn.SetReadDeadline(time.Time{})
	ctx = h.applyDefaultUser(ctx)
	return h.ListenerHandler.NewConnection(ctx, conn, metadata)
}

func (h *ssHandler) NewPacketConnection(ctx context.Context, conn network.PacketConn, metadata M.Metadata) error {
	_ = conn.SetReadDeadline(time.Time{})
	ctx = h.applyDefaultUser(ctx)
	return h.ListenerHandler.NewPacketConnection(ctx, conn, metadata)
}

func (h *ssHandler) NewPacket(ctx context.Context, key netip.AddrPort, buffer *buf.Buffer, metadata M.Metadata, init func(natConn network.PacketConn) network.PacketWriter) {
	ctx = h.applyDefaultUser(ctx)
	h.ListenerHandler.NewPacket(ctx, key, buffer, metadata, init)
}

var _listener *Listener

func New(config LC.ShadowsocksServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (_ C.MultiAddrListener, err error) {
	var sl *Listener
	if len(additions) == 0 {
		additions = []inbound.Addition{
			inbound.WithInName("DEFAULT-SHADOWSOCKS"),
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

	udpTimeout := int64(sing.UDPTimeout.Seconds())

	h, err := sing.NewListenerHandler(sing.ListenerConfig{
		Tunnel:    tunnel,
		Type:      C.SHADOWSOCKS,
		Additions: additions,
		MuxOption: config.MuxOption,
	})
	if err != nil {
		return nil, err
	}

	sl = &Listener{}
	sl.config = config

	usernames := make([]string, 0, len(config.Users))
	passwords := make([]string, 0, len(config.Users))
	for _, user := range config.Users {
		usernames = append(usernames, user.Username)
		passwords = append(passwords, user.Password)
	}

	defaultUser := ""
	if config.Cipher == "2022-blake3-chacha20-poly1305" && len(config.Users) == 1 {
		defaultUser = config.Users[0].Username
	}
	handler := &ssHandler{
		ListenerHandler: h,
		defaultUser:     defaultUser,
	}

	var initialService shadowsocksService
	switch {
	case config.Cipher == shadowsocks.MethodNone:
		initialService = shadowsocks.NewNoneService(udpTimeout, handler)
	case common.Contains(shadowaead.List, config.Cipher):
		if len(config.Users) == 0 {
			initialService, err = shadowaead.NewService(config.Cipher, nil, config.Password, udpTimeout, handler)
		} else {
			var service *shadowaead.MultiService[string]
			service, err = shadowaead.NewMultiService[string](config.Cipher, udpTimeout, handler)
			if err == nil {
				err = service.UpdateUsersWithPasswords(usernames, passwords)
				initialService = service
			}
		}
	case common.Contains(shadowaead_2022.List, config.Cipher):
		if len(config.Users) == 0 || config.Cipher == "2022-blake3-chacha20-poly1305" {
			initialService, err = shadowaead_2022.NewServiceWithPassword(config.Cipher, config.Password, udpTimeout, handler, ntp.Now)
		} else {
			var service *shadowaead_2022.MultiService[string]
			service, err = shadowaead_2022.NewMultiServiceWithPassword[string](config.Cipher, config.Password, udpTimeout, handler, ntp.Now)
			if err == nil {
				err = service.UpdateUsersWithPasswords(usernames, passwords)
				initialService = service
			}
		}
	default:
		sl = nil
		return embedSS.New(config, lc, tunnel, additions...)
	}
	if err != nil {
		return nil, err
	}
	sl.service.Store(&serviceHolder{svc: initialService})

	securityModes := make([]string, 0, 3)
	if config.ShadowTLS.Enable {
		securityModes = append(securityModes, "shadow-tls")
	}
	if config.ResTLS.Enable {
		securityModes = append(securityModes, "res-tls")
	}
	if config.JLSConfig.Enable {
		securityModes = append(securityModes, "jls")
	}
	if len(securityModes) > 1 {
		return nil, fmt.Errorf("security modes are mutually exclusive: %s", strings.Join(securityModes, ", "))
	}

	var shadowTLSBuilder *shadowtls.Builder
	if config.ShadowTLS.Enable {
		shadowTLSBuilder, err = shadowtls.New(config.ShadowTLS, tunnel)
		if err != nil {
			return nil, err
		}
	}

	var restlsBuilder *restls.Builder
	if config.ResTLS.Enable {
		restlsBuilder = restls.New(config.ResTLS, tunnel)
	}

	var jlsBuilder *jls.Builder
	if config.JLSConfig.Enable {
		jlsBuilder, err = jls.New(config.JLSConfig, tunnel)
		if err != nil {
			return nil, err
		}
	}

	if config.SimpleObfs.Enable {
		switch config.SimpleObfs.Mode {
		case "http":
			sl.simpleObfs = obfs.NewHTTPObfsServer
		case "tls":
			sl.simpleObfs = obfs.NewTLSObfsServer
		default:
			return nil, fmt.Errorf("unsupported simple obfs mode: %s", config.SimpleObfs.Mode)
		}
	}

	var kcptunServer *kcptun.Server
	if config.KcpTun.Enable {
		kcptunServer = kcptun.NewServer(config.KcpTun.Config)
		config.Udp = true
	}

	for _, addr := range strings.Split(config.Listen, ",") {
		addr := addr

		if config.Udp {
			//UDP
			var ul net.PacketConn
			ul, err = lc.ListenPacket(context.Background(), "udp", addr)
			if err != nil {
				return nil, err
			}

			if reuseErr := sockopt.UDPReuseaddr(ul); reuseErr != nil {
				log.Warnln("Failed to Reuse UDP Address: %s", reuseErr)
			}

			sl.udpListeners = append(sl.udpListeners, ul)

			if kcptunServer != nil {
				go kcptunServer.Serve(ul, func(c net.Conn) {
					sl.HandleConn(c, tunnel)
				})

				continue // skip tcp listener
			}

			go func() {
				conn := bufio.NewPacketConn(ul)
				rwOptions := network.NewReadWaitOptions(conn, sl.currentService())
				readWaiter, isReadWaiter := bufio.CreatePacketReadWaiter(conn)
				if isReadWaiter {
					readWaiter.InitializeReadWaiter(rwOptions)
				}
				for {
					var (
						buff *buf.Buffer
						dest M.Socksaddr
						rErr error
					)
					buff = nil // clear last loop status, avoid repeat release
					if isReadWaiter {
						buff, dest, rErr = readWaiter.WaitReadPacket()
					} else {
						buff = rwOptions.NewPacketBuffer()
						dest, rErr = conn.ReadPacket(buff)
						if buff != nil {
							rwOptions.PostReturn(buff)
						}
					}
					if rErr != nil {
						buff.Release()
						if sl.closed {
							break
						}
						continue
					}
					svc := sl.currentService()
					if svc == nil {
						buff.Release()
						continue
					}
					ctx := context.TODO()
					ctx = sing.WithInAddr(ctx, ul.LocalAddr())
					_ = svc.NewPacket(ctx, conn, buff, M.Metadata{
						Protocol: "shadowsocks",
						Source:   dest,
					})
				}
			}()
		}

		//TCP
		var l net.Listener
		l, err = lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if shadowTLSBuilder != nil {
			l = shadowTLSBuilder.NewListener(l)
		} else if restlsBuilder != nil {
			l = restlsBuilder.NewListener(l)
		} else if jlsBuilder != nil {
			l = jlsBuilder.NewListener(l)
		}
		sl.listeners = append(sl.listeners, l)

		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
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
	for _, lis := range l.listeners {
		err := lis.Close()
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
	l.updateMu.Lock()
	defer l.updateMu.Unlock()
	return l.config.String()
}

func (l *Listener) UpdateUsers(users []LC.ShadowsocksUser) error {
	usernames := make([]string, 0, len(users))
	passwords := make([]string, 0, len(users))
	for _, user := range users {
		usernames = append(usernames, user.Username)
		passwords = append(passwords, user.Password)
	}
	l.updateMu.Lock()
	defer l.updateMu.Unlock()
	current := l.currentService()
	var next shadowsocksService
	switch svc := current.(type) {
	case *shadowaead.MultiService[string]:
		cloned := *svc
		if err := cloned.UpdateUsersWithPasswords(usernames, passwords); err != nil {
			return err
		}
		next = &cloned
	case *shadowaead_2022.MultiService[string]:
		cloned := *svc
		if err := cloned.UpdateUsersWithPasswords(usernames, passwords); err != nil {
			return err
		}
		next = &cloned
	default:
		return fmt.Errorf("shadowsocks listener does not support multi-user updates")
	}
	l.service.Store(&serviceHolder{svc: next})
	l.config.Users = append([]LC.ShadowsocksUser(nil), users...)
	return nil
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, lis := range l.listeners {
		addrList = append(addrList, lis.Addr())
	}
	for _, lis := range l.udpListeners {
		addrList = append(addrList, lis.LocalAddr())
	}
	return
}

func (l *Listener) HandleConn(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	svc := l.currentService()
	if svc == nil {
		_ = conn.Close()
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	user, loaded := shadowtls.UserFromConn(conn)
	if jlsUser, jlsLoaded := jls.UserFromConn(conn); jlsLoaded {
		user, loaded = jlsUser, true
	}
	if l.simpleObfs != nil {
		conn = l.simpleObfs(conn)
	}
	ctx := sing.WithAdditions(context.TODO(), additions...)
	if loaded {
		ctx = auth.ContextWithUser(ctx, user)
	}
	err := svc.NewConnection(ctx, conn, M.Metadata{
		Protocol: "shadowsocks",
		Source:   M.SocksaddrFromNet(conn.RemoteAddr()),
	})
	if err != nil {
		_ = conn.Close()
		return
	}
}

func HandleShadowSocks(conn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) bool {
	if _listener != nil && _listener.currentService() != nil {
		go _listener.HandleConn(conn, tunnel, additions...)
		return true
	}
	return embedSS.HandleShadowSocks(conn, tunnel, additions...)
}
