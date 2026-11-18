package sing_hysteria2

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/quic-go"
	"github.com/metacubex/quic-go/http3"
	"github.com/metacubex/quic-go/quicvarint"
	rand2 "github.com/metacubex/randv2"
	"github.com/metacubex/sing-quic/hysteria2"
	hyCC "github.com/metacubex/sing-quic/hysteria2/congestion"
	"github.com/metacubex/sing-quic/hysteria2/realm"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/baderror"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/cache"
	"github.com/metacubex/sing/common/canceler"
	E "github.com/metacubex/sing/common/exceptions"
	"github.com/metacubex/sing/common/logger"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/pipe"
	"github.com/metacubex/sing/common/rw"
	"github.com/metacubex/tls"
)

const (
	hy2URLHost                  = "hysteria"
	hy2URLPath                  = "/auth"
	hy2RequestHeaderAuth        = "Hysteria-Auth"
	hy2ResponseHeaderUDPEnabled = "Hysteria-UDP"
	hy2CommonHeaderCCRX         = "Hysteria-CC-RX"
	hy2CommonHeaderPadding      = "Hysteria-Padding"
	hy2StatusAuthOK             = 233

	hy2FrameTypeTCPRequest = 0x401
	hy2MaxAddressLength    = 2048
	hy2MaxMessageLength    = 2048
	hy2MaxPaddingLength    = 4096
	hy2MaxUDPSize          = 4096

	hy2GeckoDefaultMinPacketSize = 512
	hy2GeckoDefaultMaxPacketSize = 1200
	hy2GeckoMaxOnWireSize        = 2048

	hy2PaddingChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	hy2MaxVarInt1 = 63
	hy2MaxVarInt2 = 16383
	hy2MaxVarInt4 = 1073741823
	hy2MaxVarInt8 = 4611686018427387903
)

type hy2PaddingRange struct {
	min int
	max int
}

func (p hy2PaddingRange) generate() string {
	n := p.min + rand2.IntN(p.max-p.min)
	bs := make([]byte, n)
	for i := range bs {
		bs[i] = hy2PaddingChars[rand2.IntN(len(hy2PaddingChars))]
	}
	return string(bs)
}

var (
	hy2AuthResponsePadding = hy2PaddingRange{min: 256, max: 2048}
	hy2TCPResponsePadding  = hy2PaddingRange{min: 128, max: 1024}
)

type serviceOptions struct {
	Context               context.Context
	Logger                logger.Logger
	BrutalDebug           bool
	SendBPS               uint64
	ReceiveBPS            uint64
	IgnoreClientBandwidth bool
	SalamanderPassword    string
	GeckoPassword         string
	GeckoMinPacketSize    int
	GeckoMaxPacketSize    int
	TLSConfig             *tls.Config
	QUICConfig            *quic.Config
	UDPDisabled           bool
	UDPTimeout            time.Duration
	Handler               hysteria2.ServerHandler
	MasqueradeHandler     http.Handler
	RealmOptions          *realm.Options
	SetBBRCongestion      hysteria2.SetCongestionControllerFunc
	UdpMTU                int
}

type hy2Service[U comparable] struct {
	ctx                   context.Context
	logger                logger.Logger
	brutalDebug           bool
	sendBPS               uint64
	receiveBPS            uint64
	ignoreClientBandwidth bool
	salamanderPassword    string
	geckoPassword         string
	geckoMinPacketSize    int
	geckoMaxPacketSize    int
	tlsConfig             *tls.Config
	quicConfig            *quic.Config
	userMap               *atomic.Pointer[map[string]U]
	udpDisabled           bool
	udpTimeout            time.Duration
	handler               hysteria2.ServerHandler
	masqueradeHandler     http.Handler
	quicListener          io.Closer
	realmServer           *realm.Server
	setBBRCongestion      hysteria2.SetCongestionControllerFunc
	udpMTU                int
}

func newHy2Service[U comparable](options serviceOptions) (*hy2Service[U], error) {
	quicConfig := &quic.Config{}
	if options.QUICConfig != nil {
		quicConfig = options.QUICConfig
	}
	quicConfig.DisablePathManager = true // for port hopping
	quicConfig.DisablePathMTUDiscovery = !(runtime.GOOS == "windows" || runtime.GOOS == "linux" || runtime.GOOS == "android" || runtime.GOOS == "darwin")
	quicConfig.EnableDatagrams = !options.UDPDisabled
	if quicConfig.MaxIncomingStreams == 0 {
		quicConfig.MaxIncomingStreams = 1 << 60
	}
	if quicConfig.InitialStreamReceiveWindow == 0 {
		quicConfig.InitialStreamReceiveWindow = hysteria2.DefaultStreamReceiveWindow
	}
	if quicConfig.MaxStreamReceiveWindow == 0 {
		quicConfig.MaxStreamReceiveWindow = hysteria2.DefaultStreamReceiveWindow
	}
	if quicConfig.InitialConnectionReceiveWindow == 0 {
		quicConfig.InitialConnectionReceiveWindow = hysteria2.DefaultConnReceiveWindow
	}
	if quicConfig.MaxConnectionReceiveWindow == 0 {
		quicConfig.MaxConnectionReceiveWindow = hysteria2.DefaultConnReceiveWindow
	}
	if quicConfig.MaxIdleTimeout == 0 {
		quicConfig.MaxIdleTimeout = hysteria2.DefaultMaxIdleTimeout
	}
	if quicConfig.KeepAlivePeriod == 0 {
		quicConfig.KeepAlivePeriod = hysteria2.DefaultKeepAlivePeriod
	}
	if options.MasqueradeHandler == nil {
		options.MasqueradeHandler = http.NotFoundHandler()
	}
	if len(options.TLSConfig.NextProtos) == 0 {
		options.TLSConfig.NextProtos = []string{http3.NextProtoH3}
	}
	if options.GeckoPassword != "" {
		if options.GeckoMinPacketSize == 0 {
			options.GeckoMinPacketSize = hy2GeckoDefaultMinPacketSize
		}
		if options.GeckoMaxPacketSize == 0 {
			options.GeckoMaxPacketSize = hy2GeckoDefaultMaxPacketSize
		}
		if options.GeckoMinPacketSize <= 0 || options.GeckoMinPacketSize > options.GeckoMaxPacketSize || options.GeckoMaxPacketSize > hy2GeckoMaxOnWireSize {
			return nil, E.New("gecko: invalid packet size range")
		}
	}
	var realmServer *realm.Server
	if options.RealmOptions != nil {
		var err error
		realmServer, err = realm.NewServer(*options.RealmOptions)
		if err != nil {
			return nil, E.Cause(err, "create realm server")
		}
	}
	emptyUsers := make(map[string]U)
	userMapPtr := new(atomic.Pointer[map[string]U])
	userMapPtr.Store(&emptyUsers)
	return &hy2Service[U]{
		ctx:                   options.Context,
		logger:                options.Logger,
		brutalDebug:           options.BrutalDebug,
		sendBPS:               options.SendBPS,
		receiveBPS:            options.ReceiveBPS,
		ignoreClientBandwidth: options.IgnoreClientBandwidth,
		salamanderPassword:    options.SalamanderPassword,
		geckoPassword:         options.GeckoPassword,
		geckoMinPacketSize:    options.GeckoMinPacketSize,
		geckoMaxPacketSize:    options.GeckoMaxPacketSize,
		tlsConfig:             options.TLSConfig,
		quicConfig:            quicConfig,
		userMap:               userMapPtr,
		udpDisabled:           options.UDPDisabled,
		udpTimeout:            options.UDPTimeout,
		handler:               options.Handler,
		masqueradeHandler:     options.MasqueradeHandler,
		realmServer:           realmServer,
		setBBRCongestion:      options.SetBBRCongestion,
		udpMTU:                options.UdpMTU,
	}, nil
}

func (s *hy2Service[U]) UpdateUsers(userList []U, passwordList []string) {
	userMap := make(map[string]U, len(userList))
	for i, user := range userList {
		userMap[passwordList[i]] = user
	}
	s.userMap.Store(&userMap)
}

func (s *hy2Service[U]) lookupUser(secret string) (U, bool) {
	if m := s.userMap.Load(); m != nil {
		u, ok := (*m)[secret]
		return u, ok
	}
	var zero U
	return zero, false
}

func (s *hy2Service[U]) Start(conn net.PacketConn) error {
	if s.realmServer != nil {
		return s.startWithRealm(conn)
	}
	if s.geckoPassword != "" {
		conn = hysteria2.NewGeckoConn(conn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		conn = hysteria2.NewSalamanderConn(conn, []byte(s.salamanderPassword))
	}
	listener, err := quic.Listen(conn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return err
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *hy2Service[U]) startWithRealm(conn net.PacketConn) error {
	punchConn, err := s.realmServer.Start(s.ctx, conn)
	if err != nil {
		return E.Cause(err, "start realm server")
	}
	var quicConn net.PacketConn = punchConn
	if s.geckoPassword != "" {
		quicConn = hysteria2.NewGeckoConn(quicConn, []byte(s.geckoPassword), s.geckoMinPacketSize, s.geckoMaxPacketSize)
	} else if s.salamanderPassword != "" {
		quicConn = hysteria2.NewSalamanderConn(quicConn, []byte(s.salamanderPassword))
	}
	listener, err := quic.Listen(quicConn, s.tlsConfig, s.quicConfig)
	if err != nil {
		return E.Errors(err, s.realmServer.Close())
	}
	s.quicListener = listener
	go s.loopConnections(listener)
	return nil
}

func (s *hy2Service[U]) Close() error {
	var realmErr error
	if s.realmServer != nil {
		realmErr = s.realmServer.Close()
	}
	return E.Errors(realmErr, common.Close(s.quicListener))
}

func (s *hy2Service[U]) loopConnections(listener *quic.Listener) {
	for {
		connection, err := listener.Accept(s.ctx)
		if err != nil {
			if E.IsClosedOrCanceled(err) || errors.Is(err, quic.ErrServerClosed) {
				s.logger.Debug(E.Cause(err, "listener closed"))
			} else {
				s.logger.Error(E.Cause(err, "listener closed"))
			}
			return
		}
		go s.handleConnection(connection)
	}
}

func (s *hy2Service[U]) handleConnection(connection *quic.Conn) {
	session := &hy2ServerSession[U]{
		hy2Service: s,
		ctx:        s.ctx,
		quicConn:   connection,
		connDone:   make(chan struct{}),
		udpConnMap: make(map[uint32]*hy2UDPPacketConn),
	}
	httpServer := http3.Server{
		Handler:          session,
		StreamDispatcher: session.dispatchStream,
	}
	_ = httpServer.ServeQUICConn(connection)
	_ = connection.CloseWithError(0, "")
}

type hy2SessionAuth[U comparable] struct {
	secret string
	user   U
}

type hy2ServerSession[U comparable] struct {
	*hy2Service[U]
	ctx        context.Context
	quicConn   *quic.Conn
	connAccess sync.Mutex
	connDone   chan struct{}
	connErr    error
	authState  atomic.Pointer[hy2SessionAuth[U]]
	udpAccess  sync.RWMutex
	udpConnMap map[uint32]*hy2UDPPacketConn
}

func (s *hy2ServerSession[U]) currentUser() (U, bool) {
	state := s.authState.Load()
	if state == nil {
		var zero U
		return zero, false
	}
	user, ok := s.lookupUser(state.secret)
	if !ok || user != state.user {
		var zero U
		return zero, false
	}
	return user, true
}

func (s *hy2ServerSession[U]) writeAuthResponse(w http.ResponseWriter, rxAuto bool) {
	h := w.Header()
	h.Set(hy2ResponseHeaderUDPEnabled, strconv.FormatBool(!s.udpDisabled))
	if rxAuto {
		h.Set(hy2CommonHeaderCCRX, "auto")
	} else {
		h.Set(hy2CommonHeaderCCRX, strconv.FormatUint(s.receiveBPS, 10))
	}
	h.Set(hy2CommonHeaderPadding, hy2AuthResponsePadding.generate())
	w.WriteHeader(hy2StatusAuthOK)
}

func (s *hy2ServerSession[U]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost && r.Host == hy2URLHost && r.URL.Path == hy2URLPath {
		if _, ok := s.currentUser(); ok {
			s.writeAuthResponse(w, s.receiveBPS == 0 && s.ignoreClientBandwidth)
			return
		}
		authSecret := r.Header.Get(hy2RequestHeaderAuth)
		clientRx, _ := strconv.ParseUint(r.Header.Get(hy2CommonHeaderCCRX), 10, 64)
		user, loaded := s.lookupUser(authSecret)
		if !loaded {
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		}
		var rxAuto bool
		if s.receiveBPS > 0 && s.ignoreClientBandwidth && clientRx == 0 {
			s.logger.Debug("process connection from ", r.RemoteAddr, ": BBR disabled by server")
			s.masqueradeHandler.ServeHTTP(w, r)
			return
		} else if !(s.receiveBPS == 0 && s.ignoreClientBandwidth) && clientRx > 0 {
			rx := clientRx
			if s.sendBPS > 0 && rx > s.sendBPS {
				rx = s.sendBPS
			}
			s.quicConn.SetCongestionControl(hyCC.NewBrutalSender(rx, s.brutalDebug, s.logger))
		} else {
			if s.setBBRCongestion != nil {
				s.setBBRCongestion(s.quicConn)
			}
			rxAuto = true
		}
		installed := s.authState.CompareAndSwap(nil, &hy2SessionAuth[U]{
			secret: authSecret,
			user:   user,
		})
		s.writeAuthResponse(w, rxAuto)
		if installed {
			if s.ctx.Done() != nil {
				go func() {
					select {
					case <-s.ctx.Done():
						s.closeWithError(s.ctx.Err())
					case <-s.connDone:
					}
				}()
			}
			if !s.udpDisabled {
				go s.loopMessages()
			}
		}
	} else {
		s.masqueradeHandler.ServeHTTP(w, r)
	}
}

func (s *hy2ServerSession[U]) dispatchStream(frameType http3.FrameType, stream *quic.Stream, err error) (bool, error) {
	if err != nil {
		return false, nil
	}
	user, ok := s.currentUser()
	if !ok {
		if s.authState.Load() != nil {
			s.closeWithError(E.New("user removed"))
		}
		return false, nil
	}
	if frameType != hy2FrameTypeTCPRequest {
		return false, nil
	}
	go func() {
		hErr := s.handleStream(stream, user)
		stream.CancelRead(0)
		stream.Close()
		if hErr != nil {
			stream.CancelRead(0)
			stream.Close()
			s.logger.Error(E.Cause(hErr, "handle stream request"))
		}
	}()
	return true, nil
}

func (s *hy2ServerSession[U]) handleStream(stream *quic.Stream, user U) error {
	_ = stream.SetReadDeadline(time.Now().Add(15 * time.Second))
	destinationString, err := hy2ReadTCPRequest(stream)
	if err != nil {
		return E.New("read TCP request")
	}
	_ = stream.SetReadDeadline(time.Time{})
	ctx := auth.ContextWithUser(s.ctx, user)
	_ = s.handler.NewConnection(ctx, &hy2ServerConn{Stream: stream}, M.Metadata{
		Source:      M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(),
		Destination: M.ParseSocksaddr(destinationString).Unwrap(),
	})
	return nil
}

func (s *hy2ServerSession[U]) closeWithError(err error) {
	s.connAccess.Lock()
	defer s.connAccess.Unlock()
	select {
	case <-s.connDone:
		return
	default:
		s.connErr = err
		close(s.connDone)
	}
	if E.IsClosedOrCanceled(err) {
		s.logger.Debug(E.Cause(err, "connection failed"))
	} else {
		s.logger.Error(E.Cause(err, "connection failed"))
	}
	s.udpAccess.Lock()
	udpConnMap := s.udpConnMap
	s.udpConnMap = make(map[uint32]*hy2UDPPacketConn)
	s.udpAccess.Unlock()
	for _, udpConn := range udpConnMap {
		udpConn.closeWithError(err)
	}
	_ = s.quicConn.CloseWithError(0, "")
}

func (s *hy2ServerSession[U]) loopMessages() {
	for {
		message, err := s.quicConn.ReceiveDatagram(s.ctx)
		if err != nil {
			s.closeWithError(E.Cause(err, "receive message"))
			return
		}
		hErr := s.handleMessage(message)
		if hErr != nil {
			s.closeWithError(E.Cause(hErr, "handle message"))
			return
		}
	}
}

func (s *hy2ServerSession[U]) handleMessage(data []byte) error {
	user, ok := s.currentUser()
	if !ok {
		return E.New("user removed")
	}
	message := hy2AllocMessage()
	err := hy2DecodeUDPMessage(message, data)
	if err != nil {
		message.releaseMessage()
		return E.Cause(err, "decode UDP message")
	}
	s.handleUDPMessage(message, user)
	return nil
}

func (s *hy2ServerSession[U]) handleUDPMessage(message *hy2UDPMessage, user U) {
	sessionID := message.sessionID
	s.udpAccess.RLock()
	udpConn, loaded := s.udpConnMap[sessionID]
	s.udpAccess.RUnlock()
	if !loaded || common.Done(udpConn.ctx) {
		udpConn = newHy2UDPPacketConn(auth.ContextWithUser(s.ctx, user), s.quicConn, func() {
			s.udpAccess.Lock()
			delete(s.udpConnMap, sessionID)
			s.udpAccess.Unlock()
		}, s.udpMTU)
		udpConn.sessionID = sessionID
		s.udpAccess.Lock()
		s.udpConnMap[sessionID] = udpConn
		s.udpAccess.Unlock()
		newCtx, newConn := canceler.NewPacketConn(udpConn.ctx, udpConn, s.udpTimeout)
		go s.handler.NewPacketConnection(newCtx, newConn, M.Metadata{
			Source:      M.SocksaddrFromNet(s.quicConn.RemoteAddr()).Unwrap(),
			Destination: M.ParseSocksaddr(message.destination).Unwrap(),
		})
	}
	udpConn.inputPacket(message)
}

type hy2ServerConn struct {
	*quic.Stream
	responseWritten bool
}

func (c *hy2ServerConn) HandshakeFailure(err error) error {
	if c.responseWritten {
		return os.ErrClosed
	}
	c.responseWritten = true
	buffer := hy2WriteTCPResponse(false, err.Error(), nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *hy2ServerConn) HandshakeSuccess() error {
	if c.responseWritten {
		return nil
	}
	c.responseWritten = true
	buffer := hy2WriteTCPResponse(true, "", nil)
	defer buffer.Release()
	return common.Error(c.Stream.Write(buffer.Bytes()))
}

func (c *hy2ServerConn) Read(p []byte) (n int, err error) {
	n, err = c.Stream.Read(p)
	return n, baderror.WrapQUIC(err)
}

func (c *hy2ServerConn) Write(p []byte) (n int, err error) {
	if !c.responseWritten {
		c.responseWritten = true
		buffer := hy2WriteTCPResponse(true, "", p)
		defer buffer.Release()
		_, err = c.Stream.Write(buffer.Bytes())
		if err != nil {
			return 0, baderror.WrapQUIC(err)
		}
		return len(p), nil
	}
	n, err = c.Stream.Write(p)
	return n, baderror.WrapQUIC(err)
}

func (c *hy2ServerConn) LocalAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *hy2ServerConn) RemoteAddr() net.Addr {
	return M.Socksaddr{}
}

func (c *hy2ServerConn) Close() error {
	c.Stream.CancelRead(0)
	return c.Stream.Close()
}

func hy2ReadTCPRequest(r io.Reader) (string, error) {
	bReader := quicvarint.NewReader(r)
	frameType, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if frameType != hy2FrameTypeTCPRequest {
		return "", E.New("invalid frame type")
	}
	addrLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if addrLen == 0 || addrLen > hy2MaxAddressLength {
		return "", E.New("invalid address length")
	}
	addrBuf := make([]byte, addrLen)
	_, err = io.ReadFull(r, addrBuf)
	if err != nil {
		return "", err
	}
	paddingLen, err := quicvarint.Read(bReader)
	if err != nil {
		return "", err
	}
	if paddingLen > hy2MaxPaddingLength {
		return "", E.New("invalid padding length")
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, r, int64(paddingLen))
		if err != nil {
			return "", err
		}
	}
	return string(addrBuf), nil
}

func hy2WriteTCPResponse(ok bool, msg string, payload []byte) *buf.Buffer {
	padding := hy2TCPResponsePadding.generate()
	paddingLen := len(padding)
	msgLen := len(msg)
	if msgLen > hy2MaxMessageLength {
		msgLen = hy2MaxMessageLength
	}
	sz := 1 + int(quicvarint.Len(uint64(msgLen))) + msgLen +
		int(quicvarint.Len(uint64(paddingLen))) + paddingLen
	buffer := buf.NewSize(sz + len(payload))
	if ok {
		buffer.WriteByte(0)
	} else {
		buffer.WriteByte(1)
	}
	_ = hy2WriteVString(buffer, msg[:msgLen])
	_ = hy2WriteUVariant(buffer, uint64(paddingLen))
	copy(buffer.Extend(paddingLen), padding)
	buffer.Write(payload)
	return buffer
}

func hy2ReadVString(reader io.Reader) (string, error) {
	length, err := quicvarint.Read(quicvarint.NewReader(reader))
	if err != nil {
		return "", err
	}
	if length > hy2MaxAddressLength {
		return "", E.New("invalid address length")
	}
	value, err := rw.ReadBytes(reader, int(length))
	if err != nil {
		return "", err
	}
	return string(value), nil
}

func hy2WriteVString(writer io.Writer, value string) error {
	err := hy2WriteUVariant(writer, uint64(len(value)))
	if err != nil {
		return err
	}
	return rw.WriteString(writer, value)
}

func hy2WriteUVariant(writer io.Writer, value uint64) error {
	var b [8]byte
	return common.Error(writer.Write(b[:hy2VarintPut(b[:], value)]))
}

func hy2VarintPut(b []byte, i uint64) int {
	if i <= hy2MaxVarInt1 {
		b[0] = uint8(i)
		return 1
	}
	if i <= hy2MaxVarInt2 {
		b[0] = uint8(i>>8) | 0x40
		b[1] = uint8(i)
		return 2
	}
	if i <= hy2MaxVarInt4 {
		b[0] = uint8(i>>24) | 0x80
		b[1] = uint8(i >> 16)
		b[2] = uint8(i >> 8)
		b[3] = uint8(i)
		return 4
	}
	if i <= hy2MaxVarInt8 {
		b[0] = uint8(i>>56) | 0xc0
		b[1] = uint8(i >> 48)
		b[2] = uint8(i >> 40)
		b[3] = uint8(i >> 32)
		b[4] = uint8(i >> 24)
		b[5] = uint8(i >> 16)
		b[6] = uint8(i >> 8)
		b[7] = uint8(i)
		return 8
	}
	panic(fmt.Sprintf("%#x doesn't fit into 62 bits", i))
}

var hy2UDPMessagePool = sync.Pool{
	New: func() any {
		return new(hy2UDPMessage)
	},
}

func hy2AllocMessage() *hy2UDPMessage {
	message := hy2UDPMessagePool.Get().(*hy2UDPMessage)
	message.referenced = true
	return message
}

func hy2ReleaseMessages(messages []*hy2UDPMessage) {
	for _, message := range messages {
		if message != nil {
			message.releaseMessage()
		}
	}
}

type hy2UDPMessage struct {
	sessionID     uint32
	packetID      uint16
	fragmentID    uint8
	fragmentTotal uint8
	destination   string
	data          *buf.Buffer
	referenced    bool
}

func (m *hy2UDPMessage) release() {
	if !m.referenced {
		return
	}
	*m = hy2UDPMessage{}
	hy2UDPMessagePool.Put(m)
}

func (m *hy2UDPMessage) releaseMessage() {
	m.data.Release()
	m.release()
}

func (m *hy2UDPMessage) pack() *buf.Buffer {
	buffer := buf.NewSize(m.headerSize() + m.data.Len())
	common.Must(
		binary.Write(buffer, binary.BigEndian, m.sessionID),
		binary.Write(buffer, binary.BigEndian, m.packetID),
		binary.Write(buffer, binary.BigEndian, m.fragmentID),
		binary.Write(buffer, binary.BigEndian, m.fragmentTotal),
		hy2WriteVString(buffer, m.destination),
		common.Error(buffer.Write(m.data.Bytes())),
	)
	return buffer
}

func (m *hy2UDPMessage) headerSize() int {
	return 8 + int(quicvarint.Len(uint64(len(m.destination)))) + len(m.destination)
}

func hy2FragUDPMessage(message *hy2UDPMessage, maxPacketSize int) []*hy2UDPMessage {
	udpMTU := maxPacketSize - message.headerSize()
	if message.data.Len() <= udpMTU {
		return []*hy2UDPMessage{message}
	}
	var fragments []*hy2UDPMessage
	originPacket := message.data.Bytes()
	for remaining := len(originPacket); remaining > 0; remaining -= udpMTU {
		fragment := hy2AllocMessage()
		*fragment = *message
		if remaining > udpMTU {
			fragment.data = buf.As(originPacket[:udpMTU])
			originPacket = originPacket[udpMTU:]
		} else {
			fragment.data = buf.As(originPacket)
			originPacket = nil
		}
		fragments = append(fragments, fragment)
	}
	fragmentTotal := uint16(len(fragments))
	for index, fragment := range fragments {
		fragment.fragmentID = uint8(index)
		fragment.fragmentTotal = uint8(fragmentTotal)
	}
	return fragments
}

type hy2UDPPacketConn struct {
	ctx             context.Context
	cancel          common.ContextCancelCauseFunc
	sessionID       uint32
	quicConn        *quic.Conn
	data            chan *hy2UDPMessage
	udpMTU          int
	packetId        atomic.Uint32
	closeOnce       sync.Once
	defragger       *hy2UDPDefragger
	onDestroy       func()
	readWaitOptions N.ReadWaitOptions
	readDeadline    pipe.Deadline
}

func newHy2UDPPacketConn(ctx context.Context, quicConn *quic.Conn, onDestroy func(), udpMTU int) *hy2UDPPacketConn {
	ctx, cancel := common.ContextWithCancelCause(ctx)
	return &hy2UDPPacketConn{
		ctx:          ctx,
		cancel:       cancel,
		quicConn:     quicConn,
		data:         make(chan *hy2UDPMessage, 64),
		defragger:    newHy2UDPDefragger(),
		onDestroy:    onDestroy,
		udpMTU:       udpMTU,
		readDeadline: pipe.MakeDeadline(),
	}
}

func (c *hy2UDPPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readWaitOptions = options
	return options.NeedHeadroom()
}

func (c *hy2UDPPacketConn) WaitReadPacket() (buffer *buf.Buffer, destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		destination = M.ParseSocksaddr(p.destination).Unwrap()
		if c.readWaitOptions.NeedHeadroom() {
			buffer = c.readWaitOptions.NewPacketBuffer()
			_, err = buffer.Write(p.data.Bytes())
			if err != nil {
				buffer.Release()
				return nil, M.Socksaddr{}, err
			}
			p.releaseMessage()
			c.readWaitOptions.PostReturn(buffer)
		} else {
			buffer = p.data
			p.release()
		}
		return
	case <-c.ctx.Done():
		return nil, M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return nil, M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *hy2UDPPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	select {
	case p := <-c.data:
		_, err = buffer.ReadOnceFrom(p.data)
		destination = M.ParseSocksaddr(p.destination).Unwrap()
		p.releaseMessage()
		return
	case <-c.ctx.Done():
		return M.Socksaddr{}, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return M.Socksaddr{}, os.ErrDeadlineExceeded
	}
}

func (c *hy2UDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	select {
	case pkt := <-c.data:
		n = copy(p, pkt.data.Bytes())
		destination := M.ParseSocksaddr(pkt.destination).Unwrap()
		if destination.IsFqdn() {
			addr = destination
		} else {
			addr = destination.UDPAddr()
		}
		pkt.releaseMessage()
		return n, addr, nil
	case <-c.ctx.Done():
		return 0, nil, io.ErrClosedPipe
	case <-c.readDeadline.Wait():
		return 0, nil, os.ErrDeadlineExceeded
	}
}

func (c *hy2UDPPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	select {
	case <-c.ctx.Done():
		return net.ErrClosed
	default:
	}
	if buffer.Len() > hy2MaxUDPSize {
		return &quic.DatagramTooLargeError{MaxDatagramPayloadSize: hy2MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := hy2AllocMessage()
	*message = hy2UDPMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   destination.String(),
		data:          buffer,
	}
	defer message.releaseMessage()
	var err error
	if buffer.Len() > c.udpMTU-message.headerSize() {
		err = c.writePackets(hy2FragUDPMessage(message, c.udpMTU))
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return err
	}
	return c.writePackets(hy2FragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize)))
}

func (c *hy2UDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	select {
	case <-c.ctx.Done():
		return 0, net.ErrClosed
	default:
	}
	if len(p) > hy2MaxUDPSize {
		return 0, &quic.DatagramTooLargeError{MaxDatagramPayloadSize: hy2MaxUDPSize}
	}
	packetId := uint16(c.packetId.Add(1) % math.MaxUint16)
	message := hy2AllocMessage()
	*message = hy2UDPMessage{
		sessionID:     c.sessionID,
		packetID:      packetId,
		fragmentTotal: 1,
		destination:   addr.String(),
		data:          buf.As(p),
	}
	defer message.releaseMessage()
	if len(p) > c.udpMTU-message.headerSize() {
		err = c.writePackets(hy2FragUDPMessage(message, c.udpMTU))
		if err == nil {
			return len(p), nil
		}
	} else {
		err = c.writePacket(message)
	}
	if err == nil {
		return len(p), nil
	}
	var tooLargeErr *quic.DatagramTooLargeError
	if !errors.As(err, &tooLargeErr) {
		return
	}
	err = c.writePackets(hy2FragUDPMessage(message, int(tooLargeErr.MaxDatagramPayloadSize)))
	if err == nil {
		return len(p), nil
	}
	return
}

func (c *hy2UDPPacketConn) inputPacket(message *hy2UDPMessage) {
	if message.fragmentTotal <= 1 {
		select {
		case c.data <- message:
		default:
			message.releaseMessage()
		}
	} else {
		newMessage := c.defragger.feed(message)
		if newMessage != nil {
			select {
			case c.data <- newMessage:
			default:
				newMessage.releaseMessage()
			}
		}
	}
}

func (c *hy2UDPPacketConn) writePackets(messages []*hy2UDPMessage) error {
	defer hy2ReleaseMessages(messages)
	for _, message := range messages {
		err := c.writePacket(message)
		if err != nil {
			return err
		}
	}
	return nil
}

func (c *hy2UDPPacketConn) writePacket(message *hy2UDPMessage) error {
	buffer := message.pack()
	defer buffer.Release()
	return c.quicConn.SendDatagram(buffer.Bytes())
}

func (c *hy2UDPPacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.closeWithError(os.ErrClosed)
		c.onDestroy()
	})
	return nil
}

func (c *hy2UDPPacketConn) closeWithError(err error) {
	c.cancel(err)
}

func (c *hy2UDPPacketConn) LocalAddr() net.Addr {
	return c.quicConn.LocalAddr()
}

func (c *hy2UDPPacketConn) SetDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *hy2UDPPacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Set(t)
	return nil
}

func (c *hy2UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return os.ErrInvalid
}

func (c *hy2UDPPacketConn) ReaderMTU() int {
	return hy2MaxUDPSize
}

func (c *hy2UDPPacketConn) WriterMTU() int {
	return hy2MaxUDPSize
}

type hy2UDPDefragger struct {
	packetMap *cache.LruCache[uint16, *hy2PacketItem]
}

func newHy2UDPDefragger() *hy2UDPDefragger {
	return &hy2UDPDefragger{
		packetMap: cache.New(
			cache.WithAge[uint16, *hy2PacketItem](10),
			cache.WithUpdateAgeOnGet[uint16, *hy2PacketItem](),
			cache.WithEvict[uint16, *hy2PacketItem](func(key uint16, value *hy2PacketItem) {
				hy2ReleaseMessages(value.messages)
			}),
		),
	}
}

type hy2PacketItem struct {
	access   sync.Mutex
	messages []*hy2UDPMessage
	count    uint8
}

func (d *hy2UDPDefragger) feed(m *hy2UDPMessage) *hy2UDPMessage {
	if m.fragmentTotal <= 1 {
		return m
	}
	if m.fragmentID >= m.fragmentTotal {
		m.releaseMessage()
		return nil
	}
	item, _ := d.packetMap.LoadOrStore(m.packetID, func() *hy2PacketItem {
		return new(hy2PacketItem)
	})
	item.access.Lock()
	defer item.access.Unlock()
	if int(m.fragmentTotal) != len(item.messages) {
		hy2ReleaseMessages(item.messages)
		item.messages = make([]*hy2UDPMessage, m.fragmentTotal)
		item.count = 1
		item.messages[m.fragmentID] = m
		return nil
	}
	if item.messages[m.fragmentID] != nil {
		m.releaseMessage()
		return nil
	}
	item.messages[m.fragmentID] = m
	item.count++
	if int(item.count) != len(item.messages) {
		return nil
	}
	newMessage := hy2AllocMessage()
	newMessage.sessionID = m.sessionID
	newMessage.packetID = m.packetID
	newMessage.destination = item.messages[0].destination
	var finalLength int
	for _, message := range item.messages {
		finalLength += message.data.Len()
	}
	if finalLength > 0 {
		newMessage.data = buf.NewSize(finalLength)
		for _, message := range item.messages {
			newMessage.data.Write(message.data.Bytes())
			message.releaseMessage()
		}
		item.messages = nil
		return newMessage
	}
	newMessage.releaseMessage()
	for _, message := range item.messages {
		message.releaseMessage()
	}
	item.messages = nil
	return nil
}

func hy2DecodeUDPMessage(message *hy2UDPMessage, data []byte) error {
	reader := bytes.NewReader(data)
	if err := binary.Read(reader, binary.BigEndian, &message.sessionID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.packetID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentID); err != nil {
		return err
	}
	if err := binary.Read(reader, binary.BigEndian, &message.fragmentTotal); err != nil {
		return err
	}
	var err error
	message.destination, err = hy2ReadVString(reader)
	if err != nil {
		return err
	}
	message.data = buf.As(data[len(data)-reader.Len():])
	return nil
}
