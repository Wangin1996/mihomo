package snell

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/mihomo/adapter/inbound"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/jls"
	"github.com/metacubex/mihomo/listener/restls"
	"github.com/metacubex/mihomo/listener/shadowtls"
	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
	obfs "github.com/metacubex/mihomo/transport/simple-obfs"
	"github.com/metacubex/mihomo/transport/snell"
)

const (
	maxPacketLength  = 0x3fff
	handshakeTimeout = 15 * time.Second
)

type snellUserEntry struct {
	name    string
	matcher *snell.UserMatcher
}

type snellUserSnapshot struct {
	entries     []snellUserEntry          // sorted by matcher.FirstHeaderLen() ascending
	byName      map[string]snellUserEntry // for shadowtls/jls pre-authenticated lookup
	defaultUser *snellUserEntry           // single-user fallback (Psk or v6 unsafe-raw with 1 user)
	maxPeekLen  int
}

type Listener struct {
	closed    bool
	config    LC.SnellServer
	listeners []net.Listener
	v6Mode    snell.V6Mode // only used for version 6
	users     atomic.Pointer[snellUserSnapshot]
	updateMu  sync.Mutex
}

func buildUserSnapshot(config LC.SnellServer, v6Mode snell.V6Mode, psk string, users map[string]string) (*snellUserSnapshot, error) {
	if psk == "" && len(users) == 0 {
		return nil, errors.New("snell inbound requires psk or users")
	}
	if config.Version == snell.Version6 && v6Mode == snell.V6ModeUnsafeRaw && len(users) > 1 {
		return nil, errors.New("snell inbound version 6 unsafe-raw mode does not support multiple users")
	}

	snap := &snellUserSnapshot{}
	if len(users) > 0 {
		snap.entries = make([]snellUserEntry, 0, len(users))
		snap.byName = make(map[string]snellUserEntry, len(users))
		for username, userPSK := range users {
			if userPSK == "" {
				return nil, fmt.Errorf("snell inbound user %q has empty psk", username)
			}
			matcher, err := snell.NewUserMatcher([]byte(userPSK), config.Version, v6Mode)
			if err != nil {
				return nil, fmt.Errorf("snell inbound user %q: %w", username, err)
			}
			entry := snellUserEntry{
				name:    username,
				matcher: matcher,
			}
			snap.entries = append(snap.entries, entry)
			snap.byName[username] = entry
		}
		sort.Slice(snap.entries, func(i, j int) bool {
			li, lj := snap.entries[i].matcher.FirstHeaderLen(), snap.entries[j].matcher.FirstHeaderLen()
			if li != lj {
				return li < lj
			}
			return snap.entries[i].name < snap.entries[j].name
		})
		snap.maxPeekLen = snap.entries[len(snap.entries)-1].matcher.FirstHeaderLen()
		if config.Version == snell.Version6 && v6Mode == snell.V6ModeUnsafeRaw && len(snap.entries) == 1 {
			entry := snap.entries[0]
			snap.defaultUser = &entry
		}
	}

	if psk != "" {
		matcher, err := snell.NewUserMatcher([]byte(psk), config.Version, v6Mode)
		if err != nil {
			return nil, fmt.Errorf("snell inbound %w", err)
		}
		snap.defaultUser = &snellUserEntry{
			name:    "",
			matcher: matcher,
		}
	}

	return snap, nil
}

func New(config LC.SnellServer, lc C.InboundListenConfig, tunnel C.Tunnel, additions ...inbound.Addition) (_ C.MultiAddrListener, err error) {
	if config.Version == 0 {
		config.Version = snell.Version4
	}
	switch config.Version {
	case snell.Version1, snell.Version2, snell.Version3, snell.Version4, snell.Version5:
		if config.Mode != "" {
			return nil, errors.New("snell inbound mode is only supported on version 6")
		}
	case snell.Version6:
	default:
		return nil, fmt.Errorf("snell inbound version %d is not supported", config.Version)
	}
	if config.Psk == "" && len(config.Users) == 0 {
		return nil, errors.New("snell inbound requires psk or users")
	}
	switch config.ObfsMode {
	case "", "http", "tls":
	default:
		return nil, fmt.Errorf("snell inbound obfs mode error: %s", config.ObfsMode)
	}

	config.Users = maps.Clone(config.Users)
	l := &Listener{config: config}
	defer func() {
		if err != nil && l != nil {
			_ = l.Close()
		}
	}()

	if config.Version == snell.Version6 {
		if config.ObfsMode != "" {
			// v6 replaced the simple-obfs layer with PSK-derived traffic shaping
			return nil, fmt.Errorf("snell inbound version 6 does not support obfs mode %s", config.ObfsMode)
		}
		l.v6Mode, err = snell.ParseV6Mode(config.Mode)
		if err != nil {
			return nil, fmt.Errorf("snell inbound %w", err)
		}
	}

	snap, err := buildUserSnapshot(config, l.v6Mode, config.Psk, config.Users)
	if err != nil {
		return nil, err
	}
	l.users.Store(snap)

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
		return nil, errors.New("security modes are mutually exclusive: " + strings.Join(securityModes, ", "))
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
	for _, addr := range strings.Split(config.Listen, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		var ln net.Listener
		ln, err = lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			return nil, err
		}
		if shadowTLSBuilder != nil {
			ln = shadowTLSBuilder.NewListener(ln)
		} else if restlsBuilder != nil {
			ln = restlsBuilder.NewListener(ln)
		} else if jlsBuilder != nil {
			ln = jlsBuilder.NewListener(ln)
		}
		l.listeners = append(l.listeners, ln)
		go func(ln net.Listener) {
			for {
				conn, err := ln.Accept()
				if err != nil {
					if l.closed {
						return
					}
					continue
				}
				go l.HandleConn(conn, tunnel, additions...)
			}
		}(ln)
	}
	return l, nil
}

func (l *Listener) Close() error {
	l.closed = true
	var retErr error
	for _, ln := range l.listeners {
		if err := ln.Close(); err != nil {
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

func (l *Listener) UpdateUsers(users map[string]string) error {
	if len(users) == 0 {
		return errors.New("snell inbound requires at least one user")
	}
	l.updateMu.Lock()
	defer l.updateMu.Unlock()
	snap, err := buildUserSnapshot(l.config, l.v6Mode, l.config.Psk, users)
	if err != nil {
		return err
	}
	l.users.Store(snap)
	l.config.Users = maps.Clone(users)
	return nil
}

func (l *Listener) AddrList() (addrList []net.Addr) {
	for _, ln := range l.listeners {
		addrList = append(addrList, ln.Addr())
	}
	return
}

func (l *Listener) selectStream(conn net.Conn, snap *snellUserSnapshot, preAuthUser string, preAuthLoaded bool) (*snell.Snell, string, error) {
	if preAuthLoaded {
		if snap.defaultUser != nil && snap.defaultUser.name == "" {
			return snap.defaultUser.matcher.ServerStreamConn(conn), "", nil
		}
		if entry, ok := snap.byName[preAuthUser]; ok {
			return entry.matcher.ServerStreamConn(conn), "", nil
		}
		if len(snap.entries) > 0 && !(l.config.Version == snell.Version6 && l.v6Mode == snell.V6ModeUnsafeRaw) {
			entry, peeked, err := matchUserFromConn(conn, snap)
			if err != nil {
				return nil, "", err
			}
			return entry.matcher.ServerStreamConn(snell.NewPrefixConn(conn, peeked)), "", nil
		}
		if snap.defaultUser != nil {
			return snap.defaultUser.matcher.ServerStreamConn(conn), "", nil
		}
		return nil, "", errors.New("snell: no matching user")
	}

	if len(snap.entries) == 0 {
		if snap.defaultUser == nil {
			return nil, "", errors.New("snell: no psk configured")
		}
		return snap.defaultUser.matcher.ServerStreamConn(conn), "", nil
	}

	if l.config.Version == snell.Version6 && l.v6Mode == snell.V6ModeUnsafeRaw {
		if snap.defaultUser == nil {
			return nil, "", errors.New("snell: no user configured")
		}
		return snap.defaultUser.matcher.ServerStreamConn(conn), snap.defaultUser.name, nil
	}

	entry, peeked, err := matchUserFromConn(conn, snap)
	if err != nil {
		return nil, "", err
	}
	return entry.matcher.ServerStreamConn(snell.NewPrefixConn(conn, peeked)), entry.name, nil
}

func matchUserFromConn(conn net.Conn, snap *snellUserSnapshot) (snellUserEntry, []byte, error) {
	if len(snap.entries) == 0 || snap.maxPeekLen <= 0 {
		return snellUserEntry{}, nil, errors.New("snell: no users configured")
	}
	buf := make([]byte, snap.maxPeekLen)
	peekedLen := 0

	ensurePeeked := func(need int) error {
		for peekedLen < need {
			n, err := conn.Read(buf[peekedLen:])
			if n > 0 {
				peekedLen += n
			}
			if err != nil {
				if peekedLen >= need {
					return nil
				}
				return err
			}
		}
		return nil
	}

	minNeed := snap.entries[0].matcher.FirstHeaderLen()
	if err := ensurePeeked(minNeed); err != nil {
		return snellUserEntry{}, nil, err
	}

	var tried []bool
	if len(snap.entries) > 1 {
		for i := range snap.entries {
			entry := snap.entries[i]
			if entry.matcher.FirstHeaderLen() > peekedLen {
				break
			}
			if entry.matcher.MatchPrefixHint(buf[:peekedLen]) {
				if entry.matcher.MatchFirstHeader(buf[:peekedLen]) {
					return entry, buf[:peekedLen], nil
				}
				if tried == nil {
					tried = make([]bool, len(snap.entries))
				}
				tried[i] = true
			}
		}
	}

	for i := range snap.entries {
		if tried != nil && tried[i] {
			continue
		}
		entry := snap.entries[i]
		if err := ensurePeeked(entry.matcher.FirstHeaderLen()); err != nil {
			return snellUserEntry{}, nil, err
		}
		if entry.matcher.MatchFirstHeader(buf[:peekedLen]) {
			return entry, buf[:peekedLen], nil
		}
	}

	return snellUserEntry{}, nil, errors.New("snell: no matching user")
}

func (l *Listener) HandleConn(rawConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) {
	defer rawConn.Close()
	snap := l.users.Load()
	if snap == nil {
		return
	}

	_ = rawConn.SetReadDeadline(time.Now().Add(handshakeTimeout))

	user, loaded := shadowtls.UserFromConn(rawConn)
	if jlsUser, jlsLoaded := jls.UserFromConn(rawConn); jlsLoaded {
		user, loaded = jlsUser, true
	}
	if loaded {
		additions = append(append([]inbound.Addition(nil), additions...), inbound.WithInUser(user))
	}
	conn := rawConn
	switch l.config.ObfsMode {
	case "http":
		conn = obfs.NewHTTPObfsServer(conn)
	case "tls":
		conn = obfs.NewTLSObfsServer(conn)
	case "":
	default:
		return
	}
	stream, matchedUser, err := l.selectStream(conn, snap, user, loaded)
	if err != nil {
		return
	}
	if !loaded && matchedUser != "" {
		additions = append(append([]inbound.Addition(nil), additions...), inbound.WithInUser(matchedUser))
	}
	for {
		reuse, err := l.handleRequest(stream, rawConn, tunnel, additions...)
		if err != nil || !reuse {
			return
		}
	}
}

func (l *Listener) handleRequest(stream *snell.Snell, rawConn net.Conn, tunnel C.Tunnel, additions ...inbound.Addition) (bool, error) {
	br := bufio.NewReader(stream)
	version, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if version != snell.Version {
		return false, fmt.Errorf("snell invalid protocol version: %d", version)
	}

	command, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if command == snell.CommandPing {
		_ = rawConn.SetReadDeadline(time.Time{})
		_, _ = stream.Write([]byte{snell.CommandPong})
		return false, nil
	}

	clientID, err := readClientID(br)
	if err != nil {
		return false, err
	}

	switch command {
	case snell.CommandConnect, snell.CommandConnectV2:
		return l.handleTCP(stream, rawConn, br, command == snell.CommandConnectV2, clientID, tunnel, additions...)
	case snell.CommandUDP:
		if !l.config.UDP {
			return false, errors.New("snell UDP is disabled")
		}
		_ = rawConn.SetReadDeadline(time.Time{})
		return false, l.handleUDP(stream, clientID, tunnel, additions...)
	default:
		return false, fmt.Errorf("snell unknown command: %d", command)
	}
}

func readClientID(r *bufio.Reader) (string, error) {
	length, err := r.ReadByte()
	if err != nil {
		return "", err
	}
	if length == 0 {
		return "", nil
	}
	id := make([]byte, int(length))
	if _, err := io.ReadFull(r, id); err != nil {
		return "", err
	}
	return string(id), nil
}

func (l *Listener) handleTCP(stream *snell.Snell, rawConn net.Conn, br *bufio.Reader, reuse bool, clientID string, tunnel C.Tunnel, additions ...inbound.Addition) (bool, error) {
	hostLen, err := br.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("snell connect host is empty")
	}

	hostBytes := make([]byte, int(hostLen))
	if _, err := io.ReadFull(br, hostBytes); err != nil {
		return false, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(br, portBytes[:]); err != nil {
		return false, err
	}

	_ = rawConn.SetReadDeadline(time.Time{})
	metadata := l.metadata(C.TCP, string(hostBytes), binary.BigEndian.Uint16(portBytes[:]), stream, clientID, additions...)
	conn := &tcpRequestConn{
		Conn:   stream,
		reader: br,
		reuse:  reuse,
	}
	tunnel.HandleTCPConn(conn, metadata)
	if !reuse {
		return false, nil
	}
	return true, nil
}

func (l *Listener) handleUDP(stream *snell.Snell, clientID string, tunnel C.Tunnel, additions ...inbound.Addition) error {
	if _, err := stream.Write([]byte{snell.CommandTunnel}); err != nil {
		return err
	}

	connID := utils.NewUUIDV4().String()
	localAddr := N.NewCustomAddr(C.SNELL.String(), connID, stream.RemoteAddr())
	writeMu := &sync.Mutex{}
	buf := make([]byte, maxPacketLength)
	for {
		n, err := stream.Read(buf)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, shadowaead.ErrZeroChunk) {
				return nil
			}
			return err
		}
		request, err := snell.ParseUDPRequest(buf[:n])
		if err != nil {
			return err
		}
		metadata := l.metadata(C.UDP, request.Host, request.Port, stream, clientID, additions...)
		if request.Ip.IsValid() {
			metadata.Host = ""
			metadata.DstIP = request.Ip
		}

		payload := append([]byte(nil), request.Payload...)
		packet := &udpPacket{
			data:      payload,
			conn:      stream,
			writeMu:   writeMu,
			localAddr: localAddr,
			dstAddr:   metadata.UDPAddr(),
		}
		tunnel.HandleUDPPacket(packet, metadata)
	}
}

func (l *Listener) metadata(network C.NetWork, host string, port uint16, conn net.Conn, clientID string, additions ...inbound.Addition) *C.Metadata {
	metadata := &C.Metadata{
		NetWork: network,
		Type:    C.SNELL,
		DstPort: port,
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		metadata.DstIP = ip.Unmap()
	} else {
		metadata.Host = host
	}
	inbound.ApplyAdditions(metadata, inbound.WithSrcAddr(conn.RemoteAddr()), inbound.WithInAddr(conn.LocalAddr()))
	inbound.ApplyAdditions(metadata, additions...)
	if metadata.InUser == "" && clientID != "" {
		inbound.ApplyAdditions(metadata, inbound.WithInUser(clientID))
	}
	return metadata
}

func writeCommandError(w io.Writer, code byte, message string) error {
	msg := []byte(message)
	if len(msg) > 255 {
		msg = msg[:255]
	}
	buf := make([]byte, 0, 3+len(msg))
	buf = append(buf, snell.CommandError, code, byte(len(msg)))
	buf = append(buf, msg...)
	_, err := w.Write(buf)
	return err
}

type tcpRequestConn struct {
	net.Conn
	reader       *bufio.Reader
	reuse        bool
	writeMu      sync.Mutex
	closeOnce    sync.Once
	replyWritten bool
}

func (c *tcpRequestConn) Read(p []byte) (int, error) {
	n, err := c.reader.Read(p)
	if errors.Is(err, shadowaead.ErrZeroChunk) {
		err = io.EOF
	}
	return n, err
}

func (c *tcpRequestConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if !c.replyWritten {
		payload := make([]byte, 1+len(p))
		payload[0] = snell.CommandTunnel
		copy(payload[1:], p)
		if _, err := c.Conn.Write(payload); err != nil {
			return 0, err
		}
		c.replyWritten = true
		return len(p), nil
	}
	return c.Conn.Write(p)
}

func (c *tcpRequestConn) CloseWrite() error {
	return c.Close()
}

func (c *tcpRequestConn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()

		if !c.replyWritten {
			err = writeCommandError(c.Conn, 0x65, "Remote EOF")
			if !c.reuse {
				err = errors.Join(err, c.Conn.Close())
			}
			return
		}
		if c.reuse {
			_, err = c.Conn.Write(nil)
			return
		}
		err = c.Conn.Close()
	})
	return err
}

type udpPacket struct {
	data      []byte
	conn      *snell.Snell
	writeMu   *sync.Mutex
	localAddr net.Addr
	dstAddr   net.Addr
}

func (p *udpPacket) Data() []byte {
	return p.data
}

func (p *udpPacket) WriteBack(b []byte, addr net.Addr) (int, error) {
	if addr == nil {
		addr = p.dstAddr
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	return snell.WritePacketResponse(p.conn, addr, b)
}

func (p *udpPacket) Drop() {
	p.data = nil
}

func (p *udpPacket) LocalAddr() net.Addr {
	return p.localAddr
}

var _ C.MultiAddrListener = (*Listener)(nil)
var _ C.UDPPacket = (*udpPacket)(nil)
