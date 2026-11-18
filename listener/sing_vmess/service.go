package sing_vmess

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gofrs/uuid/v5"
	vmess "github.com/metacubex/sing-vmess"
	"github.com/metacubex/sing/common"
	"github.com/metacubex/sing/common/auth"
	"github.com/metacubex/sing/common/buf"
	"github.com/metacubex/sing/common/bufio"
	E "github.com/metacubex/sing/common/exceptions"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
	"github.com/metacubex/sing/common/replay"
	"github.com/metacubex/sing/common/rw"
)

type vmessUserTable[U comparable] struct {
	userKey      map[U][16]byte
	userIdCipher map[U]cipher.Block
	alterIds     map[U][][16]byte
}

type legacyUserEntry[U comparable] struct {
	User  U
	Time  int64
	Index int
}

type Service[U comparable] struct {
	users                atomic.Pointer[vmessUserTable[U]]
	legacyUsers          atomic.Pointer[map[[16]byte]legacyUserEntry[U]]
	replayFilter         replay.Filter
	handler              vmess.Handler
	time                 func() time.Time
	disableHeaderProtect bool

	legacyMu          sync.Mutex
	started           bool
	closed            bool
	alterIdUpdateTime map[U]int64
	alterIdUpdateTask *time.Ticker
	alterIdUpdateDone chan struct{}
}

func NewService[U comparable](handler vmess.Handler, timeFunc func() time.Time, disableHeaderProtect bool) *Service[U] {
	if timeFunc == nil {
		timeFunc = time.Now
	}
	s := &Service[U]{
		replayFilter:         replay.NewSimple(time.Second * 120),
		handler:              handler,
		time:                 timeFunc,
		disableHeaderProtect: disableHeaderProtect,
		alterIdUpdateTime:    make(map[U]int64),
	}
	s.users.Store(&vmessUserTable[U]{
		userKey:      make(map[U][16]byte),
		userIdCipher: make(map[U]cipher.Block),
		alterIds:     make(map[U][][16]byte),
	})
	emptyLegacy := make(map[[16]byte]legacyUserEntry[U])
	s.legacyUsers.Store(&emptyLegacy)
	return s
}

func (s *Service[U]) UpdateUsers(userList []U, userIdList []string, alterIdList []int) error {
	userKeyMap := make(map[U][16]byte, len(userList))
	userIdCipherMap := make(map[U]cipher.Block, len(userList))
	userAlterIds := make(map[U][][16]byte)
	for i, user := range userList {
		userId := userIdList[i]
		userUUID, err := uuid.FromString(userId)
		if err != nil {
			userUUID = uuid.NewV5(uuid.Nil, userId)
		}
		userCmdKey := vmess.Key(userUUID)
		userKeyMap[user] = userCmdKey
		userIdCipher, err := aes.NewCipher(vmess.KDF(userCmdKey[:], vmess.KDFSaltConstAuthIDEncryptionKey)[:16])
		if err != nil {
			return err
		}
		userIdCipherMap[user] = userIdCipher
		alterId := alterIdList[i]
		if alterId > 0 {
			alterIds := make([][16]byte, 0, alterId)
			currentId := userUUID
			for j := 0; j < alterId; j++ {
				currentId = vmess.AlterId(currentId)
				alterIds = append(alterIds, currentId)
			}
			userAlterIds[user] = alterIds
		}
	}

	table := &vmessUserTable[U]{
		userKey:      userKeyMap,
		userIdCipher: userIdCipherMap,
		alterIds:     userAlterIds,
	}
	s.users.Store(table)

	s.legacyMu.Lock()
	defer s.legacyMu.Unlock()
	s.alterIdUpdateTime = make(map[U]int64)
	s.generateLegacyKeysLocked(userAlterIds)
	if s.started && !s.closed {
		s.syncLegacyTickerLocked(len(userAlterIds) > 0)
	}
	return nil
}

func (s *Service[U]) Start() error {
	s.legacyMu.Lock()
	defer s.legacyMu.Unlock()
	s.started = true
	table := s.users.Load()
	hasLegacy := table != nil && len(table.alterIds) > 0
	s.syncLegacyTickerLocked(hasLegacy)
	return nil
}

func (s *Service[U]) Close() error {
	s.legacyMu.Lock()
	defer s.legacyMu.Unlock()
	s.closed = true
	s.syncLegacyTickerLocked(false)
	return nil
}

func (s *Service[U]) syncLegacyTickerLocked(needTicker bool) {
	const updateInterval = 10 * time.Second
	if needTicker {
		if s.alterIdUpdateTask == nil {
			ticker := time.NewTicker(updateInterval)
			done := make(chan struct{})
			s.alterIdUpdateTask = ticker
			s.alterIdUpdateDone = done
			go s.loopGenerateLegacyKeys(ticker, done)
		}
	} else if s.alterIdUpdateTask != nil {
		s.alterIdUpdateTask.Stop()
		close(s.alterIdUpdateDone)
		s.alterIdUpdateTask = nil
		s.alterIdUpdateDone = nil
	}
}

func (s *Service[U]) loopGenerateLegacyKeys(ticker *time.Ticker, done <-chan struct{}) {
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		table := s.users.Load()
		if table == nil {
			continue
		}
		s.legacyMu.Lock()
		if s.closed {
			s.legacyMu.Unlock()
			return
		}
		s.generateLegacyKeysLocked(table.alterIds)
		s.legacyMu.Unlock()
	}
}

func (s *Service[U]) generateLegacyKeysLocked(alterIdsMap map[U][][16]byte) {
	if len(alterIdsMap) == 0 {
		empty := make(map[[16]byte]legacyUserEntry[U])
		s.legacyUsers.Store(&empty)
		return
	}
	nowSec := s.time().Unix()
	endSec := nowSec + vmess.CacheDurationSeconds
	var hashValue [16]byte

	userAlterIdMap := make(map[[16]byte]legacyUserEntry[U])
	userAlterIdUpdateTime := make(map[U]int64, len(alterIdsMap))

	for user, alterIds := range alterIdsMap {
		beginSec := s.alterIdUpdateTime[user]
		if beginSec < nowSec-vmess.CacheDurationSeconds {
			beginSec = nowSec - vmess.CacheDurationSeconds
		}
		for i, alterId := range alterIds {
			idHash := hmac.New(md5.New, alterId[:])
			for ts := beginSec; ts <= endSec; ts++ {
				common.Must(binary.Write(idHash, binary.BigEndian, uint64(ts)))
				idHash.Sum(hashValue[:0])
				idHash.Reset()
				userAlterIdMap[hashValue] = legacyUserEntry[U]{user, ts, i}
			}
		}
		userAlterIdUpdateTime[user] = nowSec
	}
	s.alterIdUpdateTime = userAlterIdUpdateTime
	s.legacyUsers.Store(&userAlterIdMap)
}

func newVmessAesGcm(key []byte) cipher.AEAD {
	block, err := aes.NewCipher(key)
	common.Must(err)
	outCipher, err := cipher.NewGCM(block)
	common.Must(err)
	return outCipher
}

func (s *Service[U]) NewConnection(ctx context.Context, conn net.Conn, metadata M.Metadata) error {
	const headerLenBufferLen = 2 + vmess.CipherOverhead
	const aeadMinHeaderLen = 16 + headerLenBufferLen + 8 + vmess.CipherOverhead + 42

	table := s.users.Load()
	if table == nil {
		return vmess.ErrBadRequest
	}
	minHeaderLen := aeadMinHeaderLen
	if len(table.alterIds) > 0 {
		minHeaderLen = 16 + 38
	}

	requestBuffer := buf.New()
	defer requestBuffer.Release()

	if !s.disableHeaderProtect {
		n, err := requestBuffer.ReadOnceFrom(conn)
		if err != nil {
			return err
		}
		if n < minHeaderLen {
			return vmess.ErrBadHeader
		}
	} else {
		_, err := requestBuffer.ReadAtLeastFrom(conn, minHeaderLen)
		if err != nil {
			return err
		}
	}

	authId := requestBuffer.To(16)
	var decodedId [16]byte
	var user U
	var found bool
	nowUnix := s.time().Unix()
	for currUser, userIdBlock := range table.userIdCipher {
		userIdBlock.Decrypt(decodedId[:], authId)
		timestamp := int64(binary.BigEndian.Uint64(decodedId[:]))
		checksum := binary.BigEndian.Uint32(decodedId[12:])
		if crc32.ChecksumIEEE(decodedId[:12]) != checksum {
			continue
		}
		if math.Abs(math.Abs(float64(timestamp))-float64(nowUnix)) > 120 {
			return vmess.ErrBadTimestamp
		}
		if !s.replayFilter.Check(decodedId[:]) {
			return vmess.ErrReplay
		}
		user = currUser
		found = true
		break
	}

	var legacyProtocol bool
	var legacyTimestamp uint64
	if !found && len(table.alterIds) > 0 {
		copy(decodedId[:], authId)
		if legacyMap := s.legacyUsers.Load(); legacyMap != nil {
			if currUser, loaded := (*legacyMap)[decodedId]; loaded {
				found = true
				legacyProtocol = true
				user = currUser.User
				legacyTimestamp = uint64(currUser.Time)
			}
		}
	}
	if !found {
		return vmess.ErrBadRequest
	}

	ctx = auth.ContextWithUser(ctx, user)
	cmdKey := table.userKey[user]
	var headerReader io.Reader
	var headerBuffer []byte

	var reader io.Reader
	var err error
	if legacyProtocol {
		requestBuffer.Advance(16)
		reader = io.MultiReader(bytes.NewReader(requestBuffer.Bytes()), conn)

		timeHash := md5.New()
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		common.Must(binary.Write(timeHash, binary.BigEndian, legacyTimestamp))
		headerReader = vmess.NewStreamReader(reader, cmdKey[:], timeHash.Sum(nil))
		headerBuffer = make([]byte, 38)
		_, err = io.ReadFull(headerReader, headerBuffer)
		if err != nil {
			return E.Extend(vmess.ErrBadHeader, io.ErrShortBuffer)
		}
	} else {
		if requestBuffer.Len() < aeadMinHeaderLen {
			return vmess.ErrBadHeader
		}

		reader = conn

		const nonceIndex = 16 + headerLenBufferLen
		connectionNonce := requestBuffer.Range(nonceIndex, nonceIndex+8)

		lengthKey := vmess.KDF(cmdKey[:], vmess.KDFSaltConstVMessHeaderPayloadLengthAEADKey, authId, connectionNonce)[:16]
		lengthNonce := vmess.KDF(cmdKey[:], vmess.KDFSaltConstVMessHeaderPayloadLengthAEADIV, authId, connectionNonce)[:12]
		lengthBuffer, err := newVmessAesGcm(lengthKey).Open(requestBuffer.Index(16), lengthNonce, requestBuffer.Range(16, nonceIndex), authId)
		if err != nil {
			return err
		}

		const headerIndex = nonceIndex + 8
		headerLength := int(binary.BigEndian.Uint16(lengthBuffer))
		needRead := headerLength + headerIndex + vmess.CipherOverhead - requestBuffer.Len()
		if needRead > 0 {
			_, err = requestBuffer.ReadFullFrom(conn, needRead)
			if err != nil {
				return err
			}
		}

		headerKey := vmess.KDF(cmdKey[:], vmess.KDFSaltConstVMessHeaderPayloadAEADKey, authId, connectionNonce)[:16]
		headerNonce := vmess.KDF(cmdKey[:], vmess.KDFSaltConstVMessHeaderPayloadAEADIV, authId, connectionNonce)[:12]
		headerBuffer, err = newVmessAesGcm(headerKey).Open(requestBuffer.Index(headerIndex), headerNonce, requestBuffer.Range(headerIndex, headerIndex+headerLength+vmess.CipherOverhead), authId)
		if err != nil {
			return err
		}
		if len(headerBuffer) <= 38 {
			return E.Extend(vmess.ErrBadHeader, io.ErrShortBuffer)
		}
		requestBuffer.Advance(headerIndex + headerLength + vmess.CipherOverhead)
		headerReader = bytes.NewReader(headerBuffer[38:])
	}

	version := headerBuffer[0]
	if version != vmess.Version {
		return E.Extend(vmess.ErrBadVersion, version)
	}

	requestBodyKey := make([]byte, 16)
	requestBodyNonce := make([]byte, 16)

	copy(requestBodyKey, headerBuffer[17:33])
	copy(requestBodyNonce, headerBuffer[1:17])

	responseHeader := headerBuffer[33]
	option := headerBuffer[34]
	paddingLen := int(headerBuffer[35] >> 4)
	security := headerBuffer[35] & 0x0F
	command := headerBuffer[37]
	switch command {
	case vmess.CommandTCP, vmess.CommandUDP, vmess.CommandMux:
	default:
		return E.New("unknown command: ", command)
	}
	if command == vmess.CommandUDP && option == 0 {
		return E.New("bad packet connection")
	}
	if command != vmess.CommandMux {
		metadata.Destination, err = vmess.AddressSerializer.ReadAddrPort(headerReader)
		if err != nil {
			return err
		}
	}
	if paddingLen > 0 {
		_, err = io.CopyN(io.Discard, headerReader, int64(paddingLen))
		if err != nil {
			return E.Extend(vmess.ErrBadHeader, "bad padding")
		}
	}
	err = rw.SkipN(headerReader, 4)
	if err != nil {
		return err
	}

	// Clear handshake read deadline synchronously on the current goroutine before
	// entering TCP, UDP, or CommandMux (Mux.Cool / XUDP) recvLoop.
	_ = conn.SetReadDeadline(time.Time{})

	if !legacyProtocol && requestBuffer.Len() > 0 {
		reader = bufio.NewCachedReader(reader, requestBuffer.ToOwned())
	}
	reader = vmess.CreateReader(reader, nil, requestBodyKey, requestBodyNonce, requestBodyKey, requestBodyNonce, security, option)
	if option&vmess.RequestOptionChunkStream != 0 && command == vmess.CommandTCP || command == vmess.CommandMux {
		reader = bufio.NewChunkReader(reader, vmess.ReadChunkSize)
	}
	rawConn := rawServerConn{
		Conn:           conn,
		legacyProtocol: legacyProtocol,
		requestKey:     requestBodyKey,
		requestNonce:   requestBodyNonce,
		responseHeader: responseHeader,
		security:       security,
		option:         option,
		reader:         bufio.NewExtendedReader(reader),
	}

	switch command {
	case vmess.CommandTCP:
		return s.handler.NewConnection(ctx, &serverConn{rawConn}, metadata)
	case vmess.CommandUDP:
		return s.handler.NewPacketConnection(ctx, &serverPacketConn{rawConn, metadata.Destination}, metadata)
	case vmess.CommandMux:
		return vmess.HandleMuxConnection(ctx, &serverConn{rawConn}, metadata, s.handler)
	default:
		return E.New("unknown command: ", command)
	}
}

type rawServerConn struct {
	net.Conn
	legacyProtocol bool
	requestKey     []byte
	requestNonce   []byte
	responseHeader byte
	security       byte
	option         byte
	reader         N.ExtendedReader
	writer         N.ExtendedWriter
}

func (c *rawServerConn) writeResponse() error {
	if c.legacyProtocol {
		responseKey := md5.Sum(c.requestKey)
		responseNonce := md5.Sum(c.requestNonce)
		headerWriter := vmess.NewStreamWriter(c.Conn, responseKey[:], responseNonce[:])
		_, err := headerWriter.Write([]byte{c.responseHeader, c.option, 0, 0})
		if err != nil {
			return E.Cause(err, "write response")
		}
		c.writer = bufio.NewExtendedWriter(vmess.CreateWriter(c.Conn, headerWriter, c.requestKey, c.requestNonce, responseKey[:], responseNonce[:], c.security, c.option))
	} else {
		responseBuffer := buf.NewSize(2 + vmess.CipherOverhead + 4 + vmess.CipherOverhead)
		defer responseBuffer.Release()

		_responseKey := sha256.Sum256(c.requestKey[:])
		responseKey := _responseKey[:16]
		_responseNonce := sha256.Sum256(c.requestNonce[:])
		responseNonce := _responseNonce[:16]

		headerLenKey := vmess.KDF(responseKey, vmess.KDFSaltConstAEADRespHeaderLenKey)[:16]
		headerLenNonce := vmess.KDF(responseNonce, vmess.KDFSaltConstAEADRespHeaderLenIV)[:12]
		headerLenCipher := newVmessAesGcm(headerLenKey)
		binary.BigEndian.PutUint16(responseBuffer.Extend(2), 4)
		headerLenCipher.Seal(responseBuffer.Index(0), headerLenNonce, responseBuffer.Bytes(), nil)
		responseBuffer.Extend(vmess.CipherOverhead)

		headerKey := vmess.KDF(responseKey, vmess.KDFSaltConstAEADRespHeaderPayloadKey)[:16]
		headerNonce := vmess.KDF(responseNonce, vmess.KDFSaltConstAEADRespHeaderPayloadIV)[:12]
		headerCipher := newVmessAesGcm(headerKey)
		common.Must(
			responseBuffer.WriteByte(c.responseHeader),
			responseBuffer.WriteByte(c.option),
			responseBuffer.WriteZeroN(2),
		)
		const headerIndex = 2 + vmess.CipherOverhead
		headerCipher.Seal(responseBuffer.Index(headerIndex), headerNonce, responseBuffer.From(headerIndex), nil)
		responseBuffer.Extend(vmess.CipherOverhead)

		_, err := c.Conn.Write(responseBuffer.Bytes())
		if err != nil {
			return err
		}

		c.writer = bufio.NewExtendedWriter(vmess.CreateWriter(c.Conn, nil, c.requestKey, c.requestNonce, responseKey, responseNonce, c.security, c.option))
	}
	return nil
}

func (c *rawServerConn) Close() error {
	return common.Close(
		c.Conn,
		c.reader,
	)
}

func (c *rawServerConn) FrontHeadroom() int {
	return vmess.MaxFrontHeadroom
}

func (c *rawServerConn) RearHeadroom() int {
	return vmess.MaxRearHeadroom
}

func (c *rawServerConn) NeedHandshake() bool {
	return c.writer == nil
}

func (c *rawServerConn) NeedAdditionalReadDeadline() bool {
	return true
}

func (c *rawServerConn) Upstream() any {
	return c.Conn
}

type serverConn struct {
	rawServerConn
}

func (c *serverConn) Read(b []byte) (n int, err error) {
	return c.reader.Read(b)
}

func (c *serverConn) Write(b []byte) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(b)
}

func (c *serverConn) ReadBuffer(buffer *buf.Buffer) error {
	return c.reader.ReadBuffer(buffer)
}

func (c *serverConn) WriteBuffer(buffer *buf.Buffer) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			buffer.Release()
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}

func (c *serverConn) WriteTo(w io.Writer) (n int64, err error) {
	return bufio.Copy(w, c.reader)
}

func (c *serverConn) ReadFrom(r io.Reader) (n int64, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return bufio.Copy(c.writer, r)
}

var _ vmess.PacketConn = (*serverPacketConn)(nil)

type serverPacketConn struct {
	rawServerConn
	destination M.Socksaddr
}

func (c *serverPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = c.reader.Read(p)
	if err != nil {
		return
	}
	addr = c.destination.UDPAddr()
	return
}

func (c *serverPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	if c.writer == nil {
		err = c.writeResponse()
		if err != nil {
			return
		}
	}
	return c.writer.Write(p)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (destination M.Socksaddr, err error) {
	err = c.reader.ReadBuffer(buffer)
	if err != nil {
		return
	}
	destination = c.destination
	return
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	if c.writer == nil {
		err := c.writeResponse()
		if err != nil {
			return err
		}
	}
	return c.writer.WriteBuffer(buffer)
}
