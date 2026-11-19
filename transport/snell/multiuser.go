package snell

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/metacubex/mihomo/transport/shadowsocks/shadowaead"
)

const (
	v1SaltSize         = 16
	v1HeaderCipherSize = 2 + 16
)

// UserMatcher holds precomputed per-user cryptographic state and v6 shaping
// profile for authenticated first-packet trial-decryption and stream creation.
// A UserMatcher is immutable after construction and safe for concurrent use.
type UserMatcher struct {
	version        int
	v6Mode         V6Mode
	psk            []byte
	cipher         shadowaead.Cipher // v1-v3
	profile        *v6Profile        // v6 default
	firstPrefixLen int               // v6 default: recordPrefixLen(0)
	firstPrefix    []byte            // v6 default: deterministic prefix for seq 0
	firstHeaderLen int               // minimum peeked bytes needed to authenticate first header
}

// NewUserMatcher precomputes the cipher or v6 profile for a single Snell user.
func NewUserMatcher(psk []byte, version int, v6Mode V6Mode) (*UserMatcher, error) {
	if len(psk) == 0 {
		return nil, fmt.Errorf("snell psk must not be empty")
	}
	if version < Version1 || version > Version6 {
		return nil, fmt.Errorf("snell version %d is not supported", version)
	}
	pskCopy := append([]byte(nil), psk...)
	m := &UserMatcher{
		version: version,
		v6Mode:  v6Mode,
		psk:     pskCopy,
	}

	switch {
	case version == Version6:
		if err := ValidateV6PSK(pskCopy); err != nil {
			return nil, err
		}
		switch v6Mode {
		case V6ModeDefault:
			profile := newV6Profile(pskCopy)
			firstPrefixLen := profile.recordPrefixLen(0)
			firstPrefix := make([]byte, firstPrefixLen)
			profile.fillPadding(0, firstPrefix)
			m.profile = profile
			m.firstPrefixLen = firstPrefixLen
			m.firstPrefix = firstPrefix
			m.firstHeaderLen = profile.saltBlockLen + firstPrefixLen + v6HeaderCipherSize
		case V6ModeUnshaped:
			m.firstHeaderLen = v6SaltSize + v6HeaderCipherSize
		case V6ModeUnsafeRaw:
			m.firstHeaderLen = 0
		default:
			return nil, fmt.Errorf("snell v6 unknown mode: %d", int(v6Mode))
		}
	case version >= Version4:
		m.firstHeaderLen = v4SaltSize + v4HeaderCipherSize
	case version == Version1:
		m.cipher = NewChacha20Poly1305(pskCopy)
		m.firstHeaderLen = v1SaltSize + v1HeaderCipherSize
	default: // Version2, Version3
		m.cipher = NewAES128GCM(pskCopy)
		m.firstHeaderLen = v1SaltSize + v1HeaderCipherSize
	}

	return m, nil
}

// FirstHeaderLen returns the number of initial bytes required to trial-decrypt
// this user's first record/chunk header. Returns 0 for V6ModeUnsafeRaw.
func (m *UserMatcher) FirstHeaderLen() int {
	return m.firstHeaderLen
}

// MatchPrefixHint reports whether peeked matches this user's deterministic v6
// default-mode first-record prefix (O(1) fast-path hint before KDF/AEAD).
func (m *UserMatcher) MatchPrefixHint(peeked []byte) bool {
	if m.version != Version6 || m.v6Mode != V6ModeDefault || m.profile == nil {
		return false
	}
	if len(peeked) < m.firstHeaderLen {
		return false
	}
	start := m.profile.saltBlockLen
	return bytes.Equal(peeked[start:start+m.firstPrefixLen], m.firstPrefix)
}

// MatchFirstHeader performs authenticated trial-decryption of the first
// record/chunk header without modifying peeked.
func (m *UserMatcher) MatchFirstHeader(peeked []byte) bool {
	if m.firstHeaderLen == 0 || len(peeked) < m.firstHeaderLen {
		return false
	}

	switch {
	case m.version == Version6:
		switch m.v6Mode {
		case V6ModeDefault:
			saltBlockLen := m.profile.saltBlockLen
			salt := m.profile.extractSalt(peeked[:saltBlockLen])
			aead, err := v6AEAD(m.psk, salt[:])
			if err != nil {
				return false
			}
			prefix := peeked[saltBlockLen : saltBlockLen+m.firstPrefixLen]
			headerCipher := peeked[saltBlockLen+m.firstPrefixLen : m.firstHeaderLen]
			var nonce [v6NonceSize]byte
			var plain [v6HeaderPlainSize]byte
			header, err := aead.Open(plain[:0], nonce[:], headerCipher, prefix)
			if err != nil {
				return false
			}
			_, _, err = v6ParseHeader(header, false)
			return err == nil
		case V6ModeUnshaped:
			salt := peeked[:v6SaltSize]
			headerCipher := peeked[v6SaltSize : v6SaltSize+v6HeaderCipherSize]
			aead, err := v6AEAD(m.psk, salt)
			if err != nil {
				return false
			}
			var nonce [v6NonceSize]byte
			var plain [v6HeaderPlainSize]byte
			header, err := aead.Open(plain[:0], nonce[:], headerCipher, nil)
			if err != nil {
				return false
			}
			paddingLength, _, err := v6ParseHeader(header, true)
			return err == nil && paddingLength == 0
		default:
			return false
		}

	case m.version >= Version4:
		salt := peeked[:v4SaltSize]
		headerCipher := peeked[v4SaltSize : v4SaltSize+v4HeaderCipherSize]
		aead, err := v4AEAD(m.psk, salt)
		if err != nil {
			return false
		}
		var nonce [v4NonceSize]byte
		var plain [v4HeaderPlainSize]byte
		header, err := aead.Open(plain[:0], nonce[:], headerCipher, nil)
		if err != nil || len(header) != v4HeaderPlainSize || header[0] != 4 {
			return false
		}
		paddingLength := int(binary.BigEndian.Uint16(header[3:5]))
		payloadLength := int(binary.BigEndian.Uint16(header[5:7]))
		if payloadLength == 0 && paddingLength != 0 {
			return false
		}
		return payloadLength <= maxLength && paddingLength <= maxLength

	default: // Version1..Version3
		salt := peeked[:v1SaltSize]
		headerCipher := peeked[v1SaltSize : v1SaltSize+v1HeaderCipherSize]
		aead, err := m.cipher.Decrypter(salt)
		if err != nil {
			return false
		}
		var nonce [12]byte
		var plain [2]byte
		_, err = aead.Open(plain[:0], nonce[:], headerCipher, nil)
		return err == nil
	}
}

// ServerStreamConn wraps conn as a server-side Snell stream reusing this
// matcher's precomputed cipher (v1-v3) or v6 profile (v6 default).
func (m *UserMatcher) ServerStreamConn(conn net.Conn) *Snell {
	var stream *Snell
	switch {
	case m.version >= Version6:
		stream = &Snell{
			Conn: &v6Conn{
				Conn:    conn,
				psk:     m.psk,
				mode:    m.v6Mode,
				profile: m.profile,
			},
		}
	case m.version >= Version4:
		stream = &Snell{Conn: newV4Conn(conn, m.psk)}
	default:
		stream = &Snell{Conn: shadowaead.NewConn(conn, m.cipher)}
	}
	stream.reply = true
	return stream
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

// NewPrefixConn wraps conn so that prefix is served before reading from conn.
// Once prefix is drained, Read passes directly through to conn.
func NewPrefixConn(conn net.Conn, prefix []byte) net.Conn {
	if len(prefix) == 0 {
		return conn
	}
	return &prefixConn{
		Conn:   conn,
		prefix: prefix,
	}
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		if len(c.prefix) == 0 {
			c.prefix = nil
		}
		return n, nil
	}
	return c.Conn.Read(p)
}
