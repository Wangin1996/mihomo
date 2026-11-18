package loopback

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"

	"github.com/metacubex/mihomo/common/callback"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/iface"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
)

var disableLoopBackDetector, _ = strconv.ParseBool(os.Getenv("DISABLE_LOOPBACK_DETECTOR"))

func init() {
	if features.CMFA {
		disableLoopBackDetector = true
	}
}

var ErrReject = errors.New("reject loopback connection")

var (
	globalConnMap       xsync.Map[netip.AddrPort, struct{}]
	globalPacketConnMap xsync.Map[uint16, struct{}]
	sharedDetector      = &Detector{}
)

type Detector struct{}

func NewDetector() *Detector {
	if disableLoopBackDetector {
		return nil
	}
	return sharedDetector
}

func (l *Detector) NewConn(conn C.Conn) C.Conn {
	if l == nil {
		return conn
	}
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	globalConnMap.Store(connAddr, struct{}{})
	return callback.NewCloseCallbackConn(conn, func() {
		globalConnMap.Delete(connAddr)
	})
}

func (l *Detector) NewPacketConn(conn C.PacketConn) C.PacketConn {
	if l == nil {
		return conn
	}
	metadata := C.Metadata{}
	if metadata.SetRemoteAddr(conn.LocalAddr()) != nil {
		return conn
	}
	connAddr := metadata.AddrPort()
	if !connAddr.IsValid() {
		return conn
	}
	port := connAddr.Port()
	globalPacketConnMap.Store(port, struct{}{})
	return callback.NewCloseCallbackPacketConn(conn, func() {
		globalPacketConnMap.Delete(port)
	})
}

func (l *Detector) CheckConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() {
		return nil
	}
	if _, ok := globalConnMap.Load(connAddr); ok {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}

func (l *Detector) CheckPacketConn(metadata *C.Metadata) error {
	if l == nil {
		return nil
	}
	connAddr := metadata.SourceAddrPort()
	if !connAddr.IsValid() {
		return nil
	}

	isLocalIp, err := iface.IsLocalIp(connAddr.Addr())
	if err != nil {
		return err
	}
	if !isLocalIp && !connAddr.Addr().IsLoopback() {
		return nil
	}

	if _, ok := globalPacketConnMap.Load(connAddr.Port()); ok {
		return fmt.Errorf("%w to: %s", ErrReject, metadata.RemoteAddress())
	}
	return nil
}
