package statistic

import (
	"io"
	"net"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/buf"
	N "github.com/metacubex/mihomo/common/net"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/xboard"
	C "github.com/metacubex/mihomo/constant"

	"github.com/gofrs/uuid/v5"
)

type Tracker interface {
	ID() string
	Close() error
	Info() *TrackerInfo
	C.Connection
}

type TrackerInfo struct {
	UUID          uuid.UUID    `json:"id"`
	Metadata      *C.Metadata  `json:"metadata"`
	UploadTotal   atomic.Int64 `json:"upload"`
	DownloadTotal atomic.Int64 `json:"download"`
	Start         time.Time    `json:"start"`
	Chain         C.Chain      `json:"chains"`
	ProviderChain C.Chain      `json:"providerChains"`
	Rule          string       `json:"rule"`
	RulePayload   string       `json:"rulePayload"`
}

type tcpTracker struct {
	C.Conn `json:"-"`
	*TrackerInfo
	manager *Manager
	xboard  *xboard.Connection

	pushToManager bool `json:"-"`
}

func (tt *tcpTracker) ID() string {
	return tt.UUID.String()
}

func (tt *tcpTracker) Info() *TrackerInfo {
	return tt.TrackerInfo
}

func (tt *tcpTracker) Read(b []byte) (int, error) {
	if limit := tt.xboard.ReadLimit(); limit > 0 && len(b) > limit {
		b = b[:limit]
	}
	n, err := tt.Conn.Read(b)
	download := int64(n)
	if tt.pushToManager {
		tt.manager.PushDownloaded(download)
	}
	tt.DownloadTotal.Add(download)
	tt.xboard.AddDownload(download)
	if limitErr := tt.xboard.Wait(n); limitErr != nil {
		return n, limitErr
	}
	return n, err
}

func (tt *tcpTracker) ReadBuffer(buffer *buf.Buffer) (err error) {
	err = tt.Conn.ReadBuffer(buffer)
	download := int64(buffer.Len())
	if tt.pushToManager {
		tt.manager.PushDownloaded(download)
	}
	tt.DownloadTotal.Add(download)
	tt.xboard.AddDownload(download)
	if err == nil {
		err = tt.xboard.Wait(buffer.Len())
	}
	return
}

func (tt *tcpTracker) UnwrapReader() (io.Reader, []N.CountFunc) {
	if tt.xboard != nil {
		return trackedReader{tracker: tt}, nil
	}
	return tt.Conn, []N.CountFunc{func(download int64) {
		if tt.pushToManager {
			tt.manager.PushDownloaded(download)
		}
		tt.DownloadTotal.Add(download)
	}}
}

func (tt *tcpTracker) Write(b []byte) (int, error) {
	if err := tt.xboard.Wait(len(b)); err != nil {
		return 0, err
	}
	n, err := tt.Conn.Write(b)
	upload := int64(n)
	if tt.pushToManager {
		tt.manager.PushUploaded(upload)
	}
	tt.UploadTotal.Add(upload)
	tt.xboard.AddUpload(upload)
	return n, err
}

func (tt *tcpTracker) WriteBuffer(buffer *buf.Buffer) (err error) {
	upload := int64(buffer.Len())
	if err = tt.xboard.Wait(buffer.Len()); err != nil {
		return err
	}
	err = tt.Conn.WriteBuffer(buffer)
	if tt.pushToManager {
		tt.manager.PushUploaded(upload)
	}
	tt.UploadTotal.Add(upload)
	tt.xboard.AddUpload(upload)
	return
}

func (tt *tcpTracker) UnwrapWriter() (io.Writer, []N.CountFunc) {
	if tt.xboard != nil {
		return trackedWriter{tracker: tt}, nil
	}
	return tt.Conn, []N.CountFunc{func(upload int64) {
		if tt.pushToManager {
			tt.manager.PushUploaded(upload)
		}
		tt.UploadTotal.Add(upload)
	}}
}

func (tt *tcpTracker) Close() error {
	tt.xboard.Close()
	tt.manager.Leave(tt)
	return tt.Conn.Close()
}

func (tt *tcpTracker) Upstream() any {
	return tt.Conn
}

func NewTCPTracker(conn C.Conn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *tcpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	t := &tcpTracker{
		Conn:    conn,
		manager: manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
	}
	var accepted bool
	t.xboard, accepted = xboard.Open(t.ID(), metadata.InName, metadata.InUser, metadata.SrcIP.String(), t)
	if !accepted {
		_ = conn.Close()
		return t
	}

	if uploadTotal > 0 {
		t.xboard.AddUpload(uploadTotal)
	}
	if downloadTotal > 0 {
		t.xboard.AddDownload(downloadTotal)
	}
	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}

	if rule != nil {
		t.TrackerInfo.Rule = rule.RuleType().String()
		t.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(t)
	return t
}

type trackedReader struct{ tracker *tcpTracker }

func (r trackedReader) Read(buffer []byte) (int, error) { return r.tracker.Read(buffer) }

type trackedWriter struct{ tracker *tcpTracker }

func (w trackedWriter) Write(buffer []byte) (int, error) { return w.tracker.Write(buffer) }

type udpTracker struct {
	C.PacketConn `json:"-"`
	*TrackerInfo
	manager *Manager
	xboard  *xboard.Connection

	pushToManager bool `json:"-"`
}

func (ut *udpTracker) ID() string {
	return ut.UUID.String()
}

func (ut *udpTracker) Info() *TrackerInfo {
	return ut.TrackerInfo
}

func (ut *udpTracker) ReadFrom(b []byte) (int, net.Addr, error) {
	if limit := ut.xboard.ReadLimit(); limit > 0 && len(b) > limit {
		b = b[:limit]
	}
	n, addr, err := ut.PacketConn.ReadFrom(b)
	download := int64(n)
	if ut.pushToManager {
		ut.manager.PushDownloaded(download)
	}
	ut.DownloadTotal.Add(download)
	ut.xboard.AddDownload(download)
	if limitErr := ut.xboard.Wait(n); limitErr != nil {
		return n, addr, limitErr
	}
	return n, addr, err
}

func (ut *udpTracker) WaitReadFrom() (data []byte, put func(), addr net.Addr, err error) {
	data, put, addr, err = ut.PacketConn.WaitReadFrom()
	download := int64(len(data))
	if ut.pushToManager {
		ut.manager.PushDownloaded(download)
	}
	ut.DownloadTotal.Add(download)
	ut.xboard.AddDownload(download)
	if limitErr := ut.xboard.Wait(len(data)); limitErr != nil {
		err = limitErr
	}
	return
}

func (ut *udpTracker) WriteTo(b []byte, addr net.Addr) (int, error) {
	if err := ut.xboard.Wait(len(b)); err != nil {
		return 0, err
	}
	n, err := ut.PacketConn.WriteTo(b, addr)
	upload := int64(n)
	if ut.pushToManager {
		ut.manager.PushUploaded(upload)
	}
	ut.UploadTotal.Add(upload)
	ut.xboard.AddUpload(upload)
	return n, err
}

func (ut *udpTracker) Close() error {
	ut.xboard.Close()
	ut.manager.Leave(ut)
	return ut.PacketConn.Close()
}

func (ut *udpTracker) Upstream() any {
	return ut.PacketConn
}

func NewUDPTracker(conn C.PacketConn, manager *Manager, metadata *C.Metadata, rule C.Rule, uploadTotal int64, downloadTotal int64, pushToManager bool) *udpTracker {
	metadata.RemoteDst = conn.RemoteDestination()

	ut := &udpTracker{
		PacketConn: conn,
		manager:    manager,
		TrackerInfo: &TrackerInfo{
			UUID:          utils.NewUUIDV4(),
			Start:         time.Now(),
			Metadata:      metadata,
			Chain:         conn.Chains(),
			ProviderChain: conn.ProviderChains(),
			Rule:          "",
			UploadTotal:   atomic.NewInt64(uploadTotal),
			DownloadTotal: atomic.NewInt64(downloadTotal),
		},
		pushToManager: pushToManager,
	}
	var accepted bool
	ut.xboard, accepted = xboard.Open(ut.ID(), metadata.InName, metadata.InUser, metadata.SrcIP.String(), ut)
	if !accepted {
		_ = conn.Close()
		return ut
	}

	if uploadTotal > 0 {
		ut.xboard.AddUpload(uploadTotal)
	}
	if downloadTotal > 0 {
		ut.xboard.AddDownload(downloadTotal)
	}
	if pushToManager {
		if uploadTotal > 0 {
			manager.PushUploaded(uploadTotal)
		}
		if downloadTotal > 0 {
			manager.PushDownloaded(downloadTotal)
		}
	}

	if rule != nil {
		ut.TrackerInfo.Rule = rule.RuleType().String()
		ut.TrackerInfo.RulePayload = rule.Payload()
	}

	manager.Join(ut)
	return ut
}
