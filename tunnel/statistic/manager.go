package statistic

import (
	"os"
	"sync"
	"time"

	"github.com/metacubex/mihomo/common/atomic"
	"github.com/metacubex/mihomo/common/xsync"
	"github.com/metacubex/mihomo/component/memory"
	C "github.com/metacubex/mihomo/constant"
	"golang.org/x/time/rate"
)

var DefaultManager *Manager

func init() {
	DefaultManager = &Manager{
		uploadTemp:    atomic.NewInt64(0),
		downloadTemp:  atomic.NewInt64(0),
		uploadBlip:    atomic.NewInt64(0),
		downloadBlip:  atomic.NewInt64(0),
		uploadTotal:   atomic.NewInt64(0),
		downloadTotal: atomic.NewInt64(0),
		pid:           int32(os.Getpid()),
	}

	go DefaultManager.handle()
}

type Manager struct {
	connections   xsync.Map[string, Tracker]
	uploadTemp    atomic.Int64
	downloadTemp  atomic.Int64
	uploadBlip    atomic.Int64
	downloadBlip  atomic.Int64
	uploadTotal   atomic.Int64
	downloadTotal atomic.Int64
	pid           int32
	memory        uint64

	userMu            sync.Mutex
	userDevices       map[string]map[string]int
	userReservations  map[string]map[string]int
	globalUserDevices map[string]map[string]struct{}
	userTraffic       map[string][2]int64
	userLimiter       func(string) *rate.Limiter
	deviceLimit       func(string) (int, bool)
	deviceLimitEvent  func(string)
}

// UserSnapshot is the per-authenticated-user view of active connections and
// cumulative bytes. The core keeps this close to the connection tracker so
// consumers do not need to infer users from the global connection API.
type UserSnapshot struct {
	Upload      int64
	Download    int64
	AliveIPs    map[string]struct{}
	Connections int
}

func (m *Manager) initUserState() {
	if m.userDevices == nil {
		m.userDevices = make(map[string]map[string]int)
	}
	if m.userReservations == nil {
		m.userReservations = make(map[string]map[string]int)
	}
	if m.globalUserDevices == nil {
		m.globalUserDevices = make(map[string]map[string]struct{})
	}
	if m.userTraffic == nil {
		m.userTraffic = make(map[string][2]int64)
	}
}

func (m *Manager) Join(c Tracker) {
	m.connections.Store(c.ID(), c)
	if info := c.Info(); info != nil && info.Metadata != nil && info.Metadata.InUser != "" {
		m.userMu.Lock()
		m.initUserState()
		user := m.UserKey(info.Metadata)
		ip := info.Metadata.SrcIP.String()
		if pending := m.userReservations[user]; pending != nil && pending[ip] > 0 {
			pending[ip]--
			if pending[ip] == 0 {
				delete(pending, ip)
			}
			if len(pending) == 0 {
				delete(m.userReservations, user)
			}
		}
		if m.userDevices[user] == nil {
			m.userDevices[user] = make(map[string]int)
		}
		m.userDevices[user][ip]++
		m.userMu.Unlock()
	}
}

func (m *Manager) Leave(c Tracker) {
	m.connections.Delete(c.ID())
	if info := c.Info(); info != nil && info.Metadata != nil && info.Metadata.InUser != "" {
		m.userMu.Lock()
		user := m.UserKey(info.Metadata)
		if devices := m.userDevices[user]; devices != nil {
			ip := info.Metadata.SrcIP.String()
			devices[ip]--
			if devices[ip] <= 0 {
				delete(devices, ip)
			}
			if len(devices) == 0 {
				delete(m.userDevices, user)
			}
		}
		m.userMu.Unlock()
	}
}

func (m *Manager) Get(id string) (c Tracker) {
	if value, ok := m.connections.Load(id); ok {
		c = value
	}
	return
}

func (m *Manager) Range(f func(c Tracker) bool) {
	m.connections.Range(func(key string, value Tracker) bool {
		return f(value)
	})
}

// SetUserLimiter installs the common per-user bandwidth resolver. Individual
// trackers obtain a limiter once, after protocol authentication has populated
// Metadata.InUser.
func (m *Manager) SetUserLimiter(fn func(string) *rate.Limiter) {
	m.userMu.Lock()
	m.userLimiter = fn
	m.userMu.Unlock()
}

func (m *Manager) limiterForUser(user string) *rate.Limiter {
	m.userMu.Lock()
	fn := m.userLimiter
	m.userMu.Unlock()
	if fn == nil || user == "" {
		return nil
	}
	return fn(user)
}

// UserKey namespaces an authenticated identity by inbound listener.
func (m *Manager) UserKey(metadata *C.Metadata) string {
	if metadata == nil || metadata.InUser == "" {
		return ""
	}
	if metadata.InName == "" {
		return metadata.InUser
	}
	return metadata.InName + "\x00" + metadata.InUser
}

// SetDeviceLimit installs the common per-user device limit resolver.
func (m *Manager) SetDeviceLimit(fn func(string) (int, bool)) {
	m.userMu.Lock()
	m.deviceLimit = fn
	m.userMu.Unlock()
}

func (m *Manager) SetDeviceLimitEvent(fn func(string)) {
	m.userMu.Lock()
	m.deviceLimitEvent = fn
	m.userMu.Unlock()
}

// UpdateGlobalDevices supplies the panel-wide device view. The map contains
// the same stable user key used in Metadata.InUser and source IPs already
// observed on other nodes.
func (m *Manager) UpdateGlobalDevices(users map[string][]string) {
	m.userMu.Lock()
	defer m.userMu.Unlock()
	m.initUserState()
	m.globalUserDevices = make(map[string]map[string]struct{}, len(users))
	for user, ips := range users {
		set := make(map[string]struct{}, len(ips))
		for _, ip := range ips {
			if ip != "" {
				set[ip] = struct{}{}
			}
		}
		if len(set) > 0 {
			m.globalUserDevices[user] = set
		}
	}
}

func (m *Manager) ClearGlobalDevices() {
	m.userMu.Lock()
	m.globalUserDevices = make(map[string]map[string]struct{})
	m.userMu.Unlock()
}

// AdmitUser reserves a user/source pair before dialing the outbound. The
// reservation closes the race between simultaneous new connections; Join
// consumes it when the tracker is created, while callers must release it on a
// failed dial.
func (m *Manager) AdmitUser(user, sourceIP string) bool {
	if user == "" {
		return true
	}
	m.userMu.Lock()
	limitFn := m.deviceLimit
	global := m.globalUserDevices[user]
	active := m.userDevices[user]
	reserved := m.userReservations[user]
	m.userMu.Unlock()

	if limitFn == nil {
		return true
	}
	limit, hasLimit := limitFn(user)
	if !hasLimit || limit <= 0 {
		return true
	}

	m.userMu.Lock()
	defer m.userMu.Unlock()
	m.initUserState()
	active = m.userDevices[user]
	reserved = m.userReservations[user]
	known := make(map[string]struct{}, len(global)+len(active)+len(reserved))
	for ip := range global {
		known[ip] = struct{}{}
	}
	for ip := range active {
		known[ip] = struct{}{}
	}
	for ip := range reserved {
		known[ip] = struct{}{}
	}
	if _, exists := known[sourceIP]; !exists && len(known) >= limit {
		if m.deviceLimitEvent != nil {
			go m.deviceLimitEvent(user)
		}
		return false
	}
	if m.userReservations[user] == nil {
		m.userReservations[user] = make(map[string]int)
	}
	m.userReservations[user][sourceIP]++
	return true
}

func (m *Manager) ReleaseUserAdmission(user, sourceIP string) {
	if user == "" {
		return
	}
	m.userMu.Lock()
	defer m.userMu.Unlock()
	if pending := m.userReservations[user]; pending != nil {
		pending[sourceIP]--
		if pending[sourceIP] <= 0 {
			delete(pending, sourceIP)
		}
		if len(pending) == 0 {
			delete(m.userReservations, user)
		}
	}
}

// SnapshotUsers returns a stable per-user view for panel reporting.
func (m *Manager) SnapshotUsers() map[string]UserSnapshot {
	result := make(map[string]UserSnapshot)
	m.userMu.Lock()
	m.initUserState()
	for user, traffic := range m.userTraffic {
		result[user] = UserSnapshot{Upload: traffic[0], Download: traffic[1]}
	}
	m.userMu.Unlock()
	m.Range(func(c Tracker) bool {
		info := c.Info()
		if info == nil || info.Metadata == nil || info.Metadata.InUser == "" {
			return true
		}
		user := m.UserKey(info.Metadata)
		snapshot := result[user]
		snapshot.Connections++
		if snapshot.AliveIPs == nil {
			snapshot.AliveIPs = make(map[string]struct{})
		}
		ip := info.Metadata.SrcIP.String()
		if ip != "" {
			snapshot.AliveIPs[ip] = struct{}{}
		}
		result[user] = snapshot
		return true
	})
	return result
}

func (m *Manager) pushUserUploaded(user string, size int64) {
	if user == "" || size <= 0 {
		return
	}
	m.userMu.Lock()
	m.initUserState()
	traffic := m.userTraffic[user]
	traffic[0] += size
	m.userTraffic[user] = traffic
	m.userMu.Unlock()
}

func (m *Manager) pushUserDownloaded(user string, size int64) {
	if user == "" || size <= 0 {
		return
	}
	m.userMu.Lock()
	m.initUserState()
	traffic := m.userTraffic[user]
	traffic[1] += size
	m.userTraffic[user] = traffic
	m.userMu.Unlock()
}

// ResetUserTraffic starts a fresh accounting epoch. Consumers should collect
// one final snapshot before calling it during a runtime replacement.
func (m *Manager) ResetUserTraffic() {
	m.userMu.Lock()
	m.userTraffic = make(map[string][2]int64)
	m.userMu.Unlock()
}

// CloseUser closes only authenticated connections belonging to user.
func (m *Manager) CloseUser(user string) int {
	if user == "" {
		return 0
	}
	count := 0
	m.Range(func(c Tracker) bool {
		info := c.Info()
		if info != nil && info.Metadata != nil && m.UserKey(info.Metadata) == user {
			if err := c.Close(); err == nil {
				count++
			}
		}
		return true
	})
	return count
}

// CloseAll terminates every tracked connection and clears pending admission
// state. It is used when an embedded Mihomo runtime is stopped or replaced.
func (m *Manager) CloseAll() int {
	count := 0
	m.Range(func(c Tracker) bool {
		if err := c.Close(); err == nil {
			count++
		}
		return true
	})
	m.userMu.Lock()
	m.userDevices = make(map[string]map[string]int)
	m.userReservations = make(map[string]map[string]int)
	m.userMu.Unlock()
	return count
}

func (m *Manager) PushUploaded(size int64) {
	m.uploadTemp.Add(size)
	m.uploadTotal.Add(size)
}

func (m *Manager) PushDownloaded(size int64) {
	m.downloadTemp.Add(size)
	m.downloadTotal.Add(size)
}

func (m *Manager) Now() (up int64, down int64) {
	return m.uploadBlip.Load(), m.downloadBlip.Load()
}

func (m *Manager) Total() (up, down int64) {
	return m.uploadTotal.Load(), m.downloadTotal.Load()
}

func (m *Manager) Memory() uint64 {
	m.updateMemory()
	return m.memory
}

func (m *Manager) Snapshot() *Snapshot {
	var connections []*TrackerInfo
	m.Range(func(c Tracker) bool {
		connections = append(connections, c.Info())
		return true
	})
	return &Snapshot{
		UploadTotal:   m.uploadTotal.Load(),
		DownloadTotal: m.downloadTotal.Load(),
		Connections:   connections,
		Memory:        m.memory,
	}
}

func (m *Manager) updateMemory() {
	stat, err := memory.GetMemoryInfo(m.pid)
	if err != nil {
		return
	}
	m.memory = stat.RSS
}

func (m *Manager) ResetStatistic() {
	m.uploadTemp.Store(0)
	m.uploadBlip.Store(0)
	m.uploadTotal.Store(0)
	m.downloadTemp.Store(0)
	m.downloadBlip.Store(0)
	m.downloadTotal.Store(0)
}

func (m *Manager) handle() {
	ticker := time.NewTicker(time.Second)

	for range ticker.C {
		m.uploadBlip.Store(m.uploadTemp.Swap(0))
		m.downloadBlip.Store(m.downloadTemp.Swap(0))
	}
}

type Snapshot struct {
	DownloadTotal int64          `json:"downloadTotal"`
	UploadTotal   int64          `json:"uploadTotal"`
	Connections   []*TrackerInfo `json:"connections"`
	Memory        uint64         `json:"memory"`
}
