package xboard

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// User binds an inbound authentication alias to the panel user identity.
type User struct {
	ID   int
	UUID string
}

// Snapshot is the cumulative state for one inbound scope.
type Snapshot struct {
	Traffic     map[int][2]int64
	AliveIPs    map[int]map[string]bool
	Connections int
}

type userStats struct {
	upload   atomic.Int64
	download atomic.Int64

	mu          sync.RWMutex
	ips         map[string]int
	connections int
}

type scopeState struct {
	users       map[string]User
	speedLimit  func(string) *rate.Limiter
	deviceLimit func(string) (int, bool)
	limitEvent  func()

	globalDevices map[int]map[string]bool
	globalAt      time.Time
	stats         map[int]*userStats
}

type connectionRef struct {
	scope    string
	user     User
	alias    string
	sourceIP string
	stats    *userStats
	closer   io.Closer
}

var runtimeState = struct {
	mu          sync.RWMutex
	scopes      map[string]*scopeState
	connections map[string]*connectionRef
}{
	scopes:      make(map[string]*scopeState),
	connections: make(map[string]*connectionRef),
}

// ConfigureScope atomically publishes the users and callbacks for one inbound.
// Connections belonging to removed credentials are closed after publication.
func ConfigureScope(
	scope string,
	users map[string]User,
	speedLimit func(string) *rate.Limiter,
	deviceLimit func(string) (int, bool),
	limitEvent func(),
) {
	if scope == "" {
		return
	}
	usersCopy := make(map[string]User, len(users))
	for alias, user := range users {
		usersCopy[alias] = user
	}

	runtimeState.mu.Lock()
	state := runtimeState.scopes[scope]
	if state == nil {
		state = &scopeState{
			globalDevices: make(map[int]map[string]bool),
			stats:         make(map[int]*userStats),
		}
		runtimeState.scopes[scope] = state
	}
	state.users = usersCopy
	state.speedLimit = speedLimit
	state.deviceLimit = deviceLimit
	state.limitEvent = limitEvent
	for _, user := range usersCopy {
		if state.stats[user.ID] == nil {
			state.stats[user.ID] = &userStats{ips: make(map[string]int)}
		}
	}

	var stale []io.Closer
	for _, ref := range runtimeState.connections {
		if ref.scope != scope {
			continue
		}
		current, ok := usersCopy[ref.alias]
		if !ok || current.ID != ref.user.ID || current.UUID != ref.user.UUID {
			stale = append(stale, ref.closer)
		}
	}
	runtimeState.mu.Unlock()

	for _, closer := range stale {
		_ = closer.Close()
	}
}

// RemoveScope removes an inbound and terminates all of its active connections.
func RemoveScope(scope string) {
	runtimeState.mu.Lock()
	delete(runtimeState.scopes, scope)
	var connections []io.Closer
	for _, ref := range runtimeState.connections {
		if ref.scope == scope {
			connections = append(connections, ref.closer)
		}
	}
	runtimeState.mu.Unlock()
	for _, closer := range connections {
		_ = closer.Close()
	}
}

// Connection is the accounting handle attached to one Mihomo tracker.
type Connection struct {
	id     string
	ref    *connectionRef
	closed atomic.Bool
}

// Open reserves the source IP and registers an authenticated connection.
// Unconfigured scopes are allowed and returned without an accounting handle.
func Open(id, scope, alias, sourceIP string, closer io.Closer) (*Connection, bool) {
	if scope == "" || alias == "" {
		return nil, true
	}

	runtimeState.mu.Lock()
	state := runtimeState.scopes[scope]
	if state == nil {
		runtimeState.mu.Unlock()
		return nil, true
	}
	user, ok := state.users[alias]
	if !ok {
		runtimeState.mu.Unlock()
		return nil, false
	}
	stats := state.stats[user.ID]
	if stats == nil {
		stats = &userStats{ips: make(map[string]int)}
		state.stats[user.ID] = stats
	}

	limit := 0
	if state.deviceLimit != nil {
		if configured, enabled := state.deviceLimit(user.UUID); enabled {
			limit = configured
		}
	}
	if !admitLocked(user.ID, sourceIP, limit, state, stats) {
		event := state.limitEvent
		runtimeState.mu.Unlock()
		if event != nil {
			event()
		}
		return nil, false
	}

	ref := &connectionRef{
		scope: scope, user: user, alias: alias, sourceIP: sourceIP,
		stats: stats, closer: closer,
	}
	runtimeState.connections[id] = ref
	runtimeState.mu.Unlock()
	return &Connection{id: id, ref: ref}, true
}

func admitLocked(userID int, sourceIP string, limit int, state *scopeState, stats *userStats) bool {
	if sourceIP == "" {
		sourceIP = "unknown"
	}
	if limit > 0 && stats.ips[sourceIP] == 0 {
		seen := make(map[string]struct{})
		for _, scope := range runtimeState.scopes {
			if scopedStats := scope.stats[userID]; scopedStats != nil {
				scopedStats.mu.RLock()
				for ip := range scopedStats.ips {
					seen[ip] = struct{}{}
				}
				scopedStats.mu.RUnlock()
			}
		}
		if !state.globalAt.IsZero() && time.Since(state.globalAt) <= time.Minute {
			for ip := range state.globalDevices[userID] {
				seen[ip] = struct{}{}
			}
		}
		if _, exists := seen[sourceIP]; !exists && len(seen) >= limit {
			return false
		}
	}
	stats.mu.Lock()
	stats.connections++
	stats.ips[sourceIP]++
	stats.mu.Unlock()
	return true
}

func (c *Connection) AddUpload(size int64) {
	if c != nil && size > 0 {
		c.ref.stats.upload.Add(size)
	}
}

func (c *Connection) AddDownload(size int64) {
	if c != nil && size > 0 {
		c.ref.stats.download.Add(size)
	}
}

func (c *Connection) limiter() *rate.Limiter {
	if c == nil {
		return nil
	}
	runtimeState.mu.RLock()
	state := runtimeState.scopes[c.ref.scope]
	var limiter *rate.Limiter
	if state != nil && state.speedLimit != nil {
		limiter = state.speedLimit(c.ref.user.UUID)
	}
	runtimeState.mu.RUnlock()
	return limiter
}

func (c *Connection) ReadLimit() int {
	limiter := c.limiter()
	if limiter == nil || limiter.Limit() == rate.Inf || limiter.Burst() <= 0 {
		return 0
	}
	return limiter.Burst()
}

func (c *Connection) Wait(size int) error {
	limiter := c.limiter()
	if limiter == nil || size <= 0 || limiter.Limit() == rate.Inf || limiter.Burst() <= 0 {
		return nil
	}
	for size > 0 {
		chunk := size
		if chunk > limiter.Burst() {
			chunk = limiter.Burst()
		}
		if err := limiter.WaitN(context.Background(), chunk); err != nil {
			return err
		}
		size -= chunk
	}
	return nil
}

func (c *Connection) Close() {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return
	}
	runtimeState.mu.Lock()
	if current := runtimeState.connections[c.id]; current == c.ref {
		delete(runtimeState.connections, c.id)
	}
	runtimeState.mu.Unlock()

	stats := c.ref.stats
	stats.mu.Lock()
	if stats.connections > 0 {
		stats.connections--
	}
	if count := stats.ips[c.ref.sourceIP]; count > 1 {
		stats.ips[c.ref.sourceIP] = count - 1
	} else {
		delete(stats.ips, c.ref.sourceIP)
	}
	stats.mu.Unlock()
}

func SnapshotScope(scope string) Snapshot {
	runtimeState.mu.RLock()
	state := runtimeState.scopes[scope]
	if state == nil {
		runtimeState.mu.RUnlock()
		return Snapshot{Traffic: map[int][2]int64{}, AliveIPs: map[int]map[string]bool{}}
	}
	statsCopy := make(map[int]*userStats, len(state.stats))
	for id, stats := range state.stats {
		statsCopy[id] = stats
	}
	activeUsers := make(map[int]bool, len(state.users))
	for _, user := range state.users {
		activeUsers[user.ID] = true
	}
	connections := 0
	for _, ref := range runtimeState.connections {
		if ref.scope == scope {
			connections++
		}
	}
	runtimeState.mu.RUnlock()

	snapshot := Snapshot{
		Traffic:     make(map[int][2]int64),
		AliveIPs:    make(map[int]map[string]bool),
		Connections: connections,
	}
	for id, stats := range statsCopy {
		upload, download := stats.upload.Load(), stats.download.Load()
		if upload > 0 || download > 0 {
			snapshot.Traffic[id] = [2]int64{upload, download}
		}
		stats.mu.RLock()
		activeConnections := stats.connections
		if len(stats.ips) > 0 {
			ips := make(map[string]bool, len(stats.ips))
			for ip := range stats.ips {
				ips[ip] = true
			}
			snapshot.AliveIPs[id] = ips
		}
		stats.mu.RUnlock()
		if !activeUsers[id] && activeConnections == 0 {
			runtimeState.mu.Lock()
			if current := runtimeState.scopes[scope]; current == state && current.stats[id] == stats {
				delete(current.stats, id)
			}
			runtimeState.mu.Unlock()
		}
	}
	return snapshot
}

func CloseConnection(id string) bool {
	runtimeState.mu.RLock()
	ref := runtimeState.connections[id]
	runtimeState.mu.RUnlock()
	if ref == nil {
		return false
	}
	_ = ref.closer.Close()
	return true
}

func CloseUser(scope, uuid string) int {
	runtimeState.mu.RLock()
	var connections []io.Closer
	for _, ref := range runtimeState.connections {
		if ref.scope == scope && ref.user.UUID == uuid {
			connections = append(connections, ref.closer)
		}
	}
	runtimeState.mu.RUnlock()
	for _, closer := range connections {
		_ = closer.Close()
	}
	return len(connections)
}

func UpdateGlobalDevices(scope string, users map[int][]string) {
	runtimeState.mu.Lock()
	if state := runtimeState.scopes[scope]; state != nil {
		state.globalDevices = make(map[int]map[string]bool, len(users))
		for id, ips := range users {
			set := make(map[string]bool, len(ips))
			for _, ip := range ips {
				set[ip] = true
			}
			state.globalDevices[id] = set
		}
		state.globalAt = time.Now()
	}
	runtimeState.mu.Unlock()
}

func ClearGlobalDevices(scope string) {
	runtimeState.mu.Lock()
	if state := runtimeState.scopes[scope]; state != nil {
		state.globalDevices = make(map[int]map[string]bool)
		state.globalAt = time.Time{}
	}
	runtimeState.mu.Unlock()
}
