package xboard

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

type testCloser struct{ closed atomic.Int64 }

func (c *testCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func TestScopeTracksTrafficAndEnforcesDistinctIPs(t *testing.T) {
	const scope = "node-test-limit"
	defer RemoveScope(scope)

	var rejected atomic.Int64
	ConfigureScope(scope, map[string]User{"uuid": {ID: 7, UUID: "uuid"}}, nil,
		func(string) (int, bool) { return 1, true },
		func() { rejected.Add(1) },
	)

	first, ok := Open("c1", scope, "uuid", "1.1.1.1", &testCloser{})
	if !ok || first == nil {
		t.Fatal("first IP should be admitted")
	}
	second, ok := Open("c2", scope, "uuid", "1.1.1.1", &testCloser{})
	if !ok || second == nil {
		t.Fatal("an existing IP should be admitted")
	}
	if _, ok := Open("c3", scope, "uuid", "2.2.2.2", &testCloser{}); ok {
		t.Fatal("a second distinct IP should be rejected")
	}
	if rejected.Load() != 1 {
		t.Fatalf("rejection events = %d, want 1", rejected.Load())
	}

	first.AddUpload(11)
	first.AddDownload(22)
	snapshot := SnapshotScope(scope)
	if got := snapshot.Traffic[7]; got != [2]int64{11, 22} {
		t.Fatalf("traffic = %v", got)
	}
	if snapshot.Connections != 2 || !snapshot.AliveIPs[7]["1.1.1.1"] {
		t.Fatalf("unexpected live snapshot: %#v", snapshot)
	}

	first.Close()
	second.Close()
	if got := SnapshotScope(scope).Connections; got != 0 {
		t.Fatalf("connections after close = %d", got)
	}
}

func TestConfigureScopeClosesRemovedCredentials(t *testing.T) {
	const scope = "node-test-update"
	defer RemoveScope(scope)

	ConfigureScope(scope, map[string]User{"old": {ID: 8, UUID: "old"}}, nil, nil, nil)
	closer := &testCloser{}
	connection, ok := Open("update-1", scope, "old", "3.3.3.3", closer)
	if !ok || connection == nil {
		t.Fatal("old credential should be admitted")
	}

	ConfigureScope(scope, map[string]User{"new": {ID: 9, UUID: "new"}}, nil, nil, nil)
	if closer.closed.Load() != 1 {
		t.Fatalf("removed connection close calls = %d", closer.closed.Load())
	}
	connection.Close()
	first := SnapshotScope(scope)
	if _, ok := first.Traffic[8]; ok {
		t.Fatal("zero-traffic retired user should not produce a traffic sample")
	}
	if _, ok := runtimeState.scopes[scope].stats[8]; ok {
		t.Fatal("retired user stats were not released after final snapshot")
	}
}

func TestManagedScopeRejectsEmptyAndUnknownAlias(t *testing.T) {
	const scope = "node-test-auth"
	defer RemoveScope(scope)

	if !CanOpen("unmanaged-scope", "", "1.1.1.1") {
		t.Fatal("unmanaged scope with empty alias should be allowed")
	}
	if _, ok := Open("u1", "unmanaged-scope", "", "1.1.1.1", &testCloser{}); !ok {
		t.Fatal("unmanaged scope Open with empty alias should be allowed")
	}

	ConfigureScope(scope, map[string]User{"valid": {ID: 1, UUID: "valid"}}, nil, nil, nil)
	if CanOpen(scope, "", "1.1.1.1") {
		t.Fatal("managed scope must reject empty alias in CanOpen")
	}
	if _, ok := Open("m1", scope, "", "1.1.1.1", &testCloser{}); ok {
		t.Fatal("managed scope must reject empty alias in Open")
	}
	if CanOpen(scope, "unknown", "1.1.1.1") {
		t.Fatal("managed scope must reject unknown alias in CanOpen")
	}
}

func TestConfigureScopeLazyStatsAndIsUnlimited(t *testing.T) {
	const scope = "node-test-lazy"
	defer RemoveScope(scope)

	users := make(map[string]User, 100)
	for i := 1; i <= 100; i++ {
		alias := fmt.Sprintf("u-%d", i)
		users[alias] = User{ID: i, UUID: alias}
	}
	ConfigureScope(scope, users, func(uuid string) *rate.Limiter {
		if uuid == "u-1" {
			return rate.NewLimiter(rate.Inf, 0)
		}
		if uuid == "u-2" {
			return rate.NewLimiter(1024, 1024)
		}
		return nil
	}, nil, nil)

	runtimeState.mu.RLock()
	statsCount := len(runtimeState.scopes[scope].stats)
	runtimeState.mu.RUnlock()
	if statsCount != 0 {
		t.Fatalf("expected lazy stats allocation (0 idle entries), got %d", statsCount)
	}

	c1, ok := Open("lazy-1", scope, "u-1", "1.2.3.4", &testCloser{})
	if !ok || !c1.IsUnlimited() {
		t.Fatal("rate.Inf user should be treated as unlimited")
	}
	defer c1.Close()

	c2, ok := Open("lazy-2", scope, "u-2", "1.2.3.5", &testCloser{})
	if !ok || c2.IsUnlimited() {
		t.Fatal("finite rate user should not be unlimited")
	}
	defer c2.Close()

	c3, ok := Open("lazy-3", scope, "u-3", "1.2.3.6", &testCloser{})
	if !ok || !c3.IsUnlimited() {
		t.Fatal("nil limiter user should be unlimited")
	}
	defer c3.Close()
}

func TestWaitCancelsImmediatelyOnCloseOrKick(t *testing.T) {
	const scope = "node-test-wait-cancel"
	defer RemoveScope(scope)

	lim := rate.NewLimiter(10, 100)
	// Drain initial burst
	_ = lim.AllowN(time.Now(), 100)

	ConfigureScope(scope, map[string]User{"slow": {ID: 42, UUID: "slow"}},
		func(string) *rate.Limiter { return lim }, nil, nil)

	conn, ok := Open("wait-1", scope, "slow", "5.5.5.5", &testCloser{})
	if !ok || conn == nil {
		t.Fatal("expected Open to succeed")
	}

	done := make(chan error, 1)
	go func() {
		// 100 bytes at 10 B/s would block ~10s without cancellation
		done <- conn.Wait(100)
	}()

	time.Sleep(20 * time.Millisecond)
	ConfigureScope(scope, map[string]User{}, nil, nil, nil)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected Wait to return cancellation error when kicked")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Wait blocked after user kick")
	}
	conn.Close()
}

func TestSnapshotScopePreservesRetiredUserTailTraffic(t *testing.T) {
	const scope = "node-test-tail-traffic"
	defer RemoveScope(scope)

	ConfigureScope(scope, map[string]User{"u1": {ID: 99, UUID: "u1"}}, nil, nil, nil)
	conn, ok := Open("tail-1", scope, "u1", "8.8.8.8", &testCloser{})
	if !ok || conn == nil {
		t.Fatal("expected Open to succeed")
	}

	// Retire user while connection is still finishing tail bytes
	ConfigureScope(scope, map[string]User{}, nil, nil, nil)
	conn.AddUpload(4096)
	conn.AddDownload(8192)
	conn.Close()

	snap := SnapshotScope(scope)
	if got := snap.Traffic[99]; got != [2]int64{4096, 8192} {
		t.Fatalf("retired user tail traffic = %v, want [4096 8192]", got)
	}
	snap2 := SnapshotScope(scope)
	if _, exists := snap2.Traffic[99]; exists {
		t.Fatal("retired user stats should be cleaned up after final snapshot")
	}
}
