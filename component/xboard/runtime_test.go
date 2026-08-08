package xboard

import (
	"sync/atomic"
	"testing"
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
