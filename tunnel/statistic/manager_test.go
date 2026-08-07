package statistic

import (
	"testing"

	C "github.com/metacubex/mihomo/constant"
)

func TestUserKeyNamespacesIdentityByInbound(t *testing.T) {
	manager := &Manager{}
	first := manager.UserKey(&C.Metadata{InName: "node-1", InUser: "same-user"})
	second := manager.UserKey(&C.Metadata{InName: "node-2", InUser: "same-user"})
	if first == second {
		t.Fatalf("user keys collided: %q", first)
	}
	if got := manager.UserKey(&C.Metadata{InUser: "same-user"}); got != "same-user" {
		t.Fatalf("unnamed inbound key = %q", got)
	}
}

func TestUserTrafficSurvivesWithoutActiveTracker(t *testing.T) {
	manager := &Manager{}
	manager.pushUserUploaded("node-1\x00user", 123)
	manager.pushUserDownloaded("node-1\x00user", 456)
	snapshot := manager.SnapshotUsers()["node-1\x00user"]
	if snapshot.Upload != 123 || snapshot.Download != 456 {
		t.Fatalf("unexpected traffic snapshot: %+v", snapshot)
	}
	if snapshot.Connections != 0 {
		t.Fatalf("connections = %d, want 0", snapshot.Connections)
	}
}
