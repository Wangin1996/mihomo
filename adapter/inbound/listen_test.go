package inbound

import (
	"errors"
	"syscall"
	"testing"
)

func TestResolveListenNetwork(t *testing.T) {
	cases := []struct {
		network    string
		address    string
		listenMode string
		want       string
	}{
		{"tcp", "[::]:8080", "all", "tcp"},
		{"tcp6", "[::]:8080", "all", "tcp"},
		{"tcp4", "0.0.0.0:8080", "all", "tcp"},
		{"udp6", "[::]:8080", "dual", "udp"},
		{"tcp", "0.0.0.0:8080", "ipv4", "tcp4"},
		{"tcp6", "[::]:8080", "ipv4", "tcp4"},
		{"udp", "[::]:8080", "ipv6", "udp6"},
		{"udp4", "0.0.0.0:8080", "ipv6", "udp6"},
		{"tcp4", "0.0.0.0:8080", "", "tcp4"},
		{"tcp6", "[::]:8080", "", "tcp6"},
		{"tcp", "127.0.0.1:8080", "", "tcp4"},
		{"udp", "[::1]:8080", "", "udp6"},
	}
	for _, tc := range cases {
		if got := resolveListenNetwork(tc.network, tc.address, tc.listenMode); got != tc.want {
			t.Errorf("resolveListenNetwork(%q, %q, %q) = %q, want %q", tc.network, tc.address, tc.listenMode, got, tc.want)
		}
	}
}

func TestDualStackIPv4Fallback(t *testing.T) {
	netName, addr, ok := dualStackIPv4Fallback("tcp", "[::]:443", syscall.EAFNOSUPPORT)
	if !ok || netName != "tcp4" || addr != "0.0.0.0:443" {
		t.Fatalf("unexpected tcp fallback: ok=%v net=%q addr=%q", ok, netName, addr)
	}

	netName, addr, ok = dualStackIPv4Fallback("udp6", "[::]:8443", syscall.EPROTONOSUPPORT)
	if !ok || netName != "udp4" || addr != "0.0.0.0:8443" {
		t.Fatalf("unexpected udp fallback: ok=%v net=%q addr=%q", ok, netName, addr)
	}

	if _, _, ok := dualStackIPv4Fallback("tcp", "[::]:443", errors.New("address already in use")); ok {
		t.Fatal("EADDRINUSE must not trigger IPv4 fallback")
	}

	if _, _, ok := dualStackIPv4Fallback("tcp", "[2001:db8::1]:443", syscall.EAFNOSUPPORT); ok {
		t.Fatal("explicit non-unspecified IPv6 address must not silently bind 0.0.0.0")
	}
}
