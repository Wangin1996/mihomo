package inbound_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metacubex/mihomo/adapter/outbound"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/listener"
	listenerHttp "github.com/metacubex/mihomo/listener/http"
	"github.com/metacubex/mihomo/listener/inbound"
	listenerMixed "github.com/metacubex/mihomo/listener/mixed"
	"github.com/metacubex/mihomo/listener/sing_vmess"
	vmess "github.com/metacubex/sing-vmess"
	M "github.com/metacubex/sing/common/metadata"
)

func TestInboundUpdateUsersSupportsAddAndRemove(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"

	t.Run("vless", func(t *testing.T) {
		opt1 := &inbound.VlessOption{
			BaseOption:    inbound.BaseOption{NameStr: "vless-test", Listen: "127.0.0.1", Port: "0"},
			Users:         []inbound.VlessUser{{Username: u1, UUID: u1}},
			Decryption:    "none",
			AllowInsecure: true,
		}
		l, err := inbound.NewVless(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = []inbound.VlessUser{{Username: u1, UUID: u1}, {Username: u2, UUID: u2}}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = []inbound.VlessUser{{Username: u2, UUID: u2}}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("vmess", func(t *testing.T) {
		opt1 := &inbound.VmessOption{
			BaseOption: inbound.BaseOption{NameStr: "vmess-test", Listen: "127.0.0.1", Port: "0"},
			Users:      []inbound.VmessUser{{Username: u1, UUID: u1}},
		}
		l, err := inbound.NewVmess(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = []inbound.VmessUser{{Username: u1, UUID: u1}, {Username: u2, UUID: u2}}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = []inbound.VmessUser{{Username: u2, UUID: u2}}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("trojan", func(t *testing.T) {
		opt1 := &inbound.TrojanOption{
			BaseOption:  inbound.BaseOption{NameStr: "trojan-test", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Users:       []inbound.TrojanUser{{Username: u1, Password: u1}},
		}
		l, err := inbound.NewTrojan(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = []inbound.TrojanUser{{Username: u1, Password: u1}, {Username: u2, Password: u2}}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = []inbound.TrojanUser{{Username: u2, Password: u2}}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("shadowsocks", func(t *testing.T) {
		opt1 := &inbound.ShadowSocksOption{
			BaseOption: inbound.BaseOption{NameStr: "ss-test", Listen: "127.0.0.1", Port: "0"},
			Cipher:     "aes-128-gcm",
			Users:      map[string]string{u1: u1},
		}
		l, err := inbound.NewShadowSocks(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = map[string]string{u1: u1, u2: u2}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = map[string]string{u2: u2}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("tuic", func(t *testing.T) {
		opt1 := &inbound.TuicOption{
			BaseOption:  inbound.BaseOption{NameStr: "tuic-test", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Users:       map[string]string{u1: u1},
		}
		l, err := inbound.NewTuic(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = map[string]string{u1: u1, u2: u2}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = map[string]string{u2: u2}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("anytls", func(t *testing.T) {
		opt1 := &inbound.AnyTLSOption{
			BaseOption:  inbound.BaseOption{NameStr: "anytls-test", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Users:       map[string]string{u1: u1},
		}
		l, err := inbound.NewAnyTLS(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()

		opt2 := *opt1
		opt2.Users = map[string]string{u1: u1, u2: u2}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Users = map[string]string{u2: u2}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("socks_and_http", func(t *testing.T) {
		socksOpt1 := &inbound.SocksOption{
			BaseOption: inbound.BaseOption{NameStr: "socks-test", Listen: "127.0.0.1", Port: "0"},
			Users:      inbound.AuthUsers{{Username: u1, Password: u1}},
		}
		sl, err := inbound.NewSocks(socksOpt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := sl.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer sl.Close()
		socksOpt2 := *socksOpt1
		socksOpt2.Users = inbound.AuthUsers{{Username: u2, Password: u2}}
		if ok, err := sl.UpdateUsers(&socksOpt2); err != nil || !ok {
			t.Fatalf("socks replace user failed: ok=%v err=%v", ok, err)
		}

		httpOpt1 := &inbound.HTTPOption{
			BaseOption: inbound.BaseOption{NameStr: "http-test", Listen: "127.0.0.1", Port: "0"},
			Users:      inbound.AuthUsers{{Username: u1, Password: u1}},
		}
		hl, err := inbound.NewHTTP(httpOpt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := hl.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer hl.Close()
		httpOpt2 := *httpOpt1
		httpOpt2.Users = inbound.AuthUsers{{Username: u2, Password: u2}}
		if ok, err := hl.UpdateUsers(&httpOpt2); err != nil || !ok {
			t.Fatalf("http replace user failed: ok=%v err=%v", ok, err)
		}
	})

	t.Run("hysteria2", func(t *testing.T) {
		opt1 := &inbound.Hysteria2Option{
			BaseOption:  inbound.BaseOption{NameStr: "hy2-test", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Users:       map[string]string{"u1": u1},
		}
		l, err := inbound.NewHysteria2(opt1)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		addrBefore := l.Address()
		addrPort, err := netip.ParseAddrPort(addrBefore)
		if err != nil {
			t.Fatal(err)
		}

		// Concurrent UpdateUsers while handshaking to verify zero data race under -race
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				optLoop := *opt1
				optLoop.Users = map[string]string{"u1": u1, "u2": u2}
				_, _ = l.UpdateUsers(&optLoop)
			}
		}()

		opt2 := *opt1
		opt2.Users = map[string]string{"u1": u1, "u2": u2}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("hysteria2 add user failed: ok=%v err=%v", ok, err)
		}
		wg.Wait()

		hy2OutOpt := outbound.Hysteria2Option{
			Name:        "hy2-out-u2",
			Server:      addrPort.Addr().String(),
			Port:        int(addrPort.Port()),
			Password:    u2,
			Fingerprint: tlsFingerprint,
		}
		hy2OutOpt.DialerForAPI = tunnel.NewDialer()
		hy2OutOpt.TunnelForAPI = tunnel
		out2, err := outbound.NewHysteria2(hy2OutOpt)
		if err != nil {
			t.Fatal(err)
		}
		defer out2.Close()
		tunnel.DoSequentialTest(t, out2)

		opt3 := *opt1
		opt3.Users = map[string]string{"u2": u2}
		if ok, err := l.UpdateUsers(&opt3); err != nil || !ok {
			t.Fatalf("hysteria2 remove user failed: ok=%v err=%v", ok, err)
		}
		if l.Address() != addrBefore {
			t.Fatalf("listener address changed: %s -> %s", addrBefore, l.Address())
		}
	})

	t.Run("mieru_rebuilds_on_user_change", func(t *testing.T) {
		probe, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()

		opt1 := &inbound.MieruOption{
			BaseOption: inbound.BaseOption{NameStr: "mieru-update-test", Listen: "127.0.0.1", Port: strconv.Itoa(port)},
			Transport:  "TCP",
			Users:      map[string]string{"u1": u1},
		}
		m1, err := inbound.NewMieru(opt1)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.PatchInboundListeners(map[string]C.InboundListener{}, tunnel, true)
		listener.PatchInboundListeners(map[string]C.InboundListener{"mieru-update-test": m1}, tunnel, true)

		// Unchanged users -> true
		optSame := *opt1
		optSame.Users = map[string]string{"u1": u1}
		if ok, err := m1.UpdateUsers(&optSame); err != nil || !ok {
			t.Fatalf("expected unchanged mieru users to return true: ok=%v err=%v", ok, err)
		}

		// Changed users -> false so PatchInboundListeners triggers clean Close+Listen
		opt2 := *opt1
		opt2.Users = map[string]string{"u1": u1, "u2": u2}
		if ok, err := m1.UpdateUsers(&opt2); err != nil || ok {
			t.Fatalf("expected changed mieru users to return false for clean rebuild: ok=%v err=%v", ok, err)
		}

		m2, err := inbound.NewMieru(&opt2)
		if err != nil {
			t.Fatal(err)
		}
		listener.PatchInboundListeners(map[string]C.InboundListener{"mieru-update-test": m2}, tunnel, true)

		mieruOutOpt := outbound.MieruOption{
			Name:          "mieru-out-u2",
			Server:        "127.0.0.1",
			Port:          port,
			Transport:     "TCP",
			UserName:      "u2",
			Password:      u2,
			HandshakeMode: "HANDSHAKE_STANDARD",
		}
		mieruOutOpt.DialerForAPI = tunnel.NewDialer()
		mieruOutOpt.TunnelForAPI = tunnel
		out2, err := outbound.NewMieru(mieruOutOpt)
		if err != nil {
			t.Fatal(err)
		}
		defer out2.Close()
		tunnel.DoSequentialTest(t, out2)
	})
}

func TestHysteria2MasqueradeSecurity(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	forbiddenURLs := []string{
		"file:///etc/passwd",
		"http://localhost:8080",
		"https://sub.localhost:8443",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1:8080",
		"http://192.168.1.1:8080",
		"http://[fe80::1]:8080",
	}
	for _, masq := range forbiddenURLs {
		opt := &inbound.Hysteria2Option{
			BaseOption:  inbound.BaseOption{NameStr: "hy2-masq", Listen: "127.0.0.1", Port: "0"},
			Certificate: tlsCertificate,
			PrivateKey:  tlsPrivateKey,
			Users:       map[string]string{"u1": "secret"},
			Masquerade:  masq,
		}
		l, err := inbound.NewHysteria2(opt)
		if err != nil {
			continue
		}
		err = l.Listen(tunnel)
		_ = l.Close()
		if err == nil {
			t.Fatalf("expected masquerade URL %q to be rejected, but Listen succeeded", masq)
		}
	}
}

func TestHTTPKeepAlivePerRequestAuthAndKick(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	opt1 := &inbound.HTTPOption{
		BaseOption: inbound.BaseOption{NameStr: "http-ka-auth", Listen: "127.0.0.1", Port: "0"},
		Users:      inbound.AuthUsers{{Username: "alice", Password: "secret"}},
	}
	hl, err := inbound.NewHTTP(opt1)
	if err != nil {
		t.Fatal(err)
	}
	if err := hl.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer hl.Close()

	conn, err := net.DialTimeout("tcp", hl.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	authHdr := "Basic " + base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	// 1st request with valid auth (invalid URL scheme triggers 400 after passing auth, keeping connection alive)
	req1 := fmt.Sprintf("GET /relative HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: %s\r\n\r\n", authHdr)
	if _, err := conn.Write([]byte(req1)); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp1, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 after valid auth on 1st request, got %d", resp1.StatusCode)
	}

	// 2nd request on same Keep-Alive connection WITHOUT Proxy-Authorization must NOT bypass auth!
	req2 := "GET /relative HTTP/1.1\r\nHost: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
	if _, err := conn.Write([]byte(req2)); err != nil {
		t.Fatal(err)
	}
	resp2, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("expected 407 on unauthenticated 2nd keep-alive request, got %d", resp2.StatusCode)
	}

	// Also verify dynamic kick on Keep-Alive when UpdateUsers removes alice
	conn2, err := net.DialTimeout("tcp", hl.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn2.Close()
	_ = conn2.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn2.Write([]byte(req1)); err != nil {
		t.Fatal(err)
	}
	br2 := bufio.NewReader(conn2)
	r1, err := http.ReadResponse(br2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r1.Body.Close()

	opt2 := *opt1
	opt2.Users = inbound.AuthUsers{{Username: "bob", Password: "secret2"}}
	if ok, err := hl.UpdateUsers(&opt2); err != nil || !ok {
		t.Fatalf("UpdateUsers failed: ok=%v err=%v", ok, err)
	}

	if _, err := conn2.Write([]byte(req1)); err != nil {
		t.Fatal(err)
	}
	r2, err := http.ReadResponse(br2, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Body.Close()
	if r2.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 after alice removed via UpdateUsers on keep-alive conn, got %d", r2.StatusCode)
	}
}

func TestShadowsocksSilentHandshakeDoesNotDeadlockUpdateUsers(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"
	opt1 := &inbound.ShadowSocksOption{
		BaseOption: inbound.BaseOption{NameStr: "ss-deadlock-test", Listen: "127.0.0.1", Port: "0"},
		Cipher:     "aes-128-gcm",
		Users:      map[string]string{u1: u1},
	}
	l, err := inbound.NewShadowSocks(opt1)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Listen(tunnel); err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	// Open a silent TCP connection that sends 0 bytes (stalled in handshake Read)
	silentConn, err := net.DialTimeout("tcp", strings.Split(l.Address(), ",")[0], time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer silentConn.Close()
	time.Sleep(30 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		opt2 := *opt1
		opt2.Users = map[string]string{u1: u1, u2: u2}
		ok, uErr := l.UpdateUsers(&opt2)
		if uErr == nil && !ok {
			uErr = fmt.Errorf("UpdateUsers returned ok=false")
		}
		done <- uErr
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("UpdateUsers failed: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("UpdateUsers deadlocked behind silent TCP handshake connection")
	}
}

func TestHTTPAndMixedHandshakeTimeoutAndConnectSurvival(t *testing.T) {
	restoreHTTP := listenerHttp.SetHandshakeTimeout(120 * time.Millisecond)
	defer restoreHTTP()
	restoreMixed := listenerMixed.SetHandshakeTimeout(120 * time.Millisecond)
	defer restoreMixed()

	echoTunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			packet.Drop()
		},
		CloseFn: func() error { return nil },
	}

	httpIn, err := inbound.NewHTTP(&inbound.HTTPOption{
		BaseOption: inbound.BaseOption{NameStr: "http-timeout-test", Listen: "127.0.0.1", Port: "0"},
		Users:      inbound.AuthUsers{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := httpIn.Listen(echoTunnel); err != nil {
		t.Fatal(err)
	}
	defer httpIn.Close()

	mixedIn, err := inbound.NewMixed(&inbound.MixedOption{
		BaseOption: inbound.BaseOption{NameStr: "mixed-timeout-test", Listen: "127.0.0.1", Port: "0"},
		Users:      inbound.AuthUsers{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mixedIn.Listen(echoTunnel); err != nil {
		t.Fatal(err)
	}
	defer mixedIn.Close()

	assertSilentCloses := func(addr, label string, partial []byte) {
		t.Helper()
		start := time.Now()
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("%s dial failed: %v", label, err)
		}
		defer c.Close()
		if len(partial) > 0 {
			if _, err := c.Write(partial); err != nil {
				t.Fatalf("%s partial write failed: %v", label, err)
			}
		}
		_ = c.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		var one [1]byte
		_, err = c.Read(one[:])
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("%s expected silent connection to close on timeout, but read succeeded", label)
		}
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			t.Fatalf("%s server did not close stalled connection within expected handshake timeout", label)
		}
		if elapsed < 80*time.Millisecond {
			t.Fatalf("%s closed too early (%v < 80ms), expected ~120ms handshake timeout", label, elapsed)
		}
	}

	assertSilentCloses(httpIn.Address(), "http-silent", nil)
	assertSilentCloses(mixedIn.Address(), "mixed-silent", nil)
	assertSilentCloses(mixedIn.Address(), "mixed-partial-http", []byte("CONNECT 1.1.1.1:443 HTTP/1.1\r\n"))

	assertConnectSurvivesIdle := func(addr, label string) {
		t.Helper()
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("%s dial failed: %v", label, err)
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))

		req := "CONNECT 1.1.1.1:443 HTTP/1.1\r\nHost: 1.1.1.1:443\r\n\r\n"
		if _, err := c.Write([]byte(req)); err != nil {
			t.Fatalf("%s write CONNECT failed: %v", label, err)
		}
		br := bufio.NewReader(c)
		resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
		if err != nil {
			t.Fatalf("%s read CONNECT response failed: %v", label, err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s expected 200, got %d", label, resp.StatusCode)
		}

		// Idle longer than 2.5x handshakeTimeout (120ms): tunnel must stay alive!
		time.Sleep(320 * time.Millisecond)

		payload := []byte("hello-after-idle-threshold")
		if _, err := c.Write(payload); err != nil {
			t.Fatalf("%s tunnel write after idle failed: %v", label, err)
		}
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(br, got); err != nil {
			t.Fatalf("%s tunnel read after idle failed (killed by stale deadline): %v", label, err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("%s echo mismatch: got %q, want %q", label, got, payload)
		}
	}

	assertConnectSurvivesIdle(httpIn.Address(), "http-connect")
	assertConnectSurvivesIdle(mixedIn.Address(), "mixed-connect")
}

func TestVMessCommandMuxSurvivesPastHandshakeTimeout(t *testing.T) {
	restoreVMess := sing_vmess.SetHandshakeTimeout(120 * time.Millisecond)
	defer restoreVMess()

	u1 := "11111111-1111-1111-1111-111111111111"
	u2 := "22222222-2222-2222-2222-222222222222"

	udpEchoTunnel := &TestTunnel{
		HandleTCPConnFn: func(conn net.Conn, metadata *C.Metadata) {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		},
		HandleUDPPacketFn: func(packet C.UDPPacket, metadata *C.Metadata) {
			defer packet.Drop()
			_, _ = packet.WriteBack(packet.Data(), metadata.UDPAddr())
		},
		CloseFn: func() error { return nil },
	}

	opt1 := &inbound.VmessOption{
		BaseOption: inbound.BaseOption{NameStr: "vmess-mux-timeout-test", Listen: "127.0.0.1", Port: "0"},
		Users:      []inbound.VmessUser{{Username: u1, UUID: u1}},
	}
	vl, err := inbound.NewVmess(opt1)
	if err != nil {
		t.Fatal(err)
	}
	if err := vl.Listen(udpEchoTunnel); err != nil {
		t.Fatal(err)
	}
	defer vl.Close()

	// 1. Silent TCP client must be disconnected after 120ms handshake timeout
	silentConn, err := net.DialTimeout("tcp", vl.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = silentConn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	var b1 [1]byte
	if _, sErr := silentConn.Read(b1[:]); sErr == nil {
		_ = silentConn.Close()
		t.Fatal("expected silent VMess connection to close on handshake timeout")
	} else if ne, ok := sErr.(net.Error); ok && ne.Timeout() {
		_ = silentConn.Close()
		t.Fatal("VMess server did not close silent connection within handshake timeout")
	}
	_ = silentConn.Close()

	// 2. Establish VMess CommandMux (XUDP) connection sending ONLY the VMess header first
	rawConn, err := net.DialTimeout("tcp", vl.Address(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rawConn.Close()

	client, err := vmess.NewClient(u1, "aes-128-gcm", 0)
	if err != nil {
		t.Fatal(err)
	}
	dest := M.ParseSocksaddrHostPort("1.1.1.1", 53)
	var globalID [8]byte
	globalID[0] = 0x42
	xudpConn, err := client.DialXUDPPacketConn(rawConn, globalID, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer xudpConn.Close()

	// Sleep 320ms (> 2.5x handshakeTimeout) BEFORE sending the first StatusNew XUDP frame!
	time.Sleep(320 * time.Millisecond)

	// Hot-update users concurrently while Mux session is open
	opt2 := *opt1
	opt2.Users = []inbound.VmessUser{{Username: u1, UUID: u1}, {Username: u2, UUID: u2}}
	if ok, err := vl.UpdateUsers(&opt2); err != nil || !ok {
		t.Fatalf("VMess UpdateUsers failed: ok=%v err=%v", ok, err)
	}

	_ = rawConn.SetDeadline(time.Now().Add(3 * time.Second))
	msg1 := []byte("xudp-first-frame-after-idle")
	if _, err := xudpConn.WriteTo(msg1, dest.UDPAddr()); err != nil {
		t.Fatalf("first XUDP WriteTo after pre-stream idle failed: %v", err)
	}
	buf := make([]byte, 256)
	n, _, err := xudpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("first XUDP ReadFrom failed (CommandMux killed by handshake deadline): %v", err)
	}
	if !bytes.Equal(buf[:n], msg1) {
		t.Fatalf("first XUDP echo mismatch: got %q, want %q", buf[:n], msg1)
	}

	// Sleep another 320ms idle between XUDP packets and send a second packet
	time.Sleep(320 * time.Millisecond)
	msg2 := []byte("xudp-second-frame-after-keepalive-idle")
	if _, err := xudpConn.WriteTo(msg2, dest.UDPAddr()); err != nil {
		t.Fatalf("second XUDP WriteTo failed: %v", err)
	}
	n, _, err = xudpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("second XUDP ReadFrom failed: %v", err)
	}
	if !bytes.Equal(buf[:n], msg2) {
		t.Fatalf("second XUDP echo mismatch: got %q, want %q", buf[:n], msg2)
	}
}

func TestInboundListenModeIsolation(t *testing.T) {
	tunnel := NewHttpTestTunnel()
	defer tunnel.Close()

	u1 := "11111111-1111-1111-1111-111111111111"

	t.Run("ipv6_only_rejects_ipv4", func(t *testing.T) {
		opt := &inbound.VlessOption{
			BaseOption:    inbound.BaseOption{NameStr: "vless-v6", Listen: "::", Port: "0"},
			Users:         []inbound.VlessUser{{Username: u1, UUID: u1}},
			Decryption:    "none",
			AllowInsecure: true,
		}
		l, err := inbound.NewVless(opt)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		_, port, err := net.SplitHostPort(l.Address())
		if err != nil {
			t.Fatal(err)
		}
		if c4, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", port), 300*time.Millisecond); err == nil {
			_ = c4.Close()
			t.Fatalf("expected IPv4 dial to fail on IPv6-only listener (%s), but it succeeded", l.Address())
		}
		c6, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", port), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("expected IPv6 dial to succeed on IPv6-only listener (%s): %v", l.Address(), err)
		}
		_ = c6.Close()
	})

	t.Run("ipv4_only_rejects_ipv6", func(t *testing.T) {
		opt := &inbound.VlessOption{
			BaseOption:    inbound.BaseOption{NameStr: "vless-v4", Listen: "0.0.0.0", Port: "0"},
			Users:         []inbound.VlessUser{{Username: u1, UUID: u1}},
			Decryption:    "none",
			AllowInsecure: true,
		}
		l, err := inbound.NewVless(opt)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		_, port, err := net.SplitHostPort(l.Address())
		if err != nil {
			t.Fatal(err)
		}
		if c6, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", port), 300*time.Millisecond); err == nil {
			_ = c6.Close()
			t.Fatalf("expected IPv6 dial to fail on IPv4-only listener (%s), but it succeeded", l.Address())
		}
		c4, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", port), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("expected IPv4 dial to succeed on IPv4-only listener (%s): %v", l.Address(), err)
		}
		_ = c4.Close()
	})

	t.Run("dual_stack_accepts_both_ipv4_and_ipv6", func(t *testing.T) {
		opt := &inbound.VlessOption{
			BaseOption:    inbound.BaseOption{NameStr: "vless-dual", Listen: "0.0.0.0,::", Port: "0"},
			Users:         []inbound.VlessUser{{Username: u1, UUID: u1}},
			Decryption:    "none",
			AllowInsecure: true,
		}
		l, err := inbound.NewVless(opt)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Listen(tunnel); err != nil {
			t.Fatal(err)
		}
		defer l.Close()

		_, port, err := net.SplitHostPort(l.Address())
		if err != nil {
			t.Fatal(err)
		}
		c4, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", port), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("expected IPv4 dial to succeed on dual-stack listener (%s): %v", l.Address(), err)
		}
		_ = c4.Close()
		c6, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", port), 500*time.Millisecond)
		if err != nil {
			t.Fatalf("expected IPv6 dial to succeed on dual-stack listener (%s): %v", l.Address(), err)
		}
		_ = c6.Close()
	})
}
