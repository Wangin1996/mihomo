package inbound_test

import (
	"testing"

	"github.com/metacubex/mihomo/listener/inbound"
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
			Password:   u1,
			Users:      []inbound.ShadowSocksUser{{Username: u1, Password: u1}},
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
		opt2.Users = []inbound.ShadowSocksUser{{Username: u1, Password: u1}, {Username: u2, Password: u2}}
		if ok, err := l.UpdateUsers(&opt2); err != nil || !ok {
			t.Fatalf("add user failed: ok=%v err=%v", ok, err)
		}
		opt3 := *opt1
		opt3.Password = u2
		opt3.Users = []inbound.ShadowSocksUser{{Username: u2, Password: u2}}
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
}
