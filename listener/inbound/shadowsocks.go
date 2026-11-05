package inbound

import (
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/sing_shadowsocks"
	"github.com/metacubex/mihomo/log"
)

type ShadowSocksOption struct {
	BaseOption
	Password   string            `inbound:"password"`
	Cipher     string            `inbound:"cipher"`
	Users      []ShadowSocksUser `inbound:"users,omitempty"`
	UDP        bool              `inbound:"udp,omitempty"`
	MuxOption  MuxOption         `inbound:"mux-option,omitempty"`
	ShadowTLS  ShadowTLS         `inbound:"shadow-tls,omitempty"`
	ResTLS     ResTLS            `inbound:"res-tls,omitempty"`
	JLSConfig  JLSConfig         `inbound:"jls-config,omitempty"`
	KcpTun     KcpTun            `inbound:"kcp-tun,omitempty"`
	SimpleObfs SimpleObfs        `inbound:"simple-obfs,omitempty"`
}

type ShadowSocksUser struct {
	Username string `inbound:"username"`
	Password string `inbound:"password"`
}

type SimpleObfs struct {
	Enable bool   `inbound:"enable,omitempty"`
	Mode   string `inbound:"mode,omitempty"`
}

func (o SimpleObfs) Build() LC.SimpleObfs {
	return LC.SimpleObfs{
		Enable: o.Enable,
		Mode:   o.Mode,
	}
}

func (o ShadowSocksOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type ShadowSocks struct {
	*Base
	config *ShadowSocksOption
	l      C.MultiAddrListener
	ss     LC.ShadowsocksServer
}

func NewShadowSocks(options *ShadowSocksOption) (*ShadowSocks, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	users := make([]LC.ShadowsocksUser, len(options.Users))
	for i, user := range options.Users {
		users[i] = LC.ShadowsocksUser{Username: user.Username, Password: user.Password}
	}
	return &ShadowSocks{
		Base:   base,
		config: options,
		ss: LC.ShadowsocksServer{
			Enable:     true,
			Listen:     base.RawAddress(),
			Password:   options.Password,
			Cipher:     options.Cipher,
			Users:      users,
			Udp:        options.UDP,
			MuxOption:  options.MuxOption.Build(),
			ShadowTLS:  options.ShadowTLS.Build(),
			ResTLS:     options.ResTLS.Build(),
			JLSConfig:  options.JLSConfig.Build(),
			KcpTun:     options.KcpTun.Build(),
			SimpleObfs: options.SimpleObfs.Build(),
		},
	}, nil
}

// Config implements constant.InboundListener
func (s *ShadowSocks) Config() C.InboundConfig {
	return s.config
}

// Address implements constant.InboundListener
func (s *ShadowSocks) Address() string {
	var addrList []string
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

// Listen implements constant.InboundListener
func (s *ShadowSocks) Listen(tunnel C.Tunnel) error {
	var err error
	s.l, err = sing_shadowsocks.New(s.ss, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("ShadowSocks[%s] proxy listening at: %s", s.Name(), s.Address())
	return nil
}

// Close implements constant.InboundListener
func (s *ShadowSocks) Close() error {
	return s.l.Close()
}

func (s *ShadowSocks) UpdateUsers(config C.InboundConfig) (bool, error) {
	next, ok := config.(*ShadowSocksOption)
	if !ok || !sameShadowSocksStatic(s.config, next) || len(s.config.Users) == 0 || len(next.Users) == 0 || s.config.Cipher == "2022-blake3-chacha20-poly1305" {
		return false, nil
	}
	listener, ok := s.l.(*sing_shadowsocks.Listener)
	if !ok || listener == nil {
		return false, nil
	}
	users := append([]ShadowSocksUser(nil), next.Users...)
	listenerUsers := make([]LC.ShadowsocksUser, 0, len(users))
	for _, user := range users {
		listenerUsers = append(listenerUsers, LC.ShadowsocksUser{
			Username: user.Username,
			Password: user.Password,
		})
	}
	if err := listener.UpdateUsers(listenerUsers); err != nil {
		return false, err
	}
	s.config.Password = next.Password
	s.config.Users = users
	s.ss.Password = next.Password
	s.ss.Users = listenerUsers
	return true, nil
}

func sameShadowSocksStatic(left, right *ShadowSocksOption) bool {
	leftCopy := *left
	rightCopy := *right
	leftCopy.Users = nil
	rightCopy.Users = nil
	if len(left.Users) > 0 && len(right.Users) > 0 && !strings.HasPrefix(left.Cipher, "2022-blake3-") {
		leftCopy.Password = ""
		rightCopy.Password = ""
	}
	return optionToString(leftCopy) == optionToString(rightCopy)
}

var _ C.InboundListener = (*ShadowSocks)(nil)
var _ C.InboundUserUpdater = (*ShadowSocks)(nil)
