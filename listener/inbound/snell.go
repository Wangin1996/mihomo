package inbound

import (
	"errors"
	"fmt"
	"maps"
	"strings"

	C "github.com/metacubex/mihomo/constant"
	LC "github.com/metacubex/mihomo/listener/config"
	"github.com/metacubex/mihomo/listener/snell"
	"github.com/metacubex/mihomo/log"
)

type SnellOption struct {
	BaseOption
	Psk       string            `inbound:"psk,omitempty"`
	Users     map[string]string `inbound:"users,omitempty"`
	Version   int               `inbound:"version,omitempty"`
	Mode      string            `inbound:"mode,omitempty"` // v6 only: default / unshaped / unsafe-raw
	UDP       bool              `inbound:"udp,omitempty"`
	ObfsOpts  SnellObfsOption   `inbound:"obfs-opts,omitempty"`
	ShadowTLS ShadowTLS         `inbound:"shadow-tls,omitempty"`
	ResTLS    ResTLS            `inbound:"res-tls,omitempty"`
	JLSConfig JLSConfig         `inbound:"jls-config,omitempty"`
}

func (o SnellOption) Equal(config C.InboundConfig) bool {
	return optionToString(o) == optionToString(config)
}

type SnellObfsOption struct {
	Mode string `obfs:"mode,omitempty"`
	Host string `obfs:"host,omitempty"`
}

type Snell struct {
	*Base
	config *SnellOption
	l      C.MultiAddrListener
	snell  LC.SnellServer
}

func NewSnell(options *SnellOption) (*Snell, error) {
	base, err := NewBase(&options.BaseOption)
	if err != nil {
		return nil, err
	}
	if options.Version == 0 {
		options.Version = 4
	}
	if options.Version < 1 || options.Version > 6 {
		return nil, fmt.Errorf("snell inbound version %d is not supported", options.Version)
	}
	if options.Psk == "" && len(options.Users) == 0 {
		return nil, errors.New("snell inbound requires psk or users")
	}

	return &Snell{
		Base:   base,
		config: options,
		snell: LC.SnellServer{
			Listen:    base.RawAddress(),
			Psk:       options.Psk,
			Users:     maps.Clone(options.Users),
			Version:   options.Version,
			Mode:      options.Mode,
			UDP:       options.UDP,
			ObfsMode:  options.ObfsOpts.Mode,
			ObfsHost:  options.ObfsOpts.Host,
			ShadowTLS: options.ShadowTLS.Build(),
			ResTLS:    options.ResTLS.Build(),
			JLSConfig: options.JLSConfig.Build(),
		},
	}, nil
}

func (s *Snell) Config() C.InboundConfig {
	return s.config
}

func (s *Snell) Address() string {
	var addrList []string
	if s.l != nil {
		for _, addr := range s.l.AddrList() {
			addrList = append(addrList, addr.String())
		}
	}
	return strings.Join(addrList, ",")
}

func (s *Snell) Listen(tunnel C.Tunnel) error {
	var err error
	s.l, err = snell.New(s.snell, s.ListenConfig(), tunnel, s.Additions()...)
	if err != nil {
		return err
	}
	log.Infoln("Snell[%s] inbound listening at: %s", s.Name(), s.Address())
	return nil
}

func (s *Snell) Close() error {
	if s.l == nil {
		return nil
	}
	return s.l.Close()
}

func (s *Snell) UpdateUsers(config C.InboundConfig) (bool, error) {
	next, ok := config.(*SnellOption)
	if !ok || !sameSnellStatic(s.config, next) || len(s.config.Users) == 0 || len(next.Users) == 0 {
		return false, nil
	}
	if s.config.Version == 6 && s.config.Mode == "unsafe-raw" && len(next.Users) > 1 {
		return false, nil
	}
	listener, ok := s.l.(*snell.Listener)
	if !ok || listener == nil {
		return false, nil
	}
	users := maps.Clone(next.Users)
	if err := listener.UpdateUsers(users); err != nil {
		return false, err
	}
	s.config.Psk = next.Psk
	s.config.Users = users
	s.snell.Psk = next.Psk
	s.snell.Users = maps.Clone(users)
	return true, nil
}

func sameSnellStatic(left, right *SnellOption) bool {
	leftCopy := *left
	rightCopy := *right
	leftCopy.Users = nil
	rightCopy.Users = nil
	return optionToString(leftCopy) == optionToString(rightCopy)
}

var _ C.InboundListener = (*Snell)(nil)
var _ C.InboundUserUpdater = (*Snell)(nil)
