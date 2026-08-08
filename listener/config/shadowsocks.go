package config

import (
	"github.com/metacubex/mihomo/listener/sing"

	"encoding/json"
)

type ShadowsocksServer struct {
	Enable     bool
	Listen     string
	Password   string
	Cipher     string
	Users      []ShadowsocksUser `yaml:"users" json:"users,omitempty"`
	Udp        bool
	MuxOption  sing.MuxOption `yaml:"mux-option" json:"mux-option,omitempty"`
	ShadowTLS  ShadowTLS      `yaml:"shadow-tls" json:"shadow-tls,omitempty"`
	ResTLS     ResTLS         `yaml:"res-tls" json:"res-tls,omitempty"`
	JLSConfig  JLSConfig      `yaml:"jls-config" json:"jls-config,omitempty"`
	KcpTun     KcpTun         `yaml:"kcp-tun" json:"kcp-tun,omitempty"`
	SimpleObfs SimpleObfs     `yaml:"simple-obfs" json:"simple-obfs,omitempty"`
}

type ShadowsocksUser struct {
	Username string `yaml:"username" json:"username"`
	Password string `yaml:"password" json:"password"`
}

type SimpleObfs struct {
	Enable bool
	Mode   string
}

func (t ShadowsocksServer) String() string {
	b, _ := json.Marshal(t)
	return string(b)
}
