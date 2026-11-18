//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package sockopt

import "golang.org/x/sys/unix"

func setV6OnlyControl(fd uintptr, v6only int) error {
	return unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, v6only)
}
