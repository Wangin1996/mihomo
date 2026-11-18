//go:build windows

package sockopt

import "golang.org/x/sys/windows"

func setV6OnlyControl(fd uintptr, v6only int) error {
	return windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IPV6, windows.IPV6_V6ONLY, v6only)
}
