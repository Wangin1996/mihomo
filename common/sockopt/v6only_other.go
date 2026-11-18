//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package sockopt

func setV6OnlyControl(fd uintptr, v6only int) error {
	return nil
}
