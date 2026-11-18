package sockopt

import "syscall"

func RawConnSetV6Only(rc syscall.RawConn, v6only bool) (err error) {
	val := 0
	if v6only {
		val = 1
	}
	var innerErr error
	err = rc.Control(func(fd uintptr) {
		innerErr = setV6OnlyControl(fd, val)
	})
	if innerErr != nil {
		err = innerErr
	}
	return
}
