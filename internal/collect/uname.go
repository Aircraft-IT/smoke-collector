package collect

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// kernelRelease is `uname -r`: the release field of uname(2).
func kernelRelease() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	b := u.Release[:]
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b), nil
}
