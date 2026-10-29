//go:build linux && amd64

package sandbox

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// installSeccomp sets no_new_privs and loads the profile's filter on the calling thread. The
// caller must have called runtime.LockOSThread and must execve from this same thread, so the
// filter (which is inherited across execve) covers the user program.
func installSeccomp(p Profile) error {
	prog, err := Compile(PolicyFor(p))
	if err != nil {
		return err
	}
	filters := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filters[i] = unix.SockFilter{Code: in.Code, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_SET_NO_NEW_PRIVS: %w", err)
	}
	fprog := unix.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return fmt.Errorf("seccomp filter: %w", errno)
	}
	return nil
}
