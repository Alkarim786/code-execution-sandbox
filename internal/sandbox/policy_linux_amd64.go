//go:build linux && amd64

package sandbox

import (
	"golang.org/x/sys/unix"
)

func a(name string, nr uintptr) Rule { return Rule{Name: name, Nr: uint32(nr), Kind: Allow} }

// Hot syscalls first: the filter is a linear chain, so order is a performance knob.
var baseRules = []Rule{
	a("read", unix.SYS_READ), a("write", unix.SYS_WRITE), a("mmap", unix.SYS_MMAP), a("munmap", unix.SYS_MUNMAP),
	a("brk", unix.SYS_BRK), a("futex", unix.SYS_FUTEX), a("close", unix.SYS_CLOSE), a("openat", unix.SYS_OPENAT),
	a("newfstatat", unix.SYS_NEWFSTATAT), a("fstat", unix.SYS_FSTAT), a("mprotect", unix.SYS_MPROTECT),
	a("rt_sigaction", unix.SYS_RT_SIGACTION), a("rt_sigprocmask", unix.SYS_RT_SIGPROCMASK),
	a("rt_sigreturn", unix.SYS_RT_SIGRETURN), a("lseek", unix.SYS_LSEEK), a("pread64", unix.SYS_PREAD64),
	a("pwrite64", unix.SYS_PWRITE64), a("readv", unix.SYS_READV), a("writev", unix.SYS_WRITEV),
	a("clock_gettime", unix.SYS_CLOCK_GETTIME), a("exit_group", unix.SYS_EXIT_GROUP), a("exit", unix.SYS_EXIT),
	a("madvise", unix.SYS_MADVISE), a("mremap", unix.SYS_MREMAP), a("getrandom", unix.SYS_GETRANDOM),
	a("sched_yield", unix.SYS_SCHED_YIELD), a("nanosleep", unix.SYS_NANOSLEEP),
	a("clock_nanosleep", unix.SYS_CLOCK_NANOSLEEP), a("clock_getres", unix.SYS_CLOCK_GETRES),
	a("gettimeofday", unix.SYS_GETTIMEOFDAY), a("time", unix.SYS_TIME),
	// identity / process info (read only)
	a("getpid", unix.SYS_GETPID), a("gettid", unix.SYS_GETTID), a("getppid", unix.SYS_GETPPID),
	a("getuid", unix.SYS_GETUID), a("geteuid", unix.SYS_GETEUID), a("getgid", unix.SYS_GETGID),
	a("getegid", unix.SYS_GETEGID), a("getgroups", unix.SYS_GETGROUPS), a("getpgid", unix.SYS_GETPGID),
	a("getpgrp", unix.SYS_GETPGRP), a("getsid", unix.SYS_GETSID), a("uname", unix.SYS_UNAME),
	a("sysinfo", unix.SYS_SYSINFO), a("getrlimit", unix.SYS_GETRLIMIT), a("prlimit64", unix.SYS_PRLIMIT64),
	a("getrusage", unix.SYS_GETRUSAGE), a("times", unix.SYS_TIMES), a("umask", unix.SYS_UMASK),
	a("capget", unix.SYS_CAPGET), a("getpriority", unix.SYS_GETPRIORITY),
	// threads, signals, scheduling
	a("set_tid_address", unix.SYS_SET_TID_ADDRESS), a("set_robust_list", unix.SYS_SET_ROBUST_LIST),
	a("get_robust_list", unix.SYS_GET_ROBUST_LIST), a("rseq", unix.SYS_RSEQ), a("arch_prctl", unix.SYS_ARCH_PRCTL),
	a("sigaltstack", unix.SYS_SIGALTSTACK), a("tgkill", unix.SYS_TGKILL), a("tkill", unix.SYS_TKILL),
	a("rt_sigsuspend", unix.SYS_RT_SIGSUSPEND), a("rt_sigpending", unix.SYS_RT_SIGPENDING),
	a("rt_sigtimedwait", unix.SYS_RT_SIGTIMEDWAIT), a("pause", unix.SYS_PAUSE),
	a("setitimer", unix.SYS_SETITIMER), a("getitimer", unix.SYS_GETITIMER), a("alarm", unix.SYS_ALARM),
	a("sched_getaffinity", unix.SYS_SCHED_GETAFFINITY), a("sched_setaffinity", unix.SYS_SCHED_SETAFFINITY),
	a("sched_getparam", unix.SYS_SCHED_GETPARAM), a("sched_getscheduler", unix.SYS_SCHED_GETSCHEDULER),
	a("sched_get_priority_max", unix.SYS_SCHED_GET_PRIORITY_MAX),
	a("sched_get_priority_min", unix.SYS_SCHED_GET_PRIORITY_MIN),
	a("membarrier", unix.SYS_MEMBARRIER), a("mlock", unix.SYS_MLOCK), a("munlock", unix.SYS_MUNLOCK),
	a("mincore", unix.SYS_MINCORE), a("msync", unix.SYS_MSYNC), a("get_mempolicy", unix.SYS_GET_MEMPOLICY),
	// files (the filesystem itself is read-only except /tmp, /work, /out for toolchains)
	a("open", unix.SYS_OPEN), a("stat", unix.SYS_STAT), a("lstat", unix.SYS_LSTAT), a("statx", unix.SYS_STATX),
	a("access", unix.SYS_ACCESS), a("faccessat", unix.SYS_FACCESSAT), a("faccessat2", unix.SYS_FACCESSAT2),
	a("readlink", unix.SYS_READLINK), a("readlinkat", unix.SYS_READLINKAT), a("getcwd", unix.SYS_GETCWD),
	a("chdir", unix.SYS_CHDIR), a("fchdir", unix.SYS_FCHDIR), a("getdents", unix.SYS_GETDENTS),
	a("getdents64", unix.SYS_GETDENTS64), a("dup", unix.SYS_DUP), a("dup2", unix.SYS_DUP2),
	a("dup3", unix.SYS_DUP3), a("fcntl", unix.SYS_FCNTL), a("flock", unix.SYS_FLOCK),
	a("fsync", unix.SYS_FSYNC), a("fdatasync", unix.SYS_FDATASYNC), a("ftruncate", unix.SYS_FTRUNCATE),
	a("truncate", unix.SYS_TRUNCATE), a("fallocate", unix.SYS_FALLOCATE), a("fadvise64", unix.SYS_FADVISE64),
	a("unlink", unix.SYS_UNLINK), a("unlinkat", unix.SYS_UNLINKAT), a("rename", unix.SYS_RENAME),
	a("renameat", unix.SYS_RENAMEAT), a("renameat2", unix.SYS_RENAMEAT2), a("mkdir", unix.SYS_MKDIR),
	a("mkdirat", unix.SYS_MKDIRAT), a("rmdir", unix.SYS_RMDIR), a("chmod", unix.SYS_CHMOD),
	a("fchmod", unix.SYS_FCHMOD), a("fchmodat", unix.SYS_FCHMODAT), a("utimensat", unix.SYS_UTIMENSAT),
	a("utime", unix.SYS_UTIME), a("utimes", unix.SYS_UTIMES), a("statfs", unix.SYS_STATFS),
	a("fstatfs", unix.SYS_FSTATFS), a("preadv", unix.SYS_PREADV), a("pwritev", unix.SYS_PWRITEV),
	a("preadv2", unix.SYS_PREADV2), a("pwritev2", unix.SYS_PWRITEV2), a("sendfile", unix.SYS_SENDFILE),
	a("copy_file_range", unix.SYS_COPY_FILE_RANGE), a("close_range", unix.SYS_CLOSE_RANGE),
	a("link", unix.SYS_LINK), a("linkat", unix.SYS_LINKAT), a("symlink", unix.SYS_SYMLINK),
	a("symlinkat", unix.SYS_SYMLINKAT), a("memfd_create", unix.SYS_MEMFD_CREATE),
	// pipes and event loops (no sockets: socket() is deliberately absent)
	a("pipe", unix.SYS_PIPE), a("pipe2", unix.SYS_PIPE2), a("poll", unix.SYS_POLL), a("ppoll", unix.SYS_PPOLL),
	a("select", unix.SYS_SELECT), a("pselect6", unix.SYS_PSELECT6), a("epoll_create", unix.SYS_EPOLL_CREATE),
	a("epoll_create1", unix.SYS_EPOLL_CREATE1), a("epoll_ctl", unix.SYS_EPOLL_CTL),
	a("epoll_wait", unix.SYS_EPOLL_WAIT), a("epoll_pwait", unix.SYS_EPOLL_PWAIT),
	a("eventfd", unix.SYS_EVENTFD), a("eventfd2", unix.SYS_EVENTFD2), a("timerfd_create", unix.SYS_TIMERFD_CREATE),
	a("timerfd_settime", unix.SYS_TIMERFD_SETTIME), a("timerfd_gettime", unix.SYS_TIMERFD_GETTIME),
	a("wait4", unix.SYS_WAIT4), a("waitid", unix.SYS_WAITID),
	a("execve", unix.SYS_EXECVE),
	// probes that glibc / runtimes handle by falling back; fail them rather than kill
	{Name: "clone3", Nr: unix.SYS_CLONE3, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "io_uring_setup", Nr: unix.SYS_IO_URING_SETUP, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "io_uring_enter", Nr: unix.SYS_IO_URING_ENTER, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "io_uring_register", Nr: unix.SYS_IO_URING_REGISTER, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "openat2", Nr: unix.SYS_OPENAT2, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "pkey_alloc", Nr: unix.SYS_PKEY_ALLOC, Kind: Errno, Errno: uint32(unix.ENOSYS)}, // V8 probes memory protection keys
	{Name: "pkey_mprotect", Nr: unix.SYS_PKEY_MPROTECT, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	{Name: "pkey_free", Nr: unix.SYS_PKEY_FREE, Kind: Errno, Errno: uint32(unix.ENOSYS)},
	// Local (AF_UNIX) sockets only: the JVM uses them internally. The network namespace is empty
	// anyway, but AF_INET/AF_INET6/AF_PACKET/AF_NETLINK are refused at the syscall layer too.
	{Name: "socket", Nr: unix.SYS_SOCKET, Kind: AllowArg0, Errno: uint32(unix.EAFNOSUPPORT), Values: []uint32{unix.AF_UNIX}},
	{Name: "socketpair", Nr: unix.SYS_SOCKETPAIR, Kind: AllowArg0, Errno: uint32(unix.EAFNOSUPPORT), Values: []uint32{unix.AF_UNIX}},
	a("connect", unix.SYS_CONNECT), a("getsockname", unix.SYS_GETSOCKNAME), a("getpeername", unix.SYS_GETPEERNAME),
	a("setsockopt", unix.SYS_SETSOCKOPT), a("getsockopt", unix.SYS_GETSOCKOPT), a("sendto", unix.SYS_SENDTO),
	a("recvfrom", unix.SYS_RECVFROM), a("sendmsg", unix.SYS_SENDMSG), a("recvmsg", unix.SYS_RECVMSG),
	a("shutdown", unix.SYS_SHUTDOWN),
	// argument-filtered
	{Name: "ioctl", Nr: unix.SYS_IOCTL, Kind: AllowArg1, Errno: uint32(unix.ENOTTY), Values: []uint32{
		unix.TCGETS, unix.TIOCGWINSZ, 0x541B, 0x5451, 0x5450, 0x5421, // FIONREAD, FIOCLEX, FIONCLEX, FIONBIO
		unix.TCGETA,
	}},
	{Name: "prctl", Nr: unix.SYS_PRCTL, Kind: AllowArg0, Errno: uint32(unix.EPERM), Values: []uint32{
		unix.PR_SET_NAME, unix.PR_GET_NAME, unix.PR_GET_DUMPABLE, unix.PR_SET_DUMPABLE, unix.PR_GET_TID_ADDRESS,
		unix.PR_SET_THP_DISABLE, unix.PR_GET_THP_DISABLE, unix.PR_SET_TIMERSLACK, 0x53564d41, // PR_SET_VMA (glibc names anon mappings)
	}},
}

// threadRules: run profile may create threads but not processes.
var runRules = append(append([]Rule{}, baseRules...),
	Rule{Name: "clone", Nr: unix.SYS_CLONE, Kind: CloneThreadOnly})

// toolchainRules: compilers fork/exec helper programs.
var toolchainRules = append(append([]Rule{}, baseRules...),
	Rule{Name: "clone", Nr: unix.SYS_CLONE, Kind: CloneNoNamespaces},
	a("fork", unix.SYS_FORK), a("vfork", unix.SYS_VFORK), a("kill", unix.SYS_KILL))

// PolicyFor returns the seccomp rules for a profile.
func PolicyFor(p Profile) []Rule {
	if p == ProfileToolchain {
		return toolchainRules
	}
	return runRules
}
