//go:build linux

package sandbox

// Child side of the sandbox. The runner re-executes this very binary ("/proc/self/exe
// __sandbox_init") inside fresh user/mount/pid/net/uts/ipc/cgroup namespaces. This code runs as
// PID 1 of the new PID namespace with full capabilities *inside* the user namespace, builds the
// filesystem jail, then irreversibly drops privileges and execve()s the untrusted program:
//
//	mounts -> pivot_root -> rlimits -> drop capabilities -> uid 1000 -> no_new_privs + seccomp -> execve

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const initArg = "__sandbox_init"

const sandboxUID = 1000

// childConfig is passed to the child as JSON in an environment variable.
type childConfig struct {
	Argv           []string
	Env            []string
	Cwd            string
	Profile        Profile
	Limits         limitsJSON
	RootDir        string
	Mounts         []Mount
	DisableSeccomp bool
}

type limitsJSON struct {
	CPUSeconds    int64
	FileSizeBytes int64
	OpenFiles     int64
	StackBytes    int64
	TmpfsBytes    int64
}

func init() {
	if len(os.Args) > 1 && os.Args[1] == initArg {
		runtime.LockOSThread() // seccomp and execve must happen on one thread
		err := childMain()
		reportSetupError(err)
		os.Exit(125)
	}
}

func reportSetupError(err error) {
	if f := os.NewFile(3, "setup-pipe"); f != nil && err != nil {
		_, _ = f.WriteString(err.Error())
	}
}

func childMain() error {
	var cfg childConfig
	if err := json.Unmarshal([]byte(os.Getenv("SANDBOX_CONFIG")), &cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	// fd 3 reports setup failures to the parent; it closes on execve so success reads as EOF.
	if _, err := unix.FcntlInt(3, unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		return fmt.Errorf("cloexec: %w", err)
	}
	if err := unix.Sethostname([]byte("sandbox")); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	if err := setupFilesystem(&cfg); err != nil {
		return fmt.Errorf("filesystem: %w", err)
	}
	if err := applyRlimits(&cfg); err != nil {
		return fmt.Errorf("rlimits: %w", err)
	}
	if err := unix.Chdir(cfg.Cwd); err != nil {
		return fmt.Errorf("chdir %s: %w", cfg.Cwd, err)
	}
	if err := dropPrivileges(); err != nil {
		return fmt.Errorf("drop privileges: %w", err)
	}
	if !cfg.DisableSeccomp {
		if err := installSeccomp(cfg.Profile); err != nil {
			return err
		}
	}
	argv0 := cfg.Argv[0]
	if err := syscall.Exec(argv0, cfg.Argv, cfg.Env); err != nil {
		return fmt.Errorf("exec %s: %w", argv0, err)
	}
	return nil
}

// ---- filesystem -------------------------------------------------------------------------

func mkdirAll(p string) error { return os.MkdirAll(p, 0o755) }

// bind mounts src onto dst. Read-only is applied with a second remount that preserves the
// flags inherited from the source mount (required inside a user namespace, where inherited
// nosuid/nodev/noexec flags are locked and cannot be cleared).
func bind(root, src, dst string, rw, exec bool) error {
	target := filepath.Join(root, dst)
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.IsDir() {
		err = mkdirAll(target)
	} else {
		if err = mkdirAll(filepath.Dir(target)); err == nil {
			var f *os.File
			f, err = os.OpenFile(target, os.O_CREATE|os.O_WRONLY, 0o644)
			if err == nil {
				f.Close()
			}
		}
	}
	if err != nil {
		return err
	}
	if err := unix.Mount(src, target, "", unix.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind %s -> %s: %w", src, dst, err)
	}
	var sfs unix.Statfs_t
	if err := unix.Statfs(target, &sfs); err != nil {
		return err
	}
	keep := uintptr(sfs.Flags) & (unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC | unix.MS_NOATIME | unix.MS_NODIRATIME | unix.MS_RELATIME)
	flags := uintptr(unix.MS_BIND|unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV) | keep
	if !rw {
		flags |= unix.MS_RDONLY
	}
	if !exec {
		flags |= unix.MS_NOEXEC
	} else {
		flags &^= unix.MS_NOEXEC
	}
	if err := unix.Mount("", target, "", flags, ""); err != nil {
		return fmt.Errorf("remount %s: %w", dst, err)
	}
	return nil
}

func tmpfs(root, dst string, size int64, mode string, flags uintptr) error {
	target := filepath.Join(root, dst)
	if err := mkdirAll(target); err != nil {
		return err
	}
	opts := fmt.Sprintf("size=%d,mode=%s", size, mode)
	if err := unix.Mount("tmpfs", target, "tmpfs", flags|unix.MS_NOSUID|unix.MS_NODEV, opts); err != nil {
		return fmt.Errorf("tmpfs %s: %w", dst, err)
	}
	return nil
}

func setupFilesystem(cfg *childConfig) error {
	// Mount changes must not propagate back to the host namespace.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	root := cfg.RootDir
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size=4m,mode=755"); err != nil {
		return fmt.Errorf("root tmpfs: %w", err)
	}
	// Merged-/usr systems: /bin, /lib, ... are symlinks into /usr; recreate them.
	for _, name := range []string{"bin", "sbin", "lib", "lib64", "lib32"} {
		if dest, err := os.Readlink("/" + name); err == nil {
			if err := os.Symlink(dest, filepath.Join(root, name)); err != nil {
				return err
			}
		}
	}
	if err := bind(root, "/usr", "/usr", false, true); err != nil {
		return err
	}
	// A minimal /etc: a tmpfs holding just enough for getpwuid() and friends, plus read-only
	// binds of the few host paths toolchains need (dynamic loader cache, alternatives symlinks,
	// JDK config). It is remounted read-only once populated.
	if err := tmpfs(root, "/etc", 1<<20, "755", 0); err != nil {
		return err
	}
	files := map[string]string{
		"passwd": fmt.Sprintf("root:x:0:0:root:/nonexistent:/bin/false\nsandbox:x:%d:%d::/work:/bin/false\n", sandboxUID, sandboxUID),
		"group":  fmt.Sprintf("root:x:0:\nsandbox:x:%d:\n", sandboxUID),
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(root, "etc", name), []byte(content), 0o644); err != nil {
			return err
		}
	}
	hostEtc := []string{"/etc/alternatives", "/etc/ld.so.cache"}
	if matches, _ := filepath.Glob("/etc/java-*"); len(matches) > 0 {
		hostEtc = append(hostEtc, matches...)
	}
	for _, p := range hostEtc {
		if _, err := os.Stat(p); err == nil {
			if err := bind(root, p, p, false, true); err != nil {
				return err
			}
		}
	}
	if err := unix.Mount("", filepath.Join(root, "etc"), "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("etc read-only: %w", err)
	}

	// /dev: tmpfs plus the handful of harmless device nodes, bind-mounted from the host.
	if err := tmpfs(root, "/dev", 64<<10, "755", unix.MS_NOEXEC); err != nil {
		return err
	}
	for _, dev := range []string{"null", "zero", "urandom", "random"} {
		if err := bind(root, "/dev/"+dev, "/dev/"+dev, true, false); err != nil {
			return err
		}
	}
	if err := mkdirAll(filepath.Join(root, "proc")); err != nil {
		return err
	}
	if err := unix.Mount("proc", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	size := cfg.Limits.TmpfsBytes
	if err := tmpfs(root, "/tmp", size, "1777", unix.MS_NOSUID); err != nil {
		return err
	}
	if err := tmpfs(root, "/work", size, "0777", 0); err != nil { // exec allowed: scratch binaries
		return err
	}
	for _, m := range cfg.Mounts {
		if err := bind(root, m.Source, m.Target, m.ReadWrite, m.Exec); err != nil {
			return err
		}
	}

	// pivot_root(".", "."): the old root is stacked under the new one, then detached, leaving
	// no path back to the host filesystem.
	oldRoot, err := unix.Open("/", unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		return err
	}
	if err := unix.Chdir(root); err != nil {
		return err
	}
	if err := unix.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Fchdir(oldRoot); err != nil {
		return err
	}
	if err := unix.Mount("", ".", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
		return fmt.Errorf("slave old root: %w", err)
	}
	if err := unix.Unmount(".", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	_ = unix.Close(oldRoot)
	return unix.Chdir("/")
}

// ---- rlimits and privileges --------------------------------------------------------------

func applyRlimits(cfg *childConfig) error {
	set := func(res int, v uint64) error {
		return unix.Setrlimit(res, &unix.Rlimit{Cur: v, Max: v})
	}
	l := cfg.Limits
	for _, s := range []struct {
		res int
		v   uint64
	}{
		{unix.RLIMIT_CPU, uint64(l.CPUSeconds)},
		{unix.RLIMIT_FSIZE, uint64(l.FileSizeBytes)},
		{unix.RLIMIT_NOFILE, uint64(l.OpenFiles)},
		{unix.RLIMIT_STACK, uint64(l.StackBytes)},
		{unix.RLIMIT_CORE, 0},
	} {
		if err := set(s.res, s.v); err != nil {
			return fmt.Errorf("rlimit %d: %w", s.res, err)
		}
	}
	return nil
}

func dropPrivileges() error {
	// Empty the bounding set, then become an ordinary user; execve then clears the rest.
	for c := 0; c <= 40; c++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(c), 0, 0, 0); err != nil && err != unix.EINVAL {
			return fmt.Errorf("capbset drop %d: %w", c, err)
		}
	}
	if err := syscall.Setresgid(sandboxUID, sandboxUID, sandboxUID); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(sandboxUID, sandboxUID, sandboxUID); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	return nil
}

func envFor(extra []string) []string {
	env := []string{"PATH=/usr/bin:/bin", "HOME=/work", "TMPDIR=/tmp", "LANG=C.UTF-8", "PYTHONDONTWRITEBYTECODE=1"}
	for _, e := range extra {
		if !strings.HasPrefix(e, "SANDBOX_") {
			env = append(env, e)
		}
	}
	return env
}
