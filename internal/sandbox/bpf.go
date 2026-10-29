package sandbox

// A tiny BPF "assembler" for seccomp filters. Portable so the program structure can be unit
// tested on any OS; installing the filter is Linux-only (seccomp_linux.go).

import "fmt"

// Seccomp return values and classic-BPF opcodes.
const (
	retKillProcess uint32 = 0x80000000
	retAllow       uint32 = 0x7fff0000
	retErrnoBase   uint32 = 0x00050000

	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJSET = 0x40
	bpfK    = 0x00
	bpfRET  = 0x06

	auditArchX8664 uint32 = 0xC000003E
	x32SyscallBit  uint32 = 0x40000000

	offNr   = 0
	offArch = 4
)

func offArgLow(i int) uint32 { return uint32(16 + 8*i) } // low 32 bits of syscall argument i (little endian)

// Instruction is one classic BPF instruction (struct sock_filter).
type Instruction struct {
	Code uint16
	Jt   uint8
	Jf   uint8
	K    uint32
}

func load(off uint32) Instruction             { return Instruction{bpfLD | bpfW | bpfABS, 0, 0, off} }
func ret(v uint32) Instruction                { return Instruction{bpfRET | bpfK, 0, 0, v} }
func jeq(k uint32, jt, jf uint8) Instruction  { return Instruction{bpfJMP | bpfJEQ | bpfK, jt, jf, k} }
func jset(k uint32, jt, jf uint8) Instruction { return Instruction{bpfJMP | bpfJSET | bpfK, jt, jf, k} }

// RuleKind says what to do when a syscall number matches.
type RuleKind int

const (
	// Allow permits the syscall unconditionally.
	Allow RuleKind = iota
	// Errno makes the syscall fail with Rule.Errno (used for probes such as clone3, which
	// glibc handles by falling back to clone).
	Errno
	// AllowArg0 / AllowArg1 permit the syscall only if the low 32 bits of that argument are in
	// Values; any other value fails with ENOTTY/EPERM-style Errno (ioctl, prctl filters).
	AllowArg0
	AllowArg1
	// CloneThreadOnly permits clone() only when CLONE_THREAD is set and no CLONE_NEW* flag is.
	CloneThreadOnly
	// CloneNoNamespaces permits clone() with any flags except CLONE_NEW* (process creation).
	CloneNoNamespaces
)

// Rule is one entry of a seccomp policy. Syscalls not listed are killed (SIGSYS).
type Rule struct {
	Name   string
	Nr     uint32
	Kind   RuleKind
	Errno  uint32
	Values []uint32
}

const (
	cloneThread     uint32 = 0x00010000
	cloneNewMask    uint32 = 0x02020000 | 0x04000000 | 0x08000000 | 0x10000000 | 0x20000000 | 0x40000000 // NS, CGROUP, UTS, IPC, USER, PID, NET
	cloneNewMaskAll        = cloneNewMask
)

// Compile assembles the rules into a BPF program: arch check, x32 rejection, then one
// self-contained block per rule (always ending in a return) so all jump offsets stay tiny and
// the accumulator still holds the syscall number when the next rule is tested.
func Compile(rules []Rule) ([]Instruction, error) {
	prog := []Instruction{
		load(offArch),
		jeq(auditArchX8664, 1, 0),
		ret(retKillProcess),
		load(offNr),
		jset(x32SyscallBit, 0, 1),
		ret(retKillProcess),
	}
	for _, r := range rules {
		blk, err := block(r)
		if err != nil {
			return nil, err
		}
		// First instruction of every block: if nr matches, fall into the block, else skip it.
		skip := len(blk)
		if skip > 255 {
			return nil, fmt.Errorf("rule %s too large", r.Name)
		}
		prog = append(prog, jeq(r.Nr, 0, uint8(skip)))
		prog = append(prog, blk...)
	}
	prog = append(prog, ret(retKillProcess))
	if len(prog) > 4096 {
		return nil, fmt.Errorf("seccomp program has %d instructions (max 4096)", len(prog))
	}
	return prog, nil
}

func block(r Rule) ([]Instruction, error) {
	switch r.Kind {
	case Allow:
		return []Instruction{ret(retAllow)}, nil
	case Errno:
		return []Instruction{ret(retErrnoBase | r.Errno)}, nil
	case AllowArg0, AllowArg1:
		arg := 0
		if r.Kind == AllowArg1 {
			arg = 1
		}
		b := []Instruction{load(offArgLow(arg))}
		for _, v := range r.Values {
			b = append(b, jeq(v, 0, 1), ret(retAllow))
		}
		return append(b, ret(retErrnoBase|r.Errno)), nil
	case CloneThreadOnly:
		return []Instruction{
			load(offArgLow(0)),
			jset(cloneNewMaskAll, 0, 1),
			ret(retKillProcess),
			jset(cloneThread, 0, 1),
			ret(retAllow),
			ret(retKillProcess),
		}, nil
	case CloneNoNamespaces:
		return []Instruction{
			load(offArgLow(0)),
			jset(cloneNewMaskAll, 0, 1),
			ret(retKillProcess),
			ret(retAllow),
		}, nil
	}
	return nil, fmt.Errorf("unknown rule kind %d", r.Kind)
}

// Eval interprets a program against a syscall number, arch and arg0/arg1 values. It exists so
// the policy can be unit tested on any OS without a kernel.
func Eval(prog []Instruction, arch, nr uint32, args [6]uint32) uint32 {
	var a uint32
	pc := 0
	for steps := 0; pc < len(prog) && steps < 100000; steps++ {
		in := prog[pc]
		switch in.Code {
		case bpfLD | bpfW | bpfABS:
			switch {
			case in.K == offArch:
				a = arch
			case in.K == offNr:
				a = nr
			case in.K >= 16 && (in.K-16)%8 == 0 && int((in.K-16)/8) < 6:
				a = args[(in.K-16)/8]
			default:
				a = 0
			}
			pc++
		case bpfJMP | bpfJEQ | bpfK:
			if a == in.K {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfJMP | bpfJSET | bpfK:
			if a&in.K != 0 {
				pc += 1 + int(in.Jt)
			} else {
				pc += 1 + int(in.Jf)
			}
		case bpfRET | bpfK:
			return in.K
		default:
			return retKillProcess
		}
	}
	return retKillProcess
}
