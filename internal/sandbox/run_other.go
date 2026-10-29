//go:build !linux

package sandbox

import "context"

// Runner is a stub on non-Linux platforms.
type Runner struct{}

// JobDir mirrors the Linux type so portable code compiles everywhere.
type JobDir struct{ Root, In, Out string }

func NewRunner(string) (*Runner, error)                    { return nil, ErrUnsupported }
func (*Runner) NewJobDir(int64) (*JobDir, error)           { return nil, ErrUnsupported }
func (*Runner) Run(context.Context, Spec) (*Result, error) { return nil, ErrUnsupported }
func (*JobDir) WriteSource(string, []byte) error           { return ErrUnsupported }
func (*JobDir) Cleanup()                                   {}
