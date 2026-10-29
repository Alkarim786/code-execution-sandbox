//go:build linux && !amd64

package sandbox

import "fmt"

func installSeccomp(Profile) error {
	return fmt.Errorf("seccomp policy is only implemented for linux/amd64")
}
