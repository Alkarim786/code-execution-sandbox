//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("bench requires Linux and root; run it in the privileged container (see README)")
}
