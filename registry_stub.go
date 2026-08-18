//go:build !windows

package main

import "errors"

func runRegistrySet(cfg config) error {
	return errors.New("registry-set is only supported on Windows")
}
