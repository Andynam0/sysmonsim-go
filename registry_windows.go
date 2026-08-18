//go:build windows

package main

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func runRegistrySet(cfg config) error {
	root, err := registryHive(cfg.regHive)
	if err != nil {
		return err
	}

	access := uint32(registry.SET_VALUE)
	if cfg.regCreateKey {
		access |= uint32(registry.CREATE_SUB_KEY)
	}

	var key registry.Key
	if cfg.regCreateKey {
		key, _, err = registry.CreateKey(root, cfg.regKey, access)
	} else {
		key, err = registry.OpenKey(root, cfg.regKey, access)
	}
	if err != nil {
		return err
	}
	defer key.Close()

	switch cfg.regValueType {
	case "string":
		err = key.SetStringValue(cfg.regValueName, cfg.regStringData)
	case "dword":
		err = key.SetDWordValue(cfg.regValueName, uint32(cfg.regDwordData))
	case "qword":
		err = key.SetQWordValue(cfg.regValueName, cfg.regQwordData)
	default:
		err = fmt.Errorf("unsupported registry value type %q", cfg.regValueType)
	}
	if err != nil {
		return err
	}

	if cfg.verbose {
		fmt.Printf("registry hive=%s key=%s value=%s type=%s\n", cfg.regHive, cfg.regKey, cfg.regValueName, cfg.regValueType)
	}
	return nil
}

func registryHive(name string) (registry.Key, error) {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER, nil
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE, nil
	default:
		return 0, fmt.Errorf("unsupported registry hive %q", name)
	}
}
