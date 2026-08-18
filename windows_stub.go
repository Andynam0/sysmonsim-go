//go:build !windows

package main

import "errors"

func runImageLoad(cfg config) error                 { return errors.New("event 7 is only supported on Windows") }
func runDriverLoad(cfg config) error                { return errors.New("event 6 is only supported on Windows") }
func runCreateRemoteThread(cfg config) error        { return errors.New("event 8 is only supported on Windows") }
func runRawDiskRead(cfg config) error               { return errors.New("event 9 is only supported on Windows") }
func runProcessAccess(cfg config) error             { return errors.New("event 10 is only supported on Windows") }
func runRegistryObjectCreateDelete(cfg config) error { return errors.New("event 12 is only supported on Windows") }
func runRegistryRename(cfg config) error            { return errors.New("event 14 is only supported on Windows") }
func runAlternateDataStreamWrite(cfg config) error  { return errors.New("event 15 is only supported on Windows") }
func runServiceConfigChange(cfg config) error       { return errors.New("event 16 is only supported on Windows") }
func runNamedPipeCreate(cfg config) error           { return errors.New("event 17 is only supported on Windows") }
func runNamedPipeConnect(cfg config) error          { return errors.New("event 18 is only supported on Windows") }
func runWMIEvent(cfg config) error                  { return errors.New("events 19-21 are only supported on Windows") }
func runClipboardSet(cfg config) error              { return errors.New("event 24 is only supported on Windows") }
func runProcessTamper(cfg config) error             { return errors.New("event 25 is only supported on Windows") }
