package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func runEvent(cfg config) error {
	if cfg.verbose {
		fmt.Printf("event=%d (%s)\n", cfg.eventID, eventName(cfg.eventID))
	}

	switch cfg.eventID {
	case 1:
		return runProcessCreate(cfg)
	case 2:
		return runFileTimeChange(cfg)
	case 3:
		return runTCPConnect(cfg)
	case 5:
		return runProcessTerminate(cfg)
	case 6:
		return runDriverLoad(cfg)
	case 7:
		return runImageLoad(cfg)
	case 8:
		return runCreateRemoteThread(cfg)
	case 9:
		return runRawDiskRead(cfg)
	case 10:
		return runProcessAccess(cfg)
	case 11:
		return runFileCreate(cfg)
	case 12:
		return runRegistryObjectCreateDelete(cfg)
	case 13:
		return runRegistrySet(cfg)
	case 14:
		return runRegistryRename(cfg)
	case 15:
		return runAlternateDataStreamWrite(cfg)
	case 16:
		return runServiceConfigChange(cfg)
	case 17:
		return runNamedPipeCreate(cfg)
	case 18:
		return runNamedPipeConnect(cfg)
	case 19, 20, 21:
		return runWMIEvent(cfg)
	case 22:
		return runDNS(cfg)
	case 24:
		return runClipboardSet(cfg)
	case 25:
		return runProcessTamper(cfg)
	case 26:
		return runFileDelete(cfg)
	default:
		return fmt.Errorf("invalid Sysmon ID %d", cfg.eventID)
	}
}

func runDNS(cfg config) error {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout)
	defer cancel()

	addresses, err := net.DefaultResolver.LookupHost(ctx, cfg.domain)
	if err != nil {
		return err
	}

	if cfg.verbose {
		fmt.Printf("dns domain=%s addresses=%v\n", cfg.domain, addresses)
	}
	return nil
}

func runTCPConnect(cfg config) error {
	dialer := net.Dialer{Timeout: cfg.timeout}
	target := fmt.Sprintf("%s:%d", cfg.host, cfg.port)
	conn, err := dialer.Dial("tcp", target)
	if err != nil {
		return err
	}
	defer conn.Close()

	if cfg.verbose {
		fmt.Printf("tcp target=%s local=%s remote=%s\n", target, conn.LocalAddr(), conn.RemoteAddr())
	}
	return nil
}

func runFileCreate(cfg config) error {
	if err := os.MkdirAll(filepath.Dir(cfg.path), 0o755); err != nil {
		return err
	}

	var file *os.File
	var err error
	if cfg.appendFile {
		file, err = os.OpenFile(cfg.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	} else {
		file, err = os.OpenFile(cfg.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	}
	if err != nil {
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(cfg.content); err != nil {
		return err
	}
	if _, err := file.WriteString("\r\n"); err != nil {
		return err
	}

	if cfg.verbose {
		fmt.Printf("file-create path=%s bytes=%d append=%t\n", cfg.path, len(cfg.content), cfg.appendFile)
	}
	return nil
}

func runFileTimeChange(cfg config) error {
	if err := ensureSeedFile(cfg.path, cfg.content); err != nil {
		return err
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(cfg.path, past, past); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("file-time-change path=%s mtime=%s\n", cfg.path, past.UTC().Format(time.RFC3339))
	}
	return nil
}

func runFileDelete(cfg config) error {
	if err := ensureSeedFile(cfg.path, cfg.content); err != nil {
		return err
	}
	if err := os.Remove(cfg.path); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("file-delete path=%s\n", cfg.path)
	}
	return nil
}

func runProcessCreate(cfg config) error {
	cmd := exec.Command(cfg.command, cfg.commandArgs...)
	if cfg.waitForExit {
		output, err := cmd.CombinedOutput()
		if cfg.verbose && len(output) > 0 {
			fmt.Printf("process output=%s\n", string(output))
		}
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("process-create pid=%d command=%s\n", cmd.Process.Pid, cfg.command)
	}
	return nil
}

func runProcessTerminate(cfg config) error {
	args := cfg.commandArgs
	if len(args) == 0 {
		if strings.EqualFold(cfg.command, "cmd.exe") || strings.EqualFold(cfg.command, "cmd") {
			args = []string{"/c", "ping 127.0.0.1 -n 30 > nul"}
		} else {
			args = []string{"/c", "ping", "127.0.0.1", "-n", "30"}
		}
	}
	cmd := exec.Command(cfg.command, args...)
	if err := cmd.Start(); err != nil {
		return err
	}
	doneCh := make(chan error, 1)
	go func() {
		doneCh <- cmd.Wait()
	}()
	time.Sleep(cfg.killAfter)

	select {
	case <-doneCh:
		if cfg.verbose {
			fmt.Printf("process-terminate pid=%d exited_before_kill=true\n", cmd.Process.Pid)
		}
		return nil
	default:
	}

	if err := cmd.Process.Kill(); err != nil {
		return err
	}
	<-doneCh
	if cfg.verbose {
		fmt.Printf("process-terminate pid=%d kill_after=%s\n", cmd.Process.Pid, cfg.killAfter)
	}
	return nil
}

func ensureSeedFile(path string, content string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(content+"\r\n"), 0o644)
}
