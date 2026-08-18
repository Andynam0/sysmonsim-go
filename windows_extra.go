//go:build windows

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func runDriverLoad(cfg config) error {
	if cfg.runHelper {
		return runHelperScript("prepare-event6-driver-load.ps1")
	}

	fmt.Println("Event 6 requires a real driver load and administrative context.")
	fmt.Println("Original SysmonSimulator guidance:")
	fmt.Println("  1. Open Windows Security > Virus & threat protection settings.")
	fmt.Println("  2. Disable Real-time protection.")
	fmt.Println("  3. Re-enable Real-time protection.")
	fmt.Println("This commonly reloads C:\\Windows\\System32\\drivers\\wd\\WdNisDrv.sys.")
	fmt.Println("To let sysmonsim-go attempt the same helper flow, run:")
	fmt.Println(`  sysmonsim-go.exe -e 6 --run-helper`)
	return nil
}

func runCreateRemoteThread(cfg config) error {
	if !cfg.dangerous {
		fmt.Println("Event 8 is intentionally gated.")
		fmt.Println("It performs remote-process memory allocation and CreateRemoteThread.")
		fmt.Println("Re-run with --dangerous to execute it.")
		if cfg.targetPID == 0 {
			fmt.Printf("Default target process: %s\n", cfg.targetProcess)
		} else {
			fmt.Printf("Target PID: %d\n", cfg.targetPID)
		}
		fmt.Printf("Default injected DLL: %s\n", cfg.injectDLL)
		return nil
	}

	loadLib := windows.NewLazySystemDLL("kernel32.dll").NewProc("LoadLibraryA")
	if err := loadLib.Find(); err != nil {
		return err
	}

	var proc windows.Handle
	var thread windows.Handle
	targetPID := uint32(cfg.targetPID)
	if targetPID == 0 {
		si := new(windows.StartupInfo)
		pi := new(windows.ProcessInformation)
		cmdline, err := windows.UTF16PtrFromString(cfg.targetProcess)
		if err != nil {
			return err
		}
		if err := windows.CreateProcess(nil, cmdline, nil, nil, false, windows.CREATE_SUSPENDED, nil, nil, si, pi); err != nil {
			return err
		}
		proc = pi.Process
		thread = pi.Thread
		targetPID = pi.ProcessId
		defer windows.TerminateProcess(proc, 0)
		defer windows.CloseHandle(thread)
	} else {
		handle, err := windows.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ, false, targetPID)
		if err != nil {
			return err
		}
		proc = handle
	}
	defer windows.CloseHandle(proc)

	dllBytes := append([]byte(cfg.injectDLL), 0)
	remoteMem, err := virtualAllocEx(proc, uintptr(len(dllBytes)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return err
	}
	defer func() { _ = virtualFreeEx(proc, remoteMem, 0, windows.MEM_RELEASE) }()

	var written uintptr
	if err := windows.WriteProcessMemory(proc, remoteMem, &dllBytes[0], uintptr(len(dllBytes)), &written); err != nil {
		return err
	}

	remoteThread, err := createRemoteThread(proc, loadLib.Addr(), remoteMem)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(remoteThread)

	_, err = windows.WaitForSingleObject(remoteThread, 5000)
	if err != nil {
		return err
	}

	if cfg.verbose {
		fmt.Printf("create-remote-thread target_pid=%d dll=%s bytes=%d\n", targetPID, cfg.injectDLL, written)
	}
	return nil
}

func runImageLoad(cfg config) error {
	handle, err := windows.LoadLibrary(cfg.libraryPath)
	if err != nil {
		return err
	}
	defer windows.FreeLibrary(handle)
	if cfg.verbose {
		fmt.Printf("image-load library=%s handle=%d\n", cfg.libraryPath, handle)
	}
	return nil
}

func runRawDiskRead(cfg config) error {
	path, err := syscall.UTF16PtrFromString(cfg.rawDiskPath)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(path, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)

	buffer := make([]byte, 4096)
	var read uint32
	if err := windows.ReadFile(handle, buffer, &read, nil); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	if cfg.verbose {
		fmt.Printf("raw-disk-read path=%s bytes=%d\n", cfg.rawDiskPath, read)
	}
	return nil
}

func runProcessAccess(cfg config) error {
	targetPID := uint32(cfg.targetPID)
	if targetPID == 0 {
		targetPID = uint32(os.Getpid())
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, targetPID)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	if cfg.verbose {
		fmt.Printf("process-access target_pid=%d handle=%d\n", targetPID, handle)
	}
	return nil
}

func runRegistryObjectCreateDelete(cfg config) error {
	root, err := registryHive(cfg.regHive)
	if err != nil {
		return err
	}
	key, _, err := registry.CreateKey(root, cfg.regKey, uint32(registry.CREATE_SUB_KEY|registry.SET_VALUE))
	if err != nil {
		return err
	}
	key.Close()
	if err := registry.DeleteKey(root, cfg.regKey); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("registry-create-delete hive=%s key=%s\n", cfg.regHive, cfg.regKey)
	}
	return nil
}

func runRegistryRename(cfg config) error {
	parentPath, oldName := splitRegistryParent(cfg.regKey)
	if oldName == "" {
		return errors.New("registry-key must contain at least one path component")
	}
	newName := oldName + "_renamed"

	_, err := exec.Command("reg.exe", "add", fmt.Sprintf(`%s\%s`, normalizeHive(cfg.regHive), cfg.regKey), "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create source key for rename: %w", err)
	}

	output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", buildRegistryRenamePS(normalizeHive(cfg.regHive), parentPath, oldName, newName)).CombinedOutput()
	if err != nil {
		return fmt.Errorf("registry rename failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if cfg.verbose {
		fmt.Printf("registry-rename hive=%s old=%s new=%s\n", cfg.regHive, cfg.regKey, filepath.Join(parentPath, newName))
	}
	return nil
}

func runAlternateDataStreamWrite(cfg config) error {
	if err := ensureSeedFile(cfg.path, cfg.content); err != nil {
		return err
	}
	streamPath := fmt.Sprintf("%s:%s", cfg.path, cfg.adsName)
	if err := os.WriteFile(streamPath, []byte(cfg.content+"\r\n"), 0o644); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("ads-write path=%s stream=%s\n", cfg.path, cfg.adsName)
	}
	return nil
}

func runServiceConfigChange(cfg config) error {
	createCmd := exec.Command("sc.exe", "create", cfg.serviceName, "binPath=", cfg.serviceBinPath, "DisplayName=", cfg.serviceDisplay, "start=", "demand")
	if output, err := createCmd.CombinedOutput(); err != nil && !strings.Contains(strings.ToLower(string(output)), "already exists") {
		return fmt.Errorf("service create failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	configCmd := exec.Command("sc.exe", "config", cfg.serviceName, "binPath=", cfg.serviceBinPath, "DisplayName=", cfg.serviceDisplay, "start=", "auto")
	output, err := configCmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("service config failed: %v: %s", err, strings.TrimSpace(string(output)))
	}

	_, _ = exec.Command("sc.exe", "delete", cfg.serviceName).CombinedOutput()
	if cfg.verbose {
		fmt.Printf("service-config service=%s\n", cfg.serviceName)
	}
	return nil
}

func runNamedPipeCreate(cfg config) error {
	name, err := syscall.UTF16PtrFromString(cfg.pipeName)
	if err != nil {
		return err
	}
	handle, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	time.Sleep(500 * time.Millisecond)
	if cfg.verbose {
		fmt.Printf("pipe-create name=%s\n", cfg.pipeName)
	}
	return nil
}

func runNamedPipeConnect(cfg config) error {
	name, err := syscall.UTF16PtrFromString(cfg.pipeName)
	if err != nil {
		return err
	}

	server, err := windows.CreateNamedPipe(name, windows.PIPE_ACCESS_DUPLEX, windows.PIPE_TYPE_BYTE|windows.PIPE_WAIT, 1, 4096, 4096, 0, nil)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(server)

	errCh := make(chan error, 1)
	go func() {
		errCh <- windows.ConnectNamedPipe(server, nil)
	}()

	time.Sleep(200 * time.Millisecond)
	client, err := windows.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(client)

	connectErr := <-errCh
	if connectErr != nil && connectErr != windows.ERROR_PIPE_CONNECTED {
		return connectErr
	}

	message := []byte("sysmonsim-go")
	var written uint32
	if err := windows.WriteFile(client, message, &written, nil); err != nil {
		return err
	}
	if cfg.verbose {
		fmt.Printf("pipe-connect name=%s bytes=%d\n", cfg.pipeName, written)
	}
	return nil
}

func runWMIEvent(cfg config) error {
	ps := fmt.Sprintf(`Get-WmiObject -Namespace '%s' -Class Win32_Process | Out-Null; Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList '%s' | Out-Null`, escapePS(cfg.wmiNamespace), escapePS(cfg.wmiCommand))
	output, err := exec.Command("powershell.exe", "-NoProfile", "-Command", ps).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wmi execution failed: %v: %s", err, strings.TrimSpace(string(output)))
	}
	if cfg.verbose {
		fmt.Printf("wmi-event namespace=%s command=%s\n", cfg.wmiNamespace, cfg.wmiCommand)
	}
	return nil
}

var (
	user32            = windows.NewLazySystemDLL("user32.dll")
	kernel32          = windows.NewLazySystemDLL("kernel32.dll")
	procVirtualAllocEx = kernel32.NewProc("VirtualAllocEx")
	procVirtualFreeEx  = kernel32.NewProc("VirtualFreeEx")
	procCreateRemoteThreadK32 = kernel32.NewProc("CreateRemoteThread")
	procOpenClipboard = user32.NewProc("OpenClipboard")
	procEmptyClipboard = user32.NewProc("EmptyClipboard")
	procSetClipboardData = user32.NewProc("SetClipboardData")
	procCloseClipboard = user32.NewProc("CloseClipboard")
	procGlobalAlloc   = kernel32.NewProc("GlobalAlloc")
	procGlobalLock    = kernel32.NewProc("GlobalLock")
	procGlobalUnlock  = kernel32.NewProc("GlobalUnlock")
)

const (
	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

func runClipboardSet(cfg config) error {
	text := syscall.StringToUTF16(cfg.clipboardText)
	size := uintptr(len(text) * 2)

	r1, _, err := procOpenClipboard.Call(0)
	if r1 == 0 {
		return err
	}
	defer procCloseClipboard.Call()

	procEmptyClipboard.Call()
	mem, _, err := procGlobalAlloc.Call(gmemMoveable, size)
	if mem == 0 {
		return err
	}
	ptr, _, err := procGlobalLock.Call(mem)
	if ptr == 0 {
		return err
	}

	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(text))
	copy(dst, text)
	procGlobalUnlock.Call(mem)

	r1, _, err = procSetClipboardData.Call(cfUnicodeText, mem)
	if r1 == 0 {
		return err
	}
	if cfg.verbose {
		fmt.Printf("clipboard-set text=%q\n", cfg.clipboardText)
	}
	return nil
}

func runProcessTamper(cfg config) error {
	if cfg.runHelper {
		return runHelperScript("prepare-event25-process-tamper.ps1")
	}

	fmt.Println("Event 25 usually needs a real process-hollowing or image-replacement style action.")
	fmt.Println("This is not run by default.")
	fmt.Printf("Suggested lab pair: source=%s target=%s\n", cfg.tamperSource, cfg.tamperTarget)
	fmt.Println("To stage the lab helper and view prerequisites, run:")
	fmt.Println(`  sysmonsim-go.exe -e 25 --run-helper`)
	return nil
}

func runHelperScript(name string) error {
	exePath, err := os.Executable()
	if err != nil {
		return err
	}
	helperPath := filepath.Join(filepath.Dir(exePath), "helpers", name)
	if _, err := os.Stat(helperPath); err != nil {
		return fmt.Errorf("helper script not found at %s", helperPath)
	}
	cmd := exec.Command("powershell.exe", "-ExecutionPolicy", "Bypass", "-File", helperPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func virtualAllocEx(process windows.Handle, size uintptr, allocationType uint32, protect uint32) (uintptr, error) {
	addr, _, callErr := procVirtualAllocEx.Call(
		uintptr(process),
		0,
		size,
		uintptr(allocationType),
		uintptr(protect),
	)
	if addr == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, windows.GetLastError()
	}
	return addr, nil
}

func virtualFreeEx(process windows.Handle, address uintptr, size uintptr, freeType uint32) error {
	result, _, callErr := procVirtualFreeEx.Call(
		uintptr(process),
		address,
		size,
		uintptr(freeType),
	)
	if result == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return callErr
		}
		return windows.GetLastError()
	}
	return nil
}

func createRemoteThread(process windows.Handle, startAddress uintptr, parameter uintptr) (windows.Handle, error) {
	thread, _, callErr := procCreateRemoteThreadK32.Call(
		uintptr(process),
		0,
		0,
		startAddress,
		parameter,
		0,
		0,
	)
	if thread == 0 {
		if callErr != nil && callErr != syscall.Errno(0) {
			return 0, callErr
		}
		return 0, windows.GetLastError()
	}
	return windows.Handle(thread), nil
}

func buildRegistryRenamePS(hive string, parentPath string, oldName string, newName string) string {
	parent := escapePS(parentPath)
	oldPart := escapePS(oldName)
	newPart := escapePS(newName)
	return fmt.Sprintf(`$base='%s'; $parent='%s'; $old='%s'; $new='%s'; $root=[Microsoft.Win32.Registry]::CurrentUser; if ($base -eq 'HKEY_LOCAL_MACHINE') { $root=[Microsoft.Win32.Registry]::LocalMachine }; $p=$root.OpenSubKey($parent,$true); if (-not $p) { throw 'parent key not found' }; $child=$p.OpenSubKey($old); if (-not $child) { throw 'source key not found' }; $dest=$p.CreateSubKey($new); foreach ($n in $child.GetValueNames()) { $dest.SetValue($n,$child.GetValue($n),$child.GetValueKind($n)) }; $p.DeleteSubKeyTree($old);`, hive, parent, oldPart, newPart)
}

func splitRegistryParent(path string) (string, string) {
	path = strings.Trim(path, `\`)
	idx := strings.LastIndex(path, `\`)
	if idx == -1 {
		return "", path
	}
	return path[:idx], path[idx+1:]
}

func normalizeHive(hive string) string {
	switch strings.ToUpper(strings.TrimSpace(hive)) {
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return "HKEY_LOCAL_MACHINE"
	default:
		return "HKEY_CURRENT_USER"
	}
}

func escapePS(value string) string {
	return strings.ReplaceAll(value, `'`, `''`)
}
