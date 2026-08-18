package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type config struct {
	eventID         int
	count           int
	sleep           time.Duration
	verbose         bool
	dangerous       bool
	runHelper       bool
	domain          string
	host            string
	port            int
	timeout         time.Duration
	path            string
	content         string
	appendFile      bool
	command         string
	commandArgs     []string
	waitForExit     bool
	killAfter       time.Duration
	regHive         string
	regKey          string
	regValueName    string
	regValueType    string
	regStringData   string
	regDwordData    uint
	regQwordData    uint64
	regCreateKey    bool
	adsName         string
	pipeName        string
	serviceName     string
	serviceBinPath  string
	serviceDisplay  string
	clipboardText   string
	libraryPath     string
	rawDiskPath     string
	targetPID       int
	targetProcess   string
	injectDLL       string
	wmiCommand      string
	wmiNamespace    string
	tamperTarget    string
	tamperSource    string
}

func main() {
	cfg, helpText, err := parseFlags(normalizeArgs(os.Args[1:]))
	if err != nil {
		if err == flag.ErrHelp {
			fmt.Println(usageText(helpText))
			return
		}
		exitf("%v\n\n%s", err, usageText(helpText))
	}
	applyEventDefaults(&cfg)

	if err := validateConfig(cfg); err != nil {
		exitf("%v\n\n%s", err, usageText(helpText))
	}

	if cfg.verbose {
		fmt.Printf("event_id=%d count=%d sleep=%s\n", cfg.eventID, cfg.count, cfg.sleep)
	}

	for i := 0; i < cfg.count; i++ {
		if cfg.verbose {
			fmt.Printf("run=%d/%d\n", i+1, cfg.count)
		}

		if err := runEvent(cfg); err != nil {
			exitf("event %d failed: %v", cfg.eventID, err)
		}

		if i < cfg.count-1 && cfg.sleep > 0 {
			time.Sleep(cfg.sleep)
		}
	}
}

func parseFlags(args []string) (config, string, error) {
	fs := flag.NewFlagSet("sysmonsim-go", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {}

	var cfg config
	var sleepMS int
	var timeoutMS int
	var killAfterMS int
	var commandArgs string

	fs.IntVar(&cfg.eventID, "e", 0, "Sysmon event ID to simulate")
	fs.IntVar(&cfg.eventID, "event-id", 0, "Sysmon event ID to simulate")
	fs.IntVar(&cfg.count, "count", 1, "How many times to run the event")
	fs.IntVar(&sleepMS, "sleep-ms", 0, "Delay between repeated runs in milliseconds")
	fs.BoolVar(&cfg.verbose, "verbose", false, "Print extra execution details")
	fs.BoolVar(&cfg.dangerous, "dangerous", false, "Allow invasive event implementations such as CreateRemoteThread")
	fs.BoolVar(&cfg.runHelper, "run-helper", false, "Run a helper PowerShell script when the event uses guided/manual simulation")

	fs.StringVar(&cfg.domain, "domain", "example.org", "Domain for DNS query tests")
	fs.StringVar(&cfg.host, "host", "example.org", "Host for network connection tests")
	fs.IntVar(&cfg.port, "port", 443, "Port for network connection tests")
	fs.IntVar(&timeoutMS, "timeout-ms", 5000, "Timeout for network operations in milliseconds")

	fs.StringVar(&cfg.path, "path", "", "Filesystem path for file-backed events")
	fs.StringVar(&cfg.content, "content", "sysmonsim-go test artifact", "Content written by file-backed events")
	fs.BoolVar(&cfg.appendFile, "append", false, "Append to an existing file instead of truncating it")
	fs.StringVar(&cfg.adsName, "ads-name", "Zone.Identifier", "Alternate data stream name for event 15")

	fs.StringVar(&cfg.command, "command", "cmd.exe", "Command used by process creation or WMI-backed process creation")
	fs.StringVar(&commandArgs, "command-args", "/c echo sysmonsim-go", "Quoted argument string for process creation")
	fs.BoolVar(&cfg.waitForExit, "wait", true, "Wait for the child process to exit")
	fs.IntVar(&killAfterMS, "kill-after-ms", 2500, "How long event 5 waits before terminating a child process")

	fs.StringVar(&cfg.regHive, "registry-hive", "HKCU", "Registry hive for registry tests: HKCU or HKLM")
	fs.StringVar(&cfg.regKey, "registry-key", `Software\sysmonsim-go`, "Registry key path for registry tests")
	fs.StringVar(&cfg.regValueName, "registry-value-name", "TestValue", "Registry value name for registry tests")
	fs.StringVar(&cfg.regValueType, "registry-value-type", "string", "Registry value type: string, dword, qword")
	fs.StringVar(&cfg.regStringData, "registry-string-data", "sysmonsim-go", "String value data for registry tests")
	fs.UintVar(&cfg.regDwordData, "registry-dword-data", 1, "DWORD value data for registry tests")
	fs.Uint64Var(&cfg.regQwordData, "registry-qword-data", 1, "QWORD value data for registry tests")
	fs.BoolVar(&cfg.regCreateKey, "registry-create-key", true, "Create the registry key if it does not exist")

	fs.StringVar(&cfg.pipeName, "pipe-name", `\\.\pipe\sysmonsim-go`, "Named pipe path for events 17 and 18")
	fs.StringVar(&cfg.serviceName, "service-name", "sysmonsim-go", "Service name for event 16")
	fs.StringVar(&cfg.serviceDisplay, "service-display-name", "sysmonsim-go test service", "Service display name for event 16")
	fs.StringVar(&cfg.serviceBinPath, "service-bin-path", `C:\Windows\System32\cmd.exe /c exit 0`, "Service binary path for event 16")
	fs.StringVar(&cfg.clipboardText, "clipboard-text", "sysmonsim-go clipboard test", "Text placed into the clipboard for event 24")
	fs.StringVar(&cfg.libraryPath, "library-path", `C:\Windows\System32\kernel32.dll`, "DLL path for event 7")
	fs.StringVar(&cfg.rawDiskPath, "raw-disk-path", `\\.\PhysicalDrive0`, "Raw disk path for event 9")
	fs.IntVar(&cfg.targetPID, "target-pid", 0, "Target PID for event 10")
	fs.StringVar(&cfg.targetProcess, "target-process", `C:\Windows\System32\PING.exe`, "Target process path for event 8 when no --target-pid is provided")
	fs.StringVar(&cfg.injectDLL, "inject-dll", `C:\Windows\System32\user32.dll`, "DLL path used by event 8 LoadLibrary-style remote thread injection")
	fs.StringVar(&cfg.wmiCommand, "wmi-command", "cmd.exe /c echo sysmonsim-go", "Command line for WMI event simulations")
	fs.StringVar(&cfg.wmiNamespace, "wmi-namespace", `root\cimv2`, "WMI namespace for events 19, 20, and 21")
	fs.StringVar(&cfg.tamperTarget, "tamper-target", `C:\Windows\System32\svchost.exe`, "Target image path for event 25 guidance")
	fs.StringVar(&cfg.tamperSource, "tamper-source", `C:\Windows\System32\cmd.exe`, "Source image path for event 25 guidance")

	if err := fs.Parse(args); err != nil {
		return cfg, renderFlagDefaults(fs), err
	}

	cfg.sleep = time.Duration(sleepMS) * time.Millisecond
	cfg.timeout = time.Duration(timeoutMS) * time.Millisecond
	cfg.killAfter = time.Duration(killAfterMS) * time.Millisecond
	cfg.commandArgs = splitArgs(commandArgs)
	return cfg, renderFlagDefaults(fs), nil
}

func normalizeArgs(args []string) []string {
	normalized := make([]string, 0, len(args))
	for _, arg := range args {
		if arg == "/?" {
			normalized = append(normalized, "-h")
			continue
		}
		normalized = append(normalized, arg)
	}
	return normalized
}

func applyEventDefaults(cfg *config) {
	if strings.TrimSpace(cfg.path) == "" {
		switch cfg.eventID {
		case 2:
			cfg.path = defaultEventPath("event2_timechange.txt")
		case 11:
			cfg.path = defaultEventPath("event11_filecreate.txt")
		case 15:
			cfg.path = defaultEventPath("event15_ads_host.txt")
		case 26:
			cfg.path = defaultEventPath("event26_delete.txt")
		}
	}

	if cfg.content == "sysmonsim-go test artifact" {
		switch cfg.eventID {
		case 2:
			cfg.content = "sysmonsim-go event 2 test artifact"
		case 11:
			cfg.content = "sysmonsim-go event 11 test artifact"
		case 15:
			cfg.content = "sysmonsim-go event 15 ADS test artifact"
		case 26:
			cfg.content = "sysmonsim-go event 26 delete test artifact"
		}
	}
}

func defaultEventPath(name string) string {
	return filepath.Join(os.TempDir(), "sysmonsim-go", name)
}

func validateConfig(cfg config) error {
	if cfg.eventID == 0 {
		return errors.New("missing required -e / --event-id")
	}
	if cfg.count < 1 {
		return errors.New("--count must be at least 1")
	}

	switch cfg.eventID {
	case 1, 5:
		if strings.TrimSpace(cfg.command) == "" {
			return errors.New("--command cannot be empty")
		}
	case 2, 11, 15, 26:
		if strings.TrimSpace(cfg.path) == "" {
			return fmt.Errorf("--path is required for event %d", cfg.eventID)
		}
	case 3, 22:
		if cfg.eventID == 3 {
			if strings.TrimSpace(cfg.host) == "" {
				return errors.New("--host cannot be empty")
			}
			if cfg.port < 1 || cfg.port > 65535 {
				return errors.New("--port must be between 1 and 65535")
			}
		}
		if cfg.eventID == 22 && strings.TrimSpace(cfg.domain) == "" {
			return errors.New("--domain cannot be empty")
		}
	case 7:
		if strings.TrimSpace(cfg.libraryPath) == "" {
			return errors.New("--library-path cannot be empty")
		}
	case 9:
		if strings.TrimSpace(cfg.rawDiskPath) == "" {
			return errors.New("--raw-disk-path cannot be empty")
		}
	case 10:
		if cfg.targetPID < 0 {
			return errors.New("--target-pid must be >= 0")
		}
	case 8:
		if cfg.targetPID < 0 {
			return errors.New("--target-pid must be >= 0")
		}
		if strings.TrimSpace(cfg.injectDLL) == "" {
			return errors.New("--inject-dll cannot be empty")
		}
		if cfg.targetPID == 0 && strings.TrimSpace(cfg.targetProcess) == "" {
			return errors.New("--target-process cannot be empty when --target-pid is not used")
		}
	case 12, 13, 14:
		if strings.TrimSpace(cfg.regKey) == "" {
			return errors.New("--registry-key cannot be empty")
		}
	case 16:
		if strings.TrimSpace(cfg.serviceName) == "" || strings.TrimSpace(cfg.serviceBinPath) == "" {
			return errors.New("--service-name and --service-bin-path are required for event 16")
		}
	case 17, 18:
		if strings.TrimSpace(cfg.pipeName) == "" {
			return fmt.Errorf("--pipe-name is required for event %d", cfg.eventID)
		}
	case 19, 20, 21:
		if strings.TrimSpace(cfg.wmiCommand) == "" {
			return fmt.Errorf("--wmi-command is required for event %d", cfg.eventID)
		}
	case 24:
		if strings.TrimSpace(cfg.clipboardText) == "" {
			return errors.New("--clipboard-text cannot be empty")
		}
	case 6:
	case 25:
		if strings.TrimSpace(cfg.tamperTarget) == "" || strings.TrimSpace(cfg.tamperSource) == "" {
			return errors.New("--tamper-target and --tamper-source cannot be empty")
		}
	case 4, 23:
		return fmt.Errorf("event %d is not a Sysmon event ID", cfg.eventID)
	default:
		return fmt.Errorf("unsupported event ID %d", cfg.eventID)
	}

	switch cfg.regValueType {
	case "string", "dword", "qword":
	default:
		return fmt.Errorf("unsupported --registry-value-type %q", cfg.regValueType)
	}
	return nil
}

func usageText(flagHelp string) string {
	ids := []string{
		`  1  Process Create (Default: cmd.exe /c echo sysmonsim-go)`,
		`  2  File Creation Time Changed (Default: %TEMP%\sysmonsim-go\event2_timechange.txt)`,
		`  3  Network Connection (Default: example.org:443)`,
		`  5  Process Terminated (Default: cmd.exe /c "ping 127.0.0.1 -n 30 > nul")`,
		`  6  Driver Loaded (Default: guided/manual helper)`,
		`  7  Image Loaded (Default: C:\Windows\System32\kernel32.dll)`,
		`  8  CreateRemoteThread (Default: dangerous opt-in, ping.exe + user32.dll)`,
		`  9  RawAccessRead (Default: \\.\PhysicalDrive0)`,
		` 10  Process Access (Default: current process)`,
		` 11  File Create (Default: %TEMP%\sysmonsim-go\event11_filecreate.txt)`,
		` 12  Registry Object Create/Delete (Default: HKCU\Software\sysmonsim-go)`,
		` 13  Registry Value Set (Default: HKCU\Software\sysmonsim-go TestValue=string:sysmonsim-go)`,
		` 14  Registry Key/Value Rename (Default: HKCU\Software\sysmonsim-go -> sysmonsim-go_renamed)`,
		` 15  FileCreateStreamHash (Default: %TEMP%\sysmonsim-go\event15_ads_host.txt:Zone.Identifier)`,
		` 16  ServiceConfigurationChange (Default: service=sysmonsim-go start=auto)`,
		` 17  Pipe Created (Default: \\.\pipe\sysmonsim-go)`,
		` 18  Pipe Connected (Default: \\.\pipe\sysmonsim-go)`,
		` 19  WMI Event Filter (Default: root\cimv2 cmd.exe /c echo sysmonsim-go)`,
		` 20  WMI Event Consumer (Default: root\cimv2 cmd.exe /c echo sysmonsim-go)`,
		` 21  WMI Consumer-Filter Binding (Default: root\cimv2 cmd.exe /c echo sysmonsim-go)`,
		` 22  DNS Query (Default: example.org)`,
		` 24  Clipboard Change (Default: "sysmonsim-go clipboard test")`,
		` 25  Process Tampering (Default: guided/helper, cmd.exe -> svchost.exe)`,
		` 26  File Delete (Default: %TEMP%\sysmonsim-go\event26_delete.txt)`,
	}

	return fmt.Sprintf(`Usage:
  sysmonsim-go.exe -e <event_id> [options]

Supported event IDs:
%s

Note:
  Some event classes need Administrator rights, special Windows APIs, or extra system setup.
  Use --run-helper for guided/manual events and --dangerous for invasive ones.

Examples:
  sysmonsim-go.exe -e 1 --command "cmd.exe" --command-args "/c whoami"
  sysmonsim-go.exe -e 13 --registry-hive HKCU --registry-key "Software\Acme\Test" --registry-value-name Beacon --registry-string-data enabled
  sysmonsim-go.exe -e 22 --domain suspicious.example
  sysmonsim-go.exe -e 11 --path "C:\Temp\dropper.bin" --content "hello"
  sysmonsim-go.exe -e 17 --pipe-name \\.\pipe\sysmonsim-demo
  sysmonsim-go.exe -e 6 --run-helper
  sysmonsim-go.exe -e 8 --dangerous
  sysmonsim-go.exe -e 25 --run-helper

Options:
%s
`, strings.Join(ids, "\n"), indentBlock(flagHelp, "  "))
}

func exitf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func splitArgs(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	return strings.Fields(raw)
}

func renderFlagDefaults(fs *flag.FlagSet) string {
	var buf bytes.Buffer
	fs.SetOutput(&buf)
	fs.PrintDefaults()
	fs.SetOutput(os.Stderr)
	return strings.TrimRight(buf.String(), "\r\n")
}

func indentBlock(text string, prefix string) string {
	if strings.TrimSpace(text) == "" {
		return ""
	}
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func eventName(eventID int) string {
	names := map[int]string{
		1:  "Process Create",
		2:  "File Creation Time Changed",
		3:  "Network Connection",
		5:  "Process Terminated",
		6:  "Driver Loaded",
		7:  "Image Loaded",
		8:  "CreateRemoteThread",
		9:  "RawAccessRead",
		10: "Process Access",
		11: "File Create",
		12: "Registry Object Create/Delete",
		13: "Registry Value Set",
		14: "Registry Key/Value Rename",
		15: "FileCreateStreamHash",
		16: "ServiceConfigurationChange",
		17: "Pipe Created",
		18: "Pipe Connected",
		19: "WMI Event Filter",
		20: "WMI Event Consumer",
		21: "WMI Consumer-Filter Binding",
		22: "DNS Query",
		24: "Clipboard Change",
		25: "Process Tampering",
		26: "File Delete",
	}
	if name, ok := names[eventID]; ok {
		return name
	}
	return "Unknown"
}
