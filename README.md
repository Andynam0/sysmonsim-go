# sysmonsim-go

`sysmonsim-go` is a Go replacement for the abandoned SysmonSimulator project. It now uses Sysmon-style event IDs on the command line so the operator experience is closer to the original tool, while still keeping the test artifacts overridable at runtime.

## Status

This repository is not planned for ongoing maintenance. It was produced from a quick coding session and is being shared as-is for reference and lab use.

## Warning

`--dangerous` options are expected to be detected by EDR and may cause the executable or related artifacts to be quarantined, blocked, or deleted. Use them only in an isolated lab where that outcome is acceptable.

## Goals

- Avoid hardcoded domains, registry keys, file paths, and child commands.
- Keep the executable simple enough to leave on a test box for long-term use.
- Generate activity that Sysmon, EDR, or SIEM content can observe without recompiling for every new test artifact.

## CLI shape

The primary interface is:

```cmd
bin\sysmonsim-go.exe -e <event_id> [options]
```

Examples:

```cmd
bin\sysmonsim-go.exe -e 1 --command "cmd.exe" --command-args "/c whoami"
bin\sysmonsim-go.exe -e 13 --registry-hive HKCU --registry-key "Software\Acme\Test" --registry-value-name Beacon --registry-string-data "enabled"
bin\sysmonsim-go.exe -e 22 --domain suspicious.example
```

## Event coverage

- `1`: Process Create
- `2`: File Creation Time Changed
- `3`: Network Connection
- `5`: Process Terminated
- `6`: Driver Loaded
- `7`: Image Loaded
- `8`: CreateRemoteThread
- `9`: RawAccessRead
- `10`: Process Access
- `11`: File Create
- `12`: Registry Object Create/Delete
- `13`: Registry Value Set
- `14`: Registry Key/Value Rename
- `15`: FileCreateStreamHash
- `16`: ServiceConfigurationChange
- `17`: Pipe Created
- `18`: Pipe Connected
- `19`: WMI Event Filter activity
- `20`: WMI Event Consumer activity
- `21`: WMI Consumer-Filter binding activity
- `22`: DNS Query
- `24`: Clipboard Change
- `25`: Process Tampering
- `26`: File Delete

These map roughly onto common Sysmon coverage areas:

- Some are implemented directly now.
- `6` is guided/manual with an optional helper script.
- `8` is implemented behind `--dangerous`.
- `25` is available behind `--dangerous`, with `--run-helper` still available for lab guidance.

The exact visibility still depends on your Sysmon configuration and whatever EDR rules exist on the endpoint.

## Build

```cmd
cd C:\path\to\sysmonsim-go
go mod tidy
go build -o bin\sysmonsim-go.exe .
```

## Sysmon config

The repo includes a default lab config at `config\sysmon-sysmonsim-go.xml`. It is meant to favor `sysmonsim-go` testing while reducing unrelated host-wide noise.

### Enable built-in Sysmon on modern Windows

Microsoft documents built-in Sysmon as an optional Windows feature for Windows 11 as of February 24, 2026. Use an elevated PowerShell window:

```powershell
Get-Service sysmon*
Enable-WindowsOptionalFeature -Online -FeatureName Sysmon
sysmon -accepteula -i
```

If you want to install built-in Sysmon and apply this repo's config in one step:

```powershell
cd C:\path\to\sysmonsim-go
sysmon -accepteula -i config\sysmon-sysmonsim-go.xml
```

If Sysmon is already installed, apply or update the config with:

```powershell
cd C:\path\to\sysmonsim-go
sysmon -c config\sysmon-sysmonsim-go.xml
```

Useful verification and maintenance commands:

```powershell
sysmon -c
sysmon -s
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 5
```

Notes:

- Microsoft Learn currently documents the built-in optional-feature flow for Windows 11, not a separate Windows Server 2026 article.
- On a 2026-era Windows build, confirm the feature is present with `Enable-WindowsOptionalFeature` and `sysmon -s` before assuming the built-in path is available.
- Built-in Sysmon doesn't support coexistence with standalone Sysmon.
- The included XML is intentionally narrower than a normal enterprise Sysmon config. It focuses on `sysmonsim-go.exe`, its default helper processes such as `cmd.exe`, `ping.exe`, `powershell.exe`, and `notepad.exe`, plus artifact paths containing `\sysmonsim-go\`.
- The included XML assumes the simulator executable name contains `sysmonsim` at a minimum. Variants like `sysmonsim-go.exe` and `sysmonsim_go.exe` will match, but unrelated names will not.
- If you override simulator defaults, you may need to update the XML to match your custom process names, DLLs, domains, registry paths, or pipe names.

Apply it during install:

```cmd
sysmon64.exe -accepteula -i config\sysmon-sysmonsim-go.xml
```

Or reconfigure an existing install:

```cmd
sysmon64.exe -c config\sysmon-sysmonsim-go.xml
```

Verify the active config:

```cmd
sysmon64.exe -c
```

Notes:

- The config uses `schemaversion="4.90"`, matching the current Microsoft Learn example format as of August 18, 2026.
- Event IDs `4` and `16` are not filterable through Sysmon XML.
- Event ID `23` is intentionally omitted because `sysmonsim-go` treats it as an invalid simulator ID.
- Some Sysmon event types expose better filter fields than others. `WmiEvent`, `DriverLoad`, `ClipboardChange`, and `ProcessTampering` are narrower than before, but still less precise than the file, registry, and process-centric event filters.
- If your local Sysmon build rejects `FileDeleteDetected`, run `sysmon64.exe -s` and update the schema version to match your installed binary.

## Usage

### DNS

```cmd
bin\sysmonsim-go.exe -e 22 --domain updates.badexample.test --verbose
```

### Registry

```cmd
bin\sysmonsim-go.exe -e 13 --registry-hive HKCU --registry-key "Software\Acme\Test" --registry-value-name Beacon --registry-value-type string --registry-string-data "enabled"
```

### File

```cmd
bin\sysmonsim-go.exe -e 11 --path "C:\Temp\sysmonsim-go\artifact.txt" --content "test artifact"
```

### Network

```cmd
bin\sysmonsim-go.exe -e 3 --host 198.51.100.10 --port 443
```

### Process

```cmd
bin\sysmonsim-go.exe -e 1 --command "cmd.exe" --command-args "/c whoami"
```

### Driver load guidance

```cmd
bin\sysmonsim-go.exe -e 6
bin\sysmonsim-go.exe -e 6 --run-helper
```

### CreateRemoteThread

```cmd
bin\sysmonsim-go.exe -e 8 --dangerous
```

### Process tampering guidance

```cmd
bin\sysmonsim-go.exe -e 25 --dangerous
bin\sysmonsim-go.exe -e 25 --run-helper
```

## Repetition

Any scenario can be repeated:

```cmd
bin\sysmonsim-go.exe -e 22 --domain lab.example --count 10 --sleep-ms 1500
```

## Design notes

- Windows-specific implementations live behind build tags so you can still cross-build from WSL.
- `-e 6` mirrors the old simulator approach by guiding you through a real driver-load prerequisite instead of pretending a normal process can fake it.
- `-e 8` is invasive and therefore gated by `--dangerous`.
- `-e 25` is invasive and therefore gated by `--dangerous`.
- `process-create` uses a plain quoted argument string and splits on whitespace. For complex quoting, pass a shell as `--command` and keep `--command-args` simple.
- This project aims for operator-controlled simulation, not stealth or anti-analysis behavior.
- Running `--dangerous` scenarios can trigger EDR prevention or quarantine actions against the simulator, helper scripts, or spawned child processes.
