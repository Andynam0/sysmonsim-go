# sysmonsim-go

`sysmonsim-go` is a Go replacement for the abandoned SysmonSimulator project. It now uses Sysmon-style event IDs on the command line so the operator experience is closer to the original tool, while still keeping the test artifacts overridable at runtime.

## Goals

- Avoid hardcoded domains, registry keys, file paths, and child commands.
- Keep the executable simple enough to leave on a test box for long-term use.
- Generate activity that Sysmon, EDR, or SIEM content can observe without recompiling for every new test artifact.

## CLI shape

The primary interface is:

```powershell
.\bin\sysmonsim-go.exe -e <event_id> [options]
```

Examples:

```powershell
.\bin\sysmonsim-go.exe -e 1 --command "cmd.exe" --command-args "/c whoami"
.\bin\sysmonsim-go.exe -e 13 --registry-hive HKCU --registry-key "Software\Acme\Test" --registry-value-name Beacon --registry-string-data "enabled"
.\bin\sysmonsim-go.exe -e 22 --domain suspicious.example
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
- `25` is guided/helper-driven because safe userland simulation is not straightforward.

The exact visibility still depends on your Sysmon configuration and whatever EDR rules exist on the endpoint.

## Build

```powershell
cd C:\path\to\sysmonsim-go
go mod tidy
go build -o .\bin\sysmonsim-go.exe .
```

## Usage

### DNS

```powershell
.\bin\sysmonsim-go.exe -e 22 --domain updates.badexample.test --verbose
```

### Registry

```powershell
.\bin\sysmonsim-go.exe -e 13 `
  --registry-hive HKCU `
  --registry-key "Software\Acme\Test" `
  --registry-value-name Beacon `
  --registry-value-type string `
  --registry-string-data "enabled"
```

### File

```powershell
.\bin\sysmonsim-go.exe -e 11 `
  --path "C:\Temp\sysmonsim-go\artifact.txt" `
  --content "test artifact"
```

### Network

```powershell
.\bin\sysmonsim-go.exe -e 3 --host 198.51.100.10 --port 443
```

### Process

```powershell
.\bin\sysmonsim-go.exe -e 1 --command "cmd.exe" --command-args "/c whoami"
```

### Driver load guidance

```powershell
.\bin\sysmonsim-go.exe -e 6
.\bin\sysmonsim-go.exe -e 6 --run-helper
```

### CreateRemoteThread

```powershell
.\bin\sysmonsim-go.exe -e 8 --dangerous
```

### Process tampering guidance

```powershell
.\bin\sysmonsim-go.exe -e 25
.\bin\sysmonsim-go.exe -e 25 --run-helper
```

## Repetition

Any scenario can be repeated:

```powershell
.\bin\sysmonsim-go.exe -e 22 --domain lab.example --count 10 --sleep-ms 1500
```

## Design notes

- Windows-specific implementations live behind build tags so you can still cross-build from WSL.
- `-e 6` mirrors the old simulator approach by guiding you through a real driver-load prerequisite instead of pretending a normal process can fake it.
- `-e 8` is invasive and therefore gated by `--dangerous`.
- `-e 25` is helper-driven guidance at the moment.
- `process-create` uses a plain quoted argument string and splits on whitespace. For complex quoting, pass a shell as `--command` and keep `--command-args` simple.
- This project aims for operator-controlled simulation, not stealth or anti-analysis behavior.
