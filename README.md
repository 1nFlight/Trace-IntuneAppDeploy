# Trace-IntuneAppDeploy

Live trace collector for **Intune Company Portal** Win32 / MSIX / LOB app deployments on Windows.

Where the Microsoft OneDataCollector (ODC) and similar tools capture an *after-the-fact snapshot*, this script captures a **trace across a known user-initiated deployment window** — baseline, network capture, live IME log tail, time-bounded event logs, content-distribution stack (WinGet / DO / WU), and a delta of installed apps — packaged into an ODC-compatible ZIP that opens cleanly in the **Win32 Analyzer** and **Store Analyzer** HTML viewers.

---

## What it does

1. **Baseline** — Captures IME log positions (per-file length, creation time, last-write time), installed apps from the registry Uninstall keys, all `Get-AppxPackage -AllUsers`, and Company Portal state.
2. **Start network trace** — `netsh trace start scenario=InternetClient_dbg` (packets + TLS + CAPI2 + DNS + WinINET). Skip with `-NoNetworkTrace`.
3. **Live tail** — Opens a seek-to-end stream on `IntuneManagementExtension.log` and streams new lines to the console while you trigger the install from Company Portal.
4. **Stop on `[ENTER]`** — Or auto-stops at the `-MaxMinutes` safety timeout.
5. **Delta + filtered exports** — IME log delta (handles mid-trace log rotation), installed-apps diff (Win32 *and* MSIX/Store), event channels filtered to the trace window via XPath, WinGet per-user logs, WPM-*.txt, `Get-DeliveryOptimizationLog`, `Get-WindowsUpdateLog`, raw DO/WU ETLs.
6. **ZIP** — ODC-style layout under `Intune\` (Commands, Files, EventLogs, RegistryKeys) plus trace-only folders (`Baseline\`, `Network\`, `Trace\`) at the stage root, with a synthesized `Intune.xml` manifest.

---

## Requirements

- Windows 10 / 11 with **PowerShell 5.1+** (PS 7 also works).
- **Administrator** elevation.
- A **console host** (PowerShell ISE is detected; you'll be offered a 1-click relaunch into `powershell.exe`, or a degraded batch-tail mode).
- No other `netsh trace` session active (the script aborts with a clear error if one is).

---

## Install / run

### One-liner (recommended)

```powershell
# No params
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1')))

# With params
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1'))) -MaxMinutes 30 -NoNetworkTrace
```

> **Why not `irm … | iex`?** `iex` runs its input at the caller's script scope, where top-level `[CmdletBinding()]` / `param()` are not legal statements. `[scriptblock]::Create($text)` parses the text as a fresh script block — which honors `param()` and `[CmdletBinding()]` exactly like a `.ps1` file does. `&` then invokes it and forwards parameters.

### Local

```powershell
# From an elevated PowerShell prompt
.\Trace-IntuneAppDeploy.ps1
```

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-OutputRoot` | Current user's Desktop | Folder where the final ZIP is written. |
| `-MaxMinutes` | `15` (range 1–240) | Safety timeout. Trace auto-stops at this mark even if `[ENTER]` was not pressed. |
| `-NoNetworkTrace` | *(off)* | Skip `netsh trace`. Use where network capture is policy-restricted, or when Wireshark / pktmon is already capturing. |
| `-NetTraceMaxSizeMB` | `512` (range 64–4096) | Max size for the netsh trace ETL (circular). |
| `-NoOpen` | *(off)* | Do not open Explorer to the output location when finished. |

---

## Examples

```powershell
# Default: 15-minute window, full netsh trace, ZIP to Desktop
.\Trace-IntuneAppDeploy.ps1

# Longer window for slow installs
.\Trace-IntuneAppDeploy.ps1 -MaxMinutes 30

# Skip netsh (locked-down environment, or capturing separately)
.\Trace-IntuneAppDeploy.ps1 -NoNetworkTrace

# Custom output folder, no Explorer popup
.\Trace-IntuneAppDeploy.ps1 -OutputRoot 'C:\Diag' -NoOpen
```

---

## Output layout

```
<COMPUTER>_AppDeployTrace_<yyyyMMdd-HHmmss>.zip
└── AppDeployTrace_<COMPUTER>_<timestamp>\
    ├── _Collector.log
    ├── _Summary.txt
    ├── _AppDeployReport.txt
    ├── Intune.xml                       ← ODC-style manifest
    ├── Baseline\                        ← pre-trace snapshot (apps, IME positions, CP state)
    ├── Network\                         ← netsh trace ETL + cab
    ├── Trace\                           ← live-tail capture, delta extracts
    └── Intune\
        ├── Commands\
        │   └── General\                 ← %COMPUTERNAME%_<Name>.txt outputs
        ├── Files\
        │   ├── Sidecar\                 ← full IME log copy
        │   ├── General\                 ← WinGet_<user>, misc
        │   ├── WPM\                     ← WPM-*.txt
        │   └── Intune\
        │       ├── DeliveryOptimization_ETL\
        │       └── WindowsUpdate_ETL\
        ├── EventLogs\                   ← .evtx, time-filtered to trace window
        └── RegistryKeys\                ← .reg exports of Win32 app state keys
```

The `Intune\` subtree matches the legacy Microsoft OneDataCollector layout, so the same ZIP opens cleanly in the **Win32 Analyzer** (`Tools/Win32/`) and **Store Analyzer** (`Tools/Store Apps/`) viewers. `Baseline\`, `Network\`, and `Trace\` are trace-only artifacts that the analyzers don't need to classify.

---

## What's in the trace window

Every artifact is filtered to `TraceStartedAt` → `TraceEndedAt` (with a small pad) so the trace window stays the source of truth:

- **IME logs** — delta extraction handles four cases: unchanged-same-file, rotation-replacement, new-post-baseline, and lost-tail (rotated-away file with `ROTATED_` prefix).
- **Installed apps diff** — two sections: *Win32 / MSI / EXE* (registry-based) and *Store / MSIX / Appx* (`Get-AppxPackage -AllUsers`, with added / removed / upgraded).
- **Event channels** — IME, AppxDeployment, DeviceManagement-Enterprise-Diagnostics-Provider, BITS, Store, AAD, DeliveryOptimization (Operational + Analytic), WindowsUpdateClient, WUSA. Filtered server-side via `wevtutil epl /q:<XPath>`.
- **Content distribution** — WinGet per-user `DiagOutputDir` (walks all user profiles), WPM-*.txt, `Get-DeliveryOptimizationLog`, `Get-WindowsUpdateLog`, raw DO + WU ETLs.

---

## Troubleshooting

**"A netsh trace session is already active on this machine."**
Stop it first: `netsh trace stop`, or re-run with `-NoNetworkTrace`.

**Running in PowerShell ISE.**
You'll get an interactive prompt: `[1]` relaunch elevated `powershell.exe` (recommended), `[2]` continue in ISE with batch-tail every 5s + `stop`/`abort` sentinel, `[Q]` quit.

**File looks corrupted / parser errors after `git clone` on PS 5.1.**
The script ships **UTF-8 BOM + CRLF** specifically so PS 5.1 doesn't mis-decode it via the ANSI codepage. If you've re-saved it without a BOM, restore from the repo.

---

## Version

`v1.2.3` (2026-04-24). See the `Changelog` block at the top of the script for the full history.

---

## Disclaimer

Provided as-is. Not a Microsoft product. The script reads system state, captures network traffic, and writes a ZIP to the path you specify; review the source before running on production hosts.
