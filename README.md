# Trace-IntuneAppDeploy

Live trace collector for **Intune Company Portal** Win32 / MSIX / LOB app deployments on Windows.

Where the Microsoft OneDataCollector (ODC) and similar tools capture an *after-the-fact snapshot*, this script captures a **trace across a known user-initiated deployment window** — baseline, network capture, live IME log tail, time-bounded event logs, content-distribution stack (WinGet / DO / WU), and a delta of installed apps — packaged into an ODC-compatible ZIP that opens cleanly in the **Win32 Analyzer** and **Store Analyzer** HTML viewers.

As of **v1.4.x** the network capture is two legs — a tuned ETW trace plus a header-only packet capture converted to `.pcapng` — alongside a proxy/DNS/DO stack snapshot and a TLS-interception probe of every Store, WinGet, Delivery-Optimization, Windows-Update and Intune endpoint. See [Network capture](#network-capture).

---

## What it does

1. **Baseline** — Captures IME log positions (per-file length, creation time, last-write time), installed apps from the registry Uninstall keys, all `Get-AppxPackage -AllUsers`, and Company Portal state.
2. **Start network capture** — Two legs: `netsh trace scenario=InternetClient_dbg` for ETW (plus the Delivery Optimization / BITS / Windows Update / Store / AppXDeployment providers the scenario lacks), and `pktmon` for header-only frames. Skip with `-NoNetworkTrace`.
3. **Snapshot + probe** — Proxy / PAC / DNS / routes / sockets / DO config, then a DNS + TCP + TLS-chain probe of the Store, WinGet, DO, WU and Intune endpoints.
4. **DO trace + live tail** — Starts the DO troubleshooter's verbose reproduction workflow, waits until it is ready, then streams new `IntuneManagementExtension.log` lines to the console while you trigger the install from Company Portal.
5. **Stop on `[ENTER]`** — Or auto-stops at the `-MaxMinutes` safety timeout.
6. **Delta + filtered exports** — IME log delta (handles mid-trace log rotation), installed-apps diff (Win32 *and* MSIX/Store), event channels filtered to the trace window via XPath, WinGet per-user logs, WPM-*.txt, the verbose Delivery Optimization reproduction trace, `Get-WindowsUpdateLog`, and raw WU ETLs. The packet ETL is converted to `.pcapng`.
7. **ZIP** — ODC-style layout under `Intune\` (Commands, Files, EventLogs, RegistryKeys) plus trace-only folders (`Baseline\`, `Network\`, `Trace\`) at the stage root, with a synthesized `Intune.xml` manifest.

---

## Requirements

- Windows 10 / 11 with **PowerShell 5.1+** (PS 7 also works).
- **Administrator** elevation.
- A **console host** (PowerShell ISE is detected; you'll be offered a 1-click relaunch into `powershell.exe`, or a degraded batch-tail mode).
- No other `netsh trace` or `pktmon` session active (the script aborts with a clear error if one is).
- `pktmon.exe` for the default header-only packet capture. Absent on older builds — the script falls back to `-PacketCapture Full` automatically.
- Access to PowerShell Gallery, or a trusted local `DeliveryOptimizationTroubleshooter.ps1` supplied with `-DeliveryOptimizationTroubleshooterPath`. Not required with `-NoDeliveryOptimizationTrace`.

---

## Install / run

### One-liner (recommended)

```powershell
irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1' | iex
```

With parameters — use `[scriptblock]::Create` so `param()` accepts them:

```powershell
& ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1'))) -MaxMinutes 30 -NoNetworkTrace
```

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
| `-NoNetworkTrace` | *(off)* | Skip the whole network capture — ETW leg, packet leg, stack snapshot and endpoint probe. Use where capture is policy-restricted, or when Wireshark / pktmon is already running. |
| `-PacketCapture` | `Headers` | `Headers` = pktmon, every frame truncated to `-PacketBytes`. `Full` = netsh `capture=yes`, full frames, no pktmon. `Off` = ETW + snapshot + probe only. |
| `-PacketBytes` | `768` (range 64–65535) | Per-frame truncation for `Headers` mode. See [Network capture](#network-capture) for why 768. |
| `-NetTraceMaxSizeMB` | `1024` (range 64–8192) | Max size cap for the netsh ETL and the pktmon ETL (each, circular). |
| `-NoEndpointProbe` | *(off)* | Skip the Store / WinGet / DO / WU / Intune reachability + TLS-chain probe. |
| `-Etl2PcapngPath` | *(none)* | Path to `etl2pcapng.exe`. Preferred over the in-box `pktmon etl2pcap` when supplied. |
| `-NoPcapConvert` | *(off)* | Keep the raw `.etl` only; skip `.pcapng` conversion. |
| `-DeliveryOptimizationTroubleshooterPath` | *(auto)* | Path to Microsoft's DO troubleshooter. Otherwise a trusted installed copy is used, or pinned version 1.3.0 is downloaded and hash-verified. |
| `-NoDeliveryOptimizationTrace` | *(off)* | Skip the DO workflow, including its download, service restarts, and removal of older DO logs. |
| `-CaptureTlsDiagnostics` | *(off)* | Enable `Microsoft-Windows-CAPI2/Operational` for the window and restore it afterwards. High event volume. |
| `-NoOpen` | *(off)* | Do not open Explorer to the output location when finished. |

---

## Examples

```powershell
# Default: 15-minute window, header-only packets + tuned ETW, ZIP to Desktop
.\Trace-IntuneAppDeploy.ps1

# Longer window for slow installs
.\Trace-IntuneAppDeploy.ps1 -MaxMinutes 30

# Full frames instead of headers (plain-HTTP CDN / DO payload analysis)
.\Trace-IntuneAppDeploy.ps1 -PacketCapture Full -NetTraceMaxSizeMB 4096

# Bigger header slice (response headers too) + external converter
.\Trace-IntuneAppDeploy.ps1 -PacketBytes 1536 -Etl2PcapngPath 'C:\Tools\etl2pcapng.exe'

# Skip all network capture (locked-down environment, or capturing separately)
.\Trace-IntuneAppDeploy.ps1 -NoNetworkTrace

# Custom output folder, no Explorer popup
.\Trace-IntuneAppDeploy.ps1 -OutputRoot 'C:\Diag' -NoOpen

# Use an already-downloaded official DO troubleshooter
.\Trace-IntuneAppDeploy.ps1 -DeliveryOptimizationTroubleshooterPath 'C:\Tools\DeliveryOptimizationTroubleshooter.ps1'

# Leave DO logging/service state untouched by the troubleshooter
.\Trace-IntuneAppDeploy.ps1 -NoDeliveryOptimizationTrace
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
    ├── Network\
    │   ├── NetTrace_<timestamp>.etl      ← ETW leg (netsh)
    │   ├── PktMon_<timestamp>.etl        ← packet leg (pktmon)
    │   ├── PktMon_<timestamp>.pcapng     ← converted — open in Wireshark / the analyzers
    │   ├── Diagnostics\                  ← network stack snapshot (pre + post) + endpoint probe
    │   └── ManualHAR\                    ← drop-folder for operator-captured Edge HAR
    ├── Trace\                           ← live-tail capture, delta extracts
    └── Intune\
        ├── Commands\
        │   └── General\                 ← includes the verbose DO reproduction trace
        ├── Files\
        │   ├── Sidecar\                 ← full IME log copy
        │   ├── General\                 ← WinGet_<user>, misc
        │   ├── WPM\                     ← WPM-*.txt
        │   └── Intune\
        │       └── WindowsUpdate_ETL\
        ├── EventLogs\                   ← .evtx, time-filtered to trace window
        └── RegistryKeys\                ← .reg exports of Win32 app state keys
```

The `Intune\` subtree matches the legacy Microsoft OneDataCollector layout, so the same ZIP opens cleanly in the **Win32 Analyzer** (`Tools/Win32/`) and **Store Analyzer** (`Tools/Store Apps/`) viewers. `Baseline\`, `Network\`, and `Trace\` are trace-only artifacts that the analyzers don't need to classify.

---

## What's in the trace window

The deployment window is recorded as `TraceStartedAt` to `TraceEndedAt`. Event exports use padded bounds; DO reproduction events are strictly limited to the DO-ready time through the operator or timeout stop. Baselines and full-copy snapshots retain their existing scope.

- **IME logs** — delta extraction handles four cases: unchanged-same-file, rotation-replacement, new-post-baseline, and lost-tail (rotated-away file with `ROTATED_` prefix).
- **Installed apps diff** — two sections: *Win32 / MSI / EXE* (registry-based) and *Store / MSIX / Appx* (`Get-AppxPackage -AllUsers`, with added / removed / upgraded).
- **Event channels** — IME, AppxDeployment, DeviceManagement-Enterprise-Diagnostics-Provider, BITS, Store, AAD, DeliveryOptimization (Operational + Analytic), WindowsUpdateClient, WUSA. Filtered server-side via `wevtutil epl /q:<XPath>`.
- **Content distribution** — WinGet per-user `DiagOutputDir` (walks all user profiles), WPM-*.txt, the `logs-dosvc-repro.txt` verbose trace produced by `DeliveryOptimizationTroubleshooter.ps1 -GenerateSupportBundle -ReproduceIssueWithVerboseLogs`, `Get-WindowsUpdateLog`, and raw WU ETLs. Only the DO reproduction trace is retained; the troubleshooter's other support-bundle files and temporary ZIP are removed.

---

## Delivery Optimization

The collector runs [Microsoft's DO troubleshooter](https://www.powershellgallery.com/packages/DeliveryOptimizationTroubleshooter/1.3.0) with:

```powershell
DeliveryOptimizationTroubleshooter.ps1 -GenerateSupportBundle -ReproduceIssueWithVerboseLogs
```

Wait for the collector's **TRACE ACTIVE** banner before triggering the deployment. The troubleshooter runs in a child process with a private temporary directory. The collector forwards Enter or the safety timeout to its reproduction prompt; Q also stops the DO workflow but discards the collection. Cleanup runs on interruptions as well.

Only events from `logs-dosvc-repro.txt` inside the reproduction window are retained. They are streamed into the existing analyzer-compatible `Key : Value` format with UTC timestamps and decoded hexadecimal process/thread IDs:

```text
Intune\Commands\General\<COMPUTER>_Get-DeliveryOptimizationLog.txt
```

The original reproduction text does not retain every structured cmdlet field, such as `LineNumber`; unavailable fields are left blank. Existing-history logs, configuration snapshots from the support bundle, raw DO ETLs, the nested ZIP, and temporary tool files are not packaged. If acquisition or capture fails, the collector logs the reason and records that the DO trace is unavailable; it never substitutes historical logs.

**Service and log impact:** the official workflow flushes and stops/restarts DoSvc, which can interrupt other DO downloads, and deletes older timestamped DO logs before reproduction. Start it before the target deployment, not during another DO capture. The collector skips DO capture if trace overrides are already configured. Use `-NoDeliveryOptimizationTrace` when those changes are inappropriate. `-NoNetworkTrace` controls the collector's separate network capture; it does not skip the DO troubleshooter or its health checks. Use both switches when neither workflow should run.

The automatic download is pinned to Gallery **1.3.0** and verified against package and script SHA-256 hashes. Despite the Gallery description, the inspected 1.3.0 script has no Authenticode signature. Local copies must match the pinned script or have a valid Microsoft signature, and must expose both required parameters. Temporary downloads are removed after each run.

---

## Network capture

Two legs, because they answer different questions and have wildly different size profiles.

### ETW leg — `netsh trace scenario=InternetClient_dbg`

The scenario already covers the network layer (TCPIP, Winsock-AFD, SChannel, DNS-Client, WinINet, WinHttp, WebIO). What it does **not** cover is the services that actually move Store and WinGet bytes — those come down Delivery Optimization (`dosvc`), BITS, or the WU agent, running as SYSTEM. So five providers are appended, resolved by name via `logman query providers` and skipped when the running build doesn't register them:

`DeliveryOptimization` · `Bits-Client` · `WindowsUpdateClient` · `Store` · `AppXDeployment-Server`

> Providers the scenario already owns are deliberately **not** re-declared. Re-declaring one replaces its tuned keyword mask with whatever you pass — passing `keywords=0xFFFFFFFFFFFFFFFF level=5` at WinINet/WinHttp/WebIO took the ETL from ~28 MB/min to ~129 MB/min.

### Packet leg — `pktmon`, header-only

Default `-PacketCapture Headers` captures every frame truncated to `-PacketBytes`, at the NIC only (`--comp nics`, so one copy per frame rather than one per stack component).

Full-frame capture is the wrong default here: a multi-hundred-MB app download fills a circular buffer in seconds, and what it overwrites is the *start* of the window — the catalog lookup, the licensing call, the DO job setup, i.e. where the failures actually are. Header-only keeps the whole window for roughly 2% of the bytes.

`-PacketBytes` defaults to **768**. pktmon counts from the start of the Ethernet frame, so usable payload is roughly that minus ~70 bytes of Eth + IP + TCP. A real Delivery Optimization content fetch has a ~500-byte request head:

```
GET /filestreamingservice/files/<guid>?P1=...&P2=...&P3=...&P4=...
    &cacheHostOrigin=msedge.b.tlu.dl.delivery.mp.microsoft.com HTTP/1.1
Connection: Keep-Alive
Accept: */*
Range: bytes=154140672-155189247
User-Agent: ...
Host: ...
```

256 cut mid-`Host:`; 512 cut inside `User-Agent`; 768 captures the whole head with margin. Raise to 1536 if you also want response headers.

Both ETLs are converted to `.pcapng` at stop — via `etl2pcapng.exe` when `-Etl2PcapngPath` is supplied, otherwise the in-box `pktmon etl2pcap`. The raw `.etl` is kept too; it holds ETW records the `.pcapng` can't represent.

### Stack snapshot + endpoint probe

`Network\Diagnostics\` gets a snapshot taken **before and after** the window, so a mid-window proxy or DNS change is visible: `ipconfig /all` and `/displaydns`, `route print`, `netsh winhttp show proxy`, WinINET policy keys, DNS client servers, `netstat`, `Get-DOConfig`, `Get-DeliveryOptimizationStatus` / `PerfSnap`, the DO policy hive, `winget source list`, and the list of locally installed root CAs.

Alongside it, every Store / WinGet / DO / WU / Intune endpoint is probed for DNS → TCP (with latency) → TLS handshake, recording the presented leaf and chain root. Verdicts are ranked so benign cases can't be reported as interception:

| Verdict | Meaning |
|---|---|
| `CERT-NAME-MISMATCH` | Presented cert is for another name — CDN default/fallback cert or wrong port. Not interception. |
| `TLS-INTERCEPTION-SUSPECTED` | Chain root is trusted locally but is **not** in the Microsoft Root Program and doesn't look like a public CA — i.e. installed by GPO, Intune, or a proxy's setup routine. |
| `TLS-CHAIN-UNTRUSTED` | Root isn't trusted by this machine at all. |
| `TLS-CHAIN-INVALID` | Chain built but failed for another reason. |
| `DNS-FAIL` / `TCP-FAIL` / `TLS-FAIL` | Didn't get that far. |

The interception test is store membership, not a CA-name allowlist: a CA in the Microsoft Root Program appears in **both** `Cert:\LocalMachine\Root` and `Cert:\LocalMachine\AuthRoot`, while a locally injected proxy root appears only in `Root`. A name allowlist can never be complete, and a proxy is free to name its root `DigiCert Global Root G2`.

> `dl.delivery.mp.microsoft.com` and `tlu.dl.delivery.mp.microsoft.com` are probed on **port 80** — Delivery Optimization fetches content over plain HTTP and gets its integrity from the update-metadata hashes. Probing them on 443 lands on the CDN's fallback certificate and tells you nothing.

---

## Troubleshooting

**"A netsh trace session is already active on this machine."**
Stop it first: `netsh trace stop`, or re-run with `-NoNetworkTrace`.

**"A pktmon capture session appears to be active on this machine."**
Stop it first: `pktmon stop`, or re-run with `-PacketCapture Full` (or `Off`).

**`.pcapng` missing from `Network\`.**
No converter was available. Supply `-Etl2PcapngPath` pointing at [etl2pcapng.exe](https://github.com/microsoft/etl2pcapng), or check that `pktmon etl2pcap` works on the build. The raw `.etl` is still in the ZIP.

**`_Summary.txt` says an ETL hit the size cap.**
The circular buffer wrapped and the earliest part of the window was overwritten. Re-run with a larger `-NetTraceMaxSizeMB` or a shorter `-MaxMinutes`.

**Running in PowerShell ISE.**
You'll get an interactive prompt: `[1]` relaunch elevated `powershell.exe` (recommended), `[2]` continue in ISE with batch-tail every 5s + `stop`/`abort` sentinel, `[Q]` quit.

**File looks corrupted / parser errors.**
The script ships **UTF-8 without BOM, LF line endings** — a BOM survives `irm | iex` as a literal U+FEFF and stops `#Requires` being recognised. `.gitattributes` enforces this; if you've re-saved the file with a BOM, restore it from the repo.

---

## Tests

Run the isolated regression suite; it uses a fake troubleshooter and stubs device-changing commands:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Test-DeliveryOptimizationTraceHelpers.ps1
pwsh -NoProfile -File .\tests\Test-DeliveryOptimizationTraceHelpers.ps1
```

Add `-CheckGallery` to verify real tool acquisition and trust without executing the downloaded script. Tests cover the readiness/stop handshake, time filtering, output format, Unicode paths/text, unrelated bundle protection, pre-existing trace settings, missing/invalid output, child failure, timeouts, and large redirected output. A live elevated deployment capture is a separate validation step.

---

## Version

`v1.5.0` (2026-09-14). See the `Changelog` block at the top of the script for the full history.

---

## Disclaimer

Provided as-is. Not a Microsoft product. The script reads system state, captures network traffic, and writes a ZIP to the path you specify; review the source before running on production hosts.
