#Requires -Version 5.1
<#
.SYNOPSIS
    Live trace collector for Intune Company Portal Win32 / MSIX / LOB app deployments.

.DESCRIPTION
    Captures a *trace* across a known user-initiated app-deployment window
    (Win32 / MSIX / LOB app installed from the Intune Company Portal app or
    Intune web portal), as opposed to an after-the-fact snapshot:

        1. Takes a baseline (IME log positions, installed apps, CP state).
        2. Starts a full network trace (netsh trace, InternetClient_dbg scenario
            -  captures packets + TLS + CAPI2 + DNS + WinINET).
        3. Opens a seek-to-end stream on IntuneManagementExtension.log for
           live console tailing.
        4. PAUSES and prompts the operator to trigger the install from the
           Company Portal app or web portal. Live-tails IME log to console
           while waiting.
        5. On [ENTER], stops the trace, flushes netsh capture, diffs baseline
           vs end-state, extracts the IME log delta for the trace window,
           exports event log entries time-filtered to the window.
        6. Packages into an ODC-style ZIP with Commands\, Files\, Registry\,
           EventLogs\, and new Network\ + Trace\ folders.

    Output is scoped to the app-deployment path: IME logs, AppxDeployment,
    DeviceManagement-Enterprise-Diagnostics-Provider, BITS, Store, AAD,
    and the registry keys that track Win32 app state. As of v1.2.0 also
    includes WinGet DiagOutputDir, WPM-*.txt, Get-DeliveryOptimizationLog
    output, Get-WindowsUpdateLog output, and raw DO/WU ETLs - each filtered
    to the trace window.

.PARAMETER OutputRoot
    Folder where the final ZIP is written. Default: current user's Desktop.

.PARAMETER MaxMinutes
    Safety timeout. Trace auto-stops at this mark even if [ENTER] was not
    pressed  -  prevents runaway capture if the operator walks away.
    Default: 15.

.PARAMETER NoNetworkTrace
    Skip netsh trace. Use on environments where network capture is restricted
    by policy, or where a separate tool (Wireshark / pktmon) is already
    capturing.

.PARAMETER NetTraceMaxSizeMB
    Max size for the netsh trace etl (circular). Default: 512.

.PARAMETER NoOpen
    Do not open Explorer to the output location when finished.

.EXAMPLE
    .\Trace-IntuneAppDeploy.ps1

.EXAMPLE
    .\Trace-IntuneAppDeploy.ps1 -MaxMinutes 30

.EXAMPLE
    .\Trace-IntuneAppDeploy.ps1 -NoNetworkTrace

.EXAMPLE
    # One-liner (no params)
    irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1' | iex

.EXAMPLE
    # One-liner with params (use [scriptblock]::Create so param() accepts them)
    & ([scriptblock]::Create((irm 'https://raw.githubusercontent.com/1nFlight/Trace-IntuneAppDeploy/main/Trace-IntuneAppDeploy.ps1'))) -MaxMinutes 30

.NOTES
    Requires administrator elevation.
    Requires console host (not PowerShell ISE) for the live-tail UX.
    Do not run concurrently with another netsh trace session  -  this script
    aborts with a clear error if one is already active.

    Changelog:
        1.2.4  2026-04-24  Remote-execution fix.
                           v1.0.1-1.2.3 saved the file as UTF-8 *with* BOM,
                           originally to prevent PS 5.1 ANSI codepage decoding
                           the embedded em-dashes as mojibake. The dashes were
                           later replaced with ASCII so the BOM was no longer
                           needed - and it was actively breaking remote
                           execution: irm preserves the BOM as a literal U+FEFF
                           character at position 0 of the returned string,
                           which makes PowerShell's parser stop recognizing
                           the leading '#Requires -Version 5.1' as a directive
                           and instead parse it as a command call. Once any
                           command has been parsed, top-level param() is no
                           longer legal, so the parser then errors on
                           [CmdletBinding()] / param() with 'Unexpected
                           attribute' - even though the .ps1 file itself runs
                           fine when invoked from disk (the script-loader path
                           strips the BOM).
                           Fix: re-saved as UTF-8 *without* BOM. Now both:
                             irm <url> | iex
                             & ([scriptblock]::Create((irm <url>))) -Param Val
                           work as expected.
        1.2.3  2026-04-24  DO log fidelity fix.
                           v1.2.0-1.2.2 filtered Get-DeliveryOptimizationLog by
                           comparing entry.TimeCreated against local-time trace
                           bounds. DO writes TimeCreated as UTC but reports it
                           with DateTimeKind=Unspecified, so on any non-UTC
                           host the comparison silently dropped every entry
                           and the captured file contained only the placeholder
                           'No DO log entries in trace window.' (39 bytes,
                           vs ~7 MB from the ODC collector on the same host).
                           Fixes:
                             - Trace bounds now converted to UTC before compare.
                             - Entry timestamps coerced to UTC (treats Unspecified
                               as UTC, matching DO log convention).
                             - Window pad widened from 30s to 120s.
                             - Empty-result fallback: dump the full DO log
                               (matches ODC over-collect behavior; trace window
                               is documented in _Summary.txt for correlation).
        1.2.2  2026-04-22  ODC-compatible directory structure (pairs with
                           Collect-IntuneLogs v1.2.0). Store Analyzer v2.3.4
                           and Win32 Analyzer v4.5.9 expect every artifact
                           under Intune\ with Team-named subdirectories; the
                           v1.0-1.2.1 flat layout bypassed the manifest-driven
                           collection-status view.
                           Restructure:
                             - IME full copy:   Files\IME  -> Files\Sidecar
                             - WinGet per-user: Files\WinGet\<user>
                                                -> Files\General\WinGet_<user>
                             - WPM:             Files\WPM (unchanged, under Intune\)
                             - DO ETL:          Files\DeliveryOptimization_ETL
                                                -> Files\Intune\DeliveryOptimization_ETL
                             - WU ETL:          Files\WindowsUpdate_ETL
                                                -> Files\Intune\WindowsUpdate_ETL
                             - Registry:        Registry\ -> RegistryKeys\
                             - EventLogs:       unchanged name, under Intune\
                             - Commands:        all CSV/TXT outputs now use
                                                %COMPUTERNAME%_<Name>.ext naming
                                                in Intune\Commands\General
                           Per user spec:
                             - DO log: %COMPUTERNAME%_Get-DeliveryOptimizationLog.txt
                                       in Intune\Commands\General
                             - WU log: %COMPUTERNAME%_WindowsUpdate.log
                                       in Intune\Commands\General
                           Emits synthesized Intune.xml manifest at stage root
                           listing every collected file under
                           Package>Collection>CollectedItem.
                           Trace-specific dirs (Baseline\, Network\, Trace\)
                           remain at stage root because analyzers don't parse
                           them - they're Trace UX artifacts, not ODC content.
        1.2.1  2026-04-22  Two fidelity fixes to delta coverage.
                           Gap 1 - IME log rotation mid-trace:
                             v1.2.0 recorded baseline as a {Name -> Length}
                             hashtable. If an IME log rotated during the trace
                             (hit 3 MB cap, got renamed to a dated variant,
                             fresh file took its place), the final bytes that
                             landed in the pre-rotation file were lost.
                             Baseline now captures {Name -> {Length, CreationTime,
                             LastWriteTime}}. Delta extraction handles four
                             cases: unchanged-same-file (tail from baseline
                             pos), rotation-replacement (new file with newer
                             CreationTime under the baseline name - copy whole
                             new file), new-post-baseline (copy all), and
                             lost-tail (rotated-away file found by matching
                             baseline CreationTime - copy from baseline.Length
                             to current end, output with ROTATED_ prefix).
                           Gap 2 - Store/MSIX apps not in install diff:
                             Modern apps deployed via CP + EnterpriseModern-
                             AppManagement CSP don't register in HKLM or HKCU
                             Uninstall. The registry-Uninstall-only diff showed
                             '(none)' for successful Store deploys - actively
                             misleading. Added Get-AppxPackage -AllUsers at
                             baseline + end-state, diffed on PackageFullName.
                             installed_apps_diff.txt now has two sections:
                             'WIN32 / MSI / EXE APPS' (registry-based, as before)
                             and 'STORE / MSIX / APPX PACKAGES' with added /
                             removed / upgraded (Name-stable with changed
                             PackageFullName).
        1.2.0  2026-04-22  Added content-distribution layer coverage.
                           v1.0-1.1 captured the IME + CP + AppX side of app
                           deployments but not the actual download/install stack
                           underneath:
                           - WinGet: per-user DiagOutputDir logs (walks all
                             user profiles, filters to trace window + 30s pad),
                             plus WPM-*.txt for Intune-managed Store apps.
                           - Delivery Optimization: Get-DeliveryOptimizationLog
                             filtered to trace window (DO is the content
                             downloader for Win32 + Store + updates), plus raw
                             DO ETLs from NetworkService profile for external
                             analysis.
                           - Windows Update: Get-WindowsUpdateLog generates a
                             merged text log from the current ETLs; raw ETLs
                             modified during the window also captured.
                           - Event channels: added DeliveryOptimization
                             (Operational + Analytic), WindowsUpdateClient
                             (Operational), WUSA (Operational) to the
                             time-filtered event log exports.
                           All three stacks are time-filtered against
                           $script:TraceStartedAt / $script:TraceEndedAt the
                           same way IME log deltas and event log exports are,
                           so the trace window stays the source of truth.
        1.1.0  2026-04-22  ISE support: interactive 1/2/Q prompt instead of hard abort.
                           - Option 1: Relaunches in elevated powershell.exe with
                             the same bound parameters, then exits ISE. Uses
                             Start-Process -Verb RunAs so UAC prompt appears.
                           - Option 2: Continues in ISE with a degraded UX
                             (batch tail every 5s via a background Start-Job that
                             streams new IME log bytes to a temp file; main thread
                             prints in batches, blocks on Read-Host for 'stop' /
                             'abort' sentinel). No per-keystroke control - ISE
                             doesn't expose KeyAvailable - but the trace itself
                             runs normally in the background.
                           - Option Q or invalid input: exits cleanly.
                           - Falls back to option 2 automatically if the relaunch
                             fails for any reason (denied UAC, elevation policy).
        1.0.1  2026-04-22  Encoding fix. v1.0.0 was saved as BOM-less UTF-8,
                           which PowerShell 5.1 on Windows reads using the ANSI
                           codepage, corrupting the embedded em-dashes into the
                           mojibake sequence '\u00e2\u20ac\u201d'. The parser
                           then choked on broken string literals starting at the
                           first offending line, with cascading syntax errors for
                           the rest of the file.
                           - All non-ASCII characters (11 em-dashes) replaced
                             with ASCII equivalents (' - ').
                           - File saved with UTF-8 BOM and CRLF line endings so
                             it's robust to PS 5.1 / PS 7 / notepad round-trips
                             and git-for-windows autocrlf.
        1.0.0  2026-04-22  Initial release.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = [Environment]::GetFolderPath('Desktop'),

    [ValidateRange(1, 240)]
    [int]$MaxMinutes = 15,

    [switch]$NoNetworkTrace,

    [ValidateRange(64, 4096)]
    [int]$NetTraceMaxSizeMB = 512,

    [switch]$NoOpen
)

#region Constants

$APP_VERSION = '1.2.4'
$APP_BUILD   = '2026-04-24'

$script:Timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$script:Computer  = $env:COMPUTERNAME
$script:StageRoot = Join-Path $env:TEMP ("AppDeployTrace_{0}_{1}" -f $script:Computer, $script:Timestamp)
$script:ZipName   = "{0}_AppDeployTrace_{1}.zip" -f $script:Computer, $script:Timestamp
$script:ZipPath   = Join-Path $OutputRoot $script:ZipName
$script:LogFile   = Join-Path $script:StageRoot '_Collector.log'
$script:Summary   = Join-Path $script:StageRoot '_Summary.txt'
$script:Report    = Join-Path $script:StageRoot '_AppDeployReport.txt'

$script:IMELogsPath  = Join-Path $env:ProgramData 'Microsoft\IntuneManagementExtension\Logs'
$script:IMEMainLog   = Join-Path $script:IMELogsPath 'IntuneManagementExtension.log'
$script:IMEWorkload  = Join-Path $script:IMELogsPath 'AppWorkload.log'
$script:IMEAction    = Join-Path $script:IMELogsPath 'AppActionProcessor.log'
$script:IMEExecutor  = Join-Path $script:IMELogsPath 'AgentExecutor.log'

$script:StartTime = Get-Date

#endregion

#region Helpers

function Write-CLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','OK','SKIP','TRACE')][string]$Level = 'INFO'
    )
    $line = '{0}  {1,-5}  {2}' -f (Get-Date -Format 'HH:mm:ss'), $Level, $Message
    $color = switch ($Level) {
        'OK'    { 'Green' }
        'WARN'  { 'Yellow' }
        'ERROR' { 'Red' }
        'SKIP'  { 'DarkGray' }
        'TRACE' { 'DarkCyan' }
        default { 'Gray' }
    }
    Write-Host $line -ForegroundColor $color
    try { Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction Stop } catch {}
}

function Invoke-Safe {
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][scriptblock]$Action
    )
    Write-CLog "BEGIN  $Name"
    try {
        & $Action
        Write-CLog "OK     $Name" -Level OK
        return $true
    } catch {
        Write-CLog "ERROR  $Name :: $($_.Exception.Message)" -Level ERROR
        return $false
    }
}

function Ensure-Dir { param([string]$Path) if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path -Force | Out-Null } }

function Test-IsAdmin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Export-RegKey {
    param([string]$Key, [string]$OutDir)
    $keyPath = $Key -replace '^HKLM\\', 'HKEY_LOCAL_MACHINE\' -replace '^HKCU\\', 'HKEY_CURRENT_USER\'
    $flat = ($keyPath -replace '[\\:/*?"<>|]', '_') + '.reg'
    $out  = Join-Path $OutDir $flat
    $null = & reg.exe export $keyPath "$out" /y 2>$null
}

function New-EventLogExport {
    <#
        Exports a channel filtered to a time window (UTC).
        Returns $true on success, $false if channel unavailable.
    #>
    param(
        [string]$Channel,
        [string]$OutDir,
        [datetime]$StartUtc,
        [datetime]$EndUtc
    )
    $safe  = $Channel -replace '[\\/:*?"<>|]', '_'
    $out   = Join-Path $OutDir ($safe + '.evtx')
    # XPath range: events where TimeCreated >= StartUtc AND <= EndUtc
    $s     = $StartUtc.ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    $e     = $EndUtc.ToString('yyyy-MM-ddTHH:mm:ss.000Z')
    $xp    = "*[System[TimeCreated[@SystemTime>='$s' and @SystemTime<='$e']]]"
    $args  = @('epl', $Channel, $out, '/ow:true', "/q:$xp")
    $null  = & wevtutil.exe @args 2>$null
    return (Test-Path -LiteralPath $out)
}

function Get-InstalledAppInventory {
    <#
        Reads registry Uninstall keys  -  no Win32_Product (avoids MSI self-repair).
    #>
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $all = foreach ($k in $keys) {
        Get-ItemProperty $k -ErrorAction SilentlyContinue |
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate,
                          @{n='Scope';e={ if ($k -like 'HKCU:*') {'User'} elseif ($k -like '*WOW6432Node*') {'MachineX86'} else {'Machine'} }}
    }
    return $all | Sort-Object DisplayName, DisplayVersion
}

#endregion

#region Preflight

if (-not (Test-IsAdmin)) {
    Write-Host ''
    Write-Host 'ERROR: Trace-IntuneAppDeploy must be run as Administrator.' -ForegroundColor Red
    return
}

# v1.1.0: ISE detection + interactive branching.
# The live-tail/keypress UX needs a console host ($Host.UI.RawUI.KeyAvailable).
# ISE doesn't support it. Rather than abort, we give the operator a choice.
$script:IseMode = $false
if ($Host.Name -eq 'Windows PowerShell ISE Host') {
    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor Yellow
    Write-Host '  PowerShell ISE detected                                     ' -ForegroundColor Yellow
    Write-Host '==============================================================' -ForegroundColor Yellow
    Write-Host '  The interactive live-tail UX needs a console host.'
    Write-Host '  Choose how to proceed:'
    Write-Host ''
    Write-Host '    [1] Relaunch in powershell.exe (recommended)' -ForegroundColor Green
    Write-Host '        - New window opens with streaming tail, color coding, ENTER to stop.'
    Write-Host '        - ISE exits immediately after the handoff.'
    Write-Host ''
    Write-Host '    [2] Continue in ISE (degraded UX)' -ForegroundColor Cyan
    Write-Host '        - No streaming tail; IME log deltas shown in batches every 5s.'
    Write-Host '        - Stop trace by typing "stop" + ENTER (or "abort" to cancel).'
    Write-Host ''
    Write-Host '    [Q] Quit' -ForegroundColor DarkGray
    Write-Host ''
    $choice = Read-Host '  Choice'
    switch -Regex ($choice.Trim()) {
        '^1$' {
            # Rebuild the parameter list from bound parameters so the relaunch
            # sees exactly what the operator typed.
            $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-NoExit', '-File', "`"$PSCommandPath`"")
            foreach ($kv in $PSBoundParameters.GetEnumerator()) {
                $name = $kv.Key; $val = $kv.Value
                if ($val -is [switch]) {
                    if ($val.IsPresent) { $argList += "-$name" }
                } elseif ($val -is [bool]) {
                    if ($val) { $argList += "-$name" }
                } else {
                    $argList += "-$name"
                    $argList += "`"$val`""
                }
            }
            try {
                Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs -ErrorAction Stop
                Write-Host ''
                Write-Host '  Relaunch initiated in new elevated console window.' -ForegroundColor Green
                Write-Host '  This ISE instance will exit now.'
                Write-Host ''
                return
            } catch {
                Write-Host ''
                Write-Host ("ERROR: Failed to relaunch powershell.exe: {0}" -f $_.Exception.Message) -ForegroundColor Red
                Write-Host "Falling back to ISE degraded mode..." -ForegroundColor Yellow
                $script:IseMode = $true
            }
        }
        '^2$' {
            $script:IseMode = $true
            Write-Host ''
            Write-Host '  Continuing in ISE degraded mode.' -ForegroundColor Cyan
            Write-Host ''
        }
        '^[Qq]$' {
            Write-Host ''
            Write-Host '  Exiting. No changes made.' -ForegroundColor DarkGray
            Write-Host ''
            return
        }
        default {
            Write-Host ''
            Write-Host '  No valid choice entered. Exiting.' -ForegroundColor DarkGray
            Write-Host ''
            return
        }
    }
}

# Ensure output path exists
if (-not (Test-Path -LiteralPath $OutputRoot)) {
    try { New-Item -ItemType Directory -Path $OutputRoot -Force | Out-Null }
    catch {
        Write-Host "ERROR: Cannot create OutputRoot '$OutputRoot'." -ForegroundColor Red
        return
    }
}

# Check for existing netsh trace session
if (-not $NoNetworkTrace) {
    $probe = & netsh.exe trace show status 2>$null
    if ($probe -match 'Trace configuration:') {
        Write-Host ''
        Write-Host 'ERROR: A netsh trace session is already active on this machine.' -ForegroundColor Red
        Write-Host '       Stop it first:  netsh trace stop' -ForegroundColor Yellow
        Write-Host '       Or re-run with -NoNetworkTrace.' -ForegroundColor Yellow
        Write-Host ''
        return
    }
}

# Prepare stage.
# v1.2.2: ODC-compatible directory layout. All app-deployment artifacts go
# under Intune\ (Commands\General, Files\Sidecar, Files\General, EventLogs,
# RegistryKeys) matching the legacy Microsoft OneDataCollector structure that
# Win32 Analyzer and Store Analyzer parse. Network\, Trace\, and Baseline\
# stay at stage root because they are Trace-specific additions the analyzers
# don't need to classify.
Ensure-Dir $script:StageRoot
$script:IntuneRoot     = Join-Path $script:StageRoot 'Intune'
$script:CmdGeneral     = Join-Path $script:IntuneRoot 'Commands\General'
$script:CmdAutopilot   = Join-Path $script:IntuneRoot 'Commands\Autopilot'
$script:FilesSidecar   = Join-Path $script:IntuneRoot 'Files\Sidecar'
$script:FilesGeneral   = Join-Path $script:IntuneRoot 'Files\General'
$script:FilesWPM       = Join-Path $script:IntuneRoot 'Files\WPM'
$script:FilesIntune    = Join-Path $script:IntuneRoot 'Files\Intune'
$script:EventLogsDir   = Join-Path $script:IntuneRoot 'EventLogs'
$script:RegKeysDir     = Join-Path $script:IntuneRoot 'RegistryKeys'
Ensure-Dir $script:IntuneRoot
Ensure-Dir $script:CmdGeneral
Ensure-Dir $script:FilesSidecar
Ensure-Dir $script:FilesGeneral
Ensure-Dir $script:EventLogsDir
Ensure-Dir $script:RegKeysDir
Ensure-Dir (Join-Path $script:StageRoot 'Network')
Ensure-Dir (Join-Path $script:StageRoot 'Trace')
'' | Out-File -FilePath $script:LogFile -Encoding UTF8

# v1.2.2: helper for ODC command-output naming: %COMPUTERNAME%_<OutputFileName>.txt
function Get-CmdOutPath {
    param(
        [Parameter(Mandatory)][string]$Dir,
        [Parameter(Mandatory)][string]$OutputFileName,
        [string]$Extension = '.txt'
    )
    Ensure-Dir $Dir
    $base = [System.IO.Path]::GetFileNameWithoutExtension($OutputFileName)
    $filename = "{0}_{1}{2}" -f $script:Computer, $base, $Extension
    return (Join-Path $Dir $filename)
}

Write-CLog ("Trace-IntuneAppDeploy v{0} ({1})" -f $APP_VERSION, $APP_BUILD)
Write-CLog ("Computer: {0}  |  User: {1}" -f $script:Computer, "$env:USERDOMAIN\$env:USERNAME")
Write-CLog ("Stage   : {0}" -f $script:StageRoot)
Write-CLog ("Output  : {0}" -f $script:ZipPath)
Write-CLog ("MaxMin  : {0}  |  NetTrace: {1}" -f $MaxMinutes, (-not $NoNetworkTrace))

#endregion

#region Baseline

# v1.2.2: directory aliases now point at the ODC-structured folders.
$cmdDir   = $script:CmdGeneral
$filesDir = $script:IntuneRoot   # per-artifact routing below uses FilesSidecar, FilesGeneral, etc.
$regDir   = $script:RegKeysDir
$evtDir   = $script:EventLogsDir
$netDir   = Join-Path $script:StageRoot 'Network'
$trcDir   = Join-Path $script:StageRoot 'Trace'
$baseDir  = Join-Path $script:StageRoot 'Baseline'
Ensure-Dir $baseDir

# Record baseline metadata for IME logs so we can detect rotation and compute
# trace-window deltas. v1.2.1: we capture CreationTime as well as Length,
# because an IME log hitting its 3 MB cap during the trace gets renamed to a
# dated variant and a fresh empty file takes its place. Without the
# CreationTime signal we'd either miss the tail of the pre-rotation file or
# double-count bytes.
$script:BaselinePositions = @{}
if (Test-Path -LiteralPath $script:IMELogsPath) {
    Get-ChildItem -LiteralPath $script:IMELogsPath -File -ErrorAction SilentlyContinue |
        ForEach-Object {
            $script:BaselinePositions[$_.Name] = [PSCustomObject]@{
                Length        = $_.Length
                CreationTime  = $_.CreationTime
                LastWriteTime = $_.LastWriteTime
            }
        }
    Write-CLog ("Baseline: recorded positions for {0} IME log file(s)" -f $script:BaselinePositions.Count)
} else {
    Write-CLog "Baseline: IME log path not found  -  device may not be Intune-enrolled" -Level WARN
}

# Installed apps inventory at baseline
Invoke-Safe 'baseline: installed apps' {
    Get-InstalledAppInventory | Export-Csv -Path (Join-Path $baseDir 'installed_apps_baseline.csv') -NoTypeInformation
}

# Baseline dsregcmd /status
Invoke-Safe 'baseline: dsregcmd /status' {
    & dsregcmd.exe /status 2>&1 | Out-File -FilePath (Join-Path $baseDir 'dsregcmd_status.txt') -Encoding UTF8
}

# Baseline CP app state
Invoke-Safe 'baseline: Company Portal package info' {
    try {
        Get-AppxPackage -AllUsers -Name 'Microsoft.CompanyPortal' -ErrorAction Stop |
            Select-Object Name, Version, PackageFullName, InstallLocation, Status |
            Format-List | Out-String | Out-File (Join-Path $baseDir 'companyportal_package.txt') -Encoding UTF8
    } catch {
        "Get-AppxPackage failed: $($_.Exception.Message)" | Out-File (Join-Path $baseDir 'companyportal_package.txt') -Encoding UTF8
    }
}

# v1.2.1: Baseline AppX/MSIX inventory. Store/Modern apps DON'T appear in
# HKLM\...\Uninstall, so the Win32-style installed_apps diff misses them
# entirely. We capture Get-AppxPackage at baseline and end-state, diff on
# PackageFullName, and append a separate section to the diff report so Store
# deploys get the same visibility as Win32 deploys.
Invoke-Safe 'baseline: AppX/MSIX inventory' {
    try {
        Get-AppxPackage -AllUsers -ErrorAction Stop |
            Select-Object Name, Version, PackageFullName, Publisher,
                          @{n='Users';e={ ($_.PackageUserInformation | ForEach-Object { $_.UserSecurityId.Username }) -join '; ' }} |
            Export-Csv -Path (Join-Path $baseDir 'appx_baseline.csv') -NoTypeInformation
    } catch {
        "Get-AppxPackage -AllUsers failed: $($_.Exception.Message)" | Out-File (Join-Path $baseDir 'appx_baseline.csv') -Encoding UTF8
    }
}

# Baseline IME registry state (key target of Win32 app tracking)
Invoke-Safe 'baseline: registry (IME + EnterpriseDesktopAppManagement)' {
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension' -OutDir $baseDir
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement' -OutDir $baseDir
}

#endregion

#region Start Traces

$script:TraceStartedAt = Get-Date
$script:NetTraceRunning = $false
$script:NetTraceEtl     = Join-Path $netDir ("NetTrace_{0}.etl" -f $script:Timestamp)

# Enable CAPI2/Operational for the trace window so we can capture certificate
# chain validation events (the channel is disabled by default).
# Records prior state so we can restore it after the trace stops.
$script:Capi2Channel       = 'Microsoft-Windows-CAPI2/Operational'
$script:Capi2WasEnabled    = $false
$script:Capi2EnabledByUs   = $false
Invoke-Safe 'enable CAPI2/Operational channel' {
    [array]$cfg = @(& wevtutil.exe gl $script:Capi2Channel 2>$null)
    if ($cfg | Where-Object { $_ -match '^\s*enabled:\s*true\s*$' }) {
        $script:Capi2WasEnabled = $true
        Write-CLog "CAPI2/Operational already enabled - leaving as-is."
    } else {
        $null = & wevtutil.exe sl $script:Capi2Channel /e:true 2>&1
        if ($LASTEXITCODE -eq 0) {
            $script:Capi2EnabledByUs = $true
            Write-CLog "CAPI2/Operational enabled for trace window." -Level OK
        } else {
            Write-CLog "Could not enable CAPI2/Operational (exit $LASTEXITCODE) - events may be missing." -Level WARN
        }
    }
}

if (-not $NoNetworkTrace) {
    Invoke-Safe 'start network trace (netsh, InternetClient_dbg)' {
        # capture=yes: include raw frames
        # persistent=no: trace does not survive reboot
        # maxSize: circular buffer cap (MB)
        # scenario=InternetClient_dbg: packets + TLS + CAPI2 + DNS + WinINET
        # correlation=disabled + traceFile=<path> for predictable output location
        $arglist = @(
            'trace', 'start',
            'scenario=InternetClient_dbg',
            'capture=yes',
            'persistent=no',
            "maxSize=$NetTraceMaxSizeMB",
            'overwrite=yes',
            "traceFile=$($script:NetTraceEtl)"
        )
        $out = & netsh.exe @arglist 2>&1
        if ($LASTEXITCODE -ne 0 -or ($out -match 'failed|error')) {
            throw ("netsh trace start failed: {0}" -f ($out -join ' | '))
        }
        $script:NetTraceRunning = $true
    }
}

# Open seek-to-end stream on the main IME log for live tailing
$script:TailStream = $null
$script:TailReader = $null
if (Test-Path -LiteralPath $script:IMEMainLog) {
    try {
        $script:TailStream = [System.IO.FileStream]::new(
            $script:IMEMainLog, 'Open', 'Read', 'ReadWrite'
        )
        $null = $script:TailStream.Seek(0, [System.IO.SeekOrigin]::End)
        $script:TailReader = [System.IO.StreamReader]::new($script:TailStream)
        Write-CLog "Tail opened on IntuneManagementExtension.log (at EOF)"
    } catch {
        Write-CLog "Failed to open tail on IME log: $($_.Exception.Message)" -Level WARN
    }
} else {
    Write-CLog "IntuneManagementExtension.log not found  -  live tail disabled" -Level WARN
}

#endregion

#region Interactive Pause with Live Tail

$deadline = $script:TraceStartedAt.AddMinutes($MaxMinutes)

Write-Host ''
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host '  TRACE ACTIVE                                                ' -ForegroundColor Cyan
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host ('  Started       : {0}' -f $script:TraceStartedAt.ToString('HH:mm:ss'))
Write-Host ('  Auto-stop at  : {0}  (+{1} min)' -f $deadline.ToString('HH:mm:ss'), $MaxMinutes)
Write-Host ('  Network trace : {0}' -f $(if ($NoNetworkTrace) {'disabled'} else {'netsh InternetClient_dbg'}))
Write-Host ('  Live tail     : {0}' -f $(if ($script:TailReader) {'IntuneManagementExtension.log'} else {'unavailable'}))
Write-Host ''
Write-Host '  Steps:' -ForegroundColor Yellow
Write-Host '    1. Open Company Portal (Store app or https://portal.manage.microsoft.com)'
Write-Host '    2. Install the target application'
Write-Host '    3. Wait for the install to complete (success or failure)'
Write-Host '    4. Press [ENTER] here to stop the trace and collect logs'
Write-Host ''
Write-Host '  [Q] to abort without collecting.' -ForegroundColor DarkGray
Write-Host '==============================================================' -ForegroundColor Cyan
Write-Host ''
Write-Host '  Live IME log tail:' -ForegroundColor DarkCyan
Write-Host '  --------------------------------------------------------------' -ForegroundColor DarkCyan

$userInterrupted = $false
$userAborted     = $false

if ($script:IseMode) {
    # -- ISE DEGRADED PATH -----------------------------------------
    # ISE's ReadKey doesn't work, so we use a background job that dumps new
    # tail bytes to the ISE output pane every 5s, while the main thread
    # blocks on Read-Host for the 'stop'/'abort' sentinel.
    Write-Host ''
    Write-Host '  [ISE mode] The main thread will block on Read-Host until you type' -ForegroundColor Cyan
    Write-Host '  [ISE mode]   stop   to stop the trace and collect logs, or' -ForegroundColor Cyan
    Write-Host '  [ISE mode]   abort  to cancel without collecting.' -ForegroundColor Cyan
    Write-Host "  [ISE mode] Safety timeout: $MaxMinutes min (auto-stops regardless)." -ForegroundColor DarkGray
    Write-Host ''

    # Background tail job - reads from current baseline position, writes any
    # new content to a temp file the main thread reads periodically. Using a
    # file instead of job output avoids Receive-Job timing weirdness in ISE.
    $iseTailOut = Join-Path $script:StageRoot '_ise_tail.txt'
    '' | Out-File -FilePath $iseTailOut -Encoding UTF8 -Force
    $startPos = if (Test-Path -LiteralPath $script:IMEMainLog) {
        (Get-Item -LiteralPath $script:IMEMainLog).Length
    } else { 0 }

    $tailJob = $null
    if (Test-Path -LiteralPath $script:IMEMainLog) {
        $tailJob = Start-Job -ScriptBlock {
            param($LogPath, $OutPath, $StartPos, $DeadlineTicks)
            $pos = $StartPos
            $deadline = [datetime]::new($DeadlineTicks)
            while ((Get-Date) -lt $deadline) {
                try {
                    if (Test-Path -LiteralPath $LogPath) {
                        $len = (Get-Item -LiteralPath $LogPath).Length
                        if ($len -gt $pos) {
                            $fs = [System.IO.FileStream]::new($LogPath, 'Open', 'Read', 'ReadWrite')
                            $null = $fs.Seek($pos, [System.IO.SeekOrigin]::Begin)
                            $sr = [System.IO.StreamReader]::new($fs)
                            $chunk = $sr.ReadToEnd()
                            $sr.Close(); $fs.Close()
                            if ($chunk.Length -gt 0) {
                                Add-Content -LiteralPath $OutPath -Value $chunk -Encoding UTF8
                            }
                            $pos = $len
                        } elseif ($len -lt $pos) {
                            # Rotated; reset position to start of new file
                            $pos = 0
                        }
                    }
                } catch {}
                Start-Sleep -Seconds 2
            }
        } -ArgumentList $script:IMEMainLog, $iseTailOut, $startPos, $deadline.Ticks
    }

    # Poll the tail file every 5s, print new lines, check deadline.
    # Read-Host runs in a nested loop that only fires when user types something.
    $lastTailLen = 0
    $lastPrintTime = Get-Date
    try {
        while ($true) {
            $now = Get-Date
            if ($now -ge $deadline) {
                Write-Host ''
                Write-CLog "Auto-stop deadline reached ($MaxMinutes min)." -Level WARN
                break
            }

            # Flush any new tail bytes every 5s
            $didFlush = $false
            if (($now - $lastPrintTime).TotalSeconds -ge 5 -and (Test-Path -LiteralPath $iseTailOut)) {
                try {
                    $bytes = (Get-Item -LiteralPath $iseTailOut).Length
                    if ($bytes -gt $lastTailLen) {
                        $fs = [System.IO.FileStream]::new($iseTailOut, 'Open', 'Read', 'ReadWrite')
                        $null = $fs.Seek($lastTailLen, [System.IO.SeekOrigin]::Begin)
                        $sr = [System.IO.StreamReader]::new($fs)
                        $chunk = $sr.ReadToEnd()
                        $sr.Close(); $fs.Close()
                        $lastTailLen = $bytes
                        if ($chunk.Trim().Length -gt 0) {
                            Write-Host ''
                            Write-Host ('  --- IME tail (new) @ ' + $now.ToString('HH:mm:ss') + ' ---') -ForegroundColor DarkCyan
                            foreach ($ln in ($chunk -split "`r?`n")) {
                                if ($ln.Trim().Length -eq 0) { continue }
                                $c = 'DarkCyan'
                                if ($ln -match '(?i)<!\[LOG\[Error|\bERR\b|failure|failed|exception') { $c = 'Red' }
                                elseif ($ln -match '(?i)warn') { $c = 'Yellow' }
                                elseif ($ln -match '(?i)success|installed|completed')       { $c = 'Green' }
                                Write-Host ('  ' + $ln) -ForegroundColor $c
                            }
                        }
                    }
                    $lastPrintTime = $now
                    $didFlush = $true
                } catch {}
            }

            # ISE has no non-blocking key read; after each flush (or once per outer
            # iteration cycle if no new tail) we block on Read-Host. Trace runs
            # normally while Read-Host blocks; tail job keeps streaming to the temp
            # file; safety deadline is rechecked on return.
            $remain = [int]([math]::Ceiling(($deadline - (Get-Date)).TotalMinutes))
            $ans = Read-Host ("  [ISE] trace running ({0} min left) - type 'stop' / 'abort' / ENTER to keep tailing" -f $remain)
            $ansT = $ans.Trim().ToLower()
            if ($ansT -eq 'stop') {
                Write-CLog "Operator typed 'stop' - stopping trace."
                $userInterrupted = $true
                break
            } elseif ($ansT -eq 'abort') {
                Write-CLog "Operator typed 'abort' - cancelling without collection." -Level WARN
                $userInterrupted = $true
                $userAborted = $true
                break
            }
            # Empty or other input: continue. Force next loop iteration to flush
            # whatever new tail accumulated while Read-Host was blocking.
            $lastPrintTime = (Get-Date).AddSeconds(-10)
        }
    }
    finally {
        if ($tailJob) {
            try { Stop-Job -Job $tailJob -ErrorAction SilentlyContinue | Out-Null } catch {}
            try { Remove-Job -Job $tailJob -Force -ErrorAction SilentlyContinue | Out-Null } catch {}
        }
        Remove-Item -LiteralPath $iseTailOut -Force -ErrorAction SilentlyContinue
    }
}
else {
    # -- CONSOLE PATH (streaming live tail with keypress) ----------
    $lastCountdown = Get-Date
    try {
        while ($true) {
            # Deadline check
            $now = Get-Date
            if ($now -ge $deadline) {
                Write-Host ''
                Write-CLog "Auto-stop deadline reached ($MaxMinutes min)." -Level WARN
                break
            }

            # Keypress
            if ($Host.UI.RawUI.KeyAvailable) {
                $k = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
                if ($k.VirtualKeyCode -eq 13) {  # ENTER
                    Write-Host ''
                    Write-CLog "Operator pressed ENTER  -  stopping trace."
                    $userInterrupted = $true
                    break
                }
                if ($k.Character -eq 'q' -or $k.Character -eq 'Q') {
                    Write-Host ''
                    Write-CLog "Operator pressed Q  -  aborting without collection." -Level WARN
                    $userInterrupted = $true
                    $userAborted     = $true
                    break
                }
            }

            # Pump tail
            if ($script:TailReader) {
                try {
                    while (-not $script:TailReader.EndOfStream) {
                        $line = $script:TailReader.ReadLine()
                        if ($null -ne $line -and $line.Length -gt 0) {
                            # Colorize based on common IME log severities
                            $c = 'DarkCyan'
                            if ($line -match '(?i)<!\[LOG\[Error|ERR|failure|failed|exception') { $c = 'Red' }
                            elseif ($line -match '(?i)warn') { $c = 'Yellow' }
                            elseif ($line -match '(?i)success|installed|completed')       { $c = 'Green' }
                            Write-Host ('  ' + $line) -ForegroundColor $c
                        }
                    }
                } catch {
                    # Log may have been rotated; attempt to reopen at EOF
                    try {
                        $script:TailReader.Close(); $script:TailStream.Close()
                    } catch {}
                    if (Test-Path -LiteralPath $script:IMEMainLog) {
                        try {
                            $script:TailStream = [System.IO.FileStream]::new($script:IMEMainLog, 'Open', 'Read', 'ReadWrite')
                            $null = $script:TailStream.Seek(0, [System.IO.SeekOrigin]::End)
                            $script:TailReader = [System.IO.StreamReader]::new($script:TailStream)
                            Write-CLog "Tail reopened after rotation." -Level TRACE
                        } catch {
                            $script:TailReader = $null
                        }
                    }
                }
            }

            # Countdown banner every 60s
            if (($now - $lastCountdown).TotalSeconds -ge 60) {
                $remain = [int]([math]::Ceiling(($deadline - $now).TotalMinutes))
                Write-Host ('  [status] trace running  -  {0} min remaining. Press [ENTER] when install is done.' -f $remain) -ForegroundColor DarkGray
                $lastCountdown = $now
            }

            Start-Sleep -Milliseconds 250
        }
    }
    finally {
        if ($script:TailReader) { try { $script:TailReader.Close() } catch {} }
        if ($script:TailStream) { try { $script:TailStream.Close() } catch {} }
    }
}

$script:TraceEndedAt = Get-Date
Write-Host ''

#endregion

#region Stop Traces

if ($script:NetTraceRunning) {
    Write-CLog "Stopping netsh trace (flushing buffers  -  this can take ~30s)..."
    try {
        $out = & netsh.exe trace stop 2>&1
        if ($LASTEXITCODE -ne 0) {
            Write-CLog ("netsh trace stop returned exit {0}: {1}" -f $LASTEXITCODE, ($out -join ' | ')) -Level WARN
        } else {
            Write-CLog "netsh trace stopped." -Level OK
        }
    } catch {
        Write-CLog "Exception stopping netsh trace: $($_.Exception.Message)" -Level ERROR
    }
    $script:NetTraceRunning = $false
}

# Restore CAPI2/Operational to its prior state (only disable if we enabled it).
if ($script:Capi2EnabledByUs) {
    Invoke-Safe 'restore CAPI2/Operational channel' {
        $null = & wevtutil.exe sl $script:Capi2Channel /e:false 2>&1
        if ($LASTEXITCODE -eq 0) {
            Write-CLog "CAPI2/Operational disabled (restored to prior state)." -Level OK
        } else {
            Write-CLog "Could not disable CAPI2/Operational (exit $LASTEXITCODE) - run: wevtutil sl $script:Capi2Channel /e:false" -Level WARN
        }
    }
}

# If user aborted, clean up and exit
if ($userAborted) {
    Write-CLog "Abort path: removing staging directory."
    Remove-Item -LiteralPath $script:StageRoot -Recurse -Force -ErrorAction SilentlyContinue
    # Best-effort: remove partial netsh output
    if (Test-Path -LiteralPath $script:NetTraceEtl) {
        Remove-Item -LiteralPath $script:NetTraceEtl -Force -ErrorAction SilentlyContinue
    }
    return
}

#endregion

#region Post-Trace Collection

$traceDurationSec = [int]($script:TraceEndedAt - $script:TraceStartedAt).TotalSeconds
Write-CLog ("Trace window: {0} -> {1}  ({2}s)" -f $script:TraceStartedAt.ToString('HH:mm:ss'), $script:TraceEndedAt.ToString('HH:mm:ss'), $traceDurationSec)

# --- IME log deltas (bytes written during trace window) ---
# v1.2.1: rotation-aware.
#   Case A: file existed at baseline, same CreationTime => seek from baseline Length,
#           copy rest.
#   Case B: file existed at baseline by name but CreationTime is newer
#           => the baseline-named file was rotated away and a new one took its
#           place during the trace; copy the whole new file.
#   Case C: file did not exist at baseline at all => new post-baseline file;
#           copy the whole thing.
#   Case D: baseline had a file that no longer exists at end => it was rotated
#           to a dated name; find it by scanning for files whose CreationTime ==
#           baseline's CreationTime (same inode-era file, now renamed). Copy the
#           portion from baseline.Length to current end.
Invoke-Safe 'IME log delta extraction (rotation-aware)' {
    $deltaDir = Join-Path $trcDir 'IME_Delta'
    Ensure-Dir $deltaDir
    $totalBytes = 0
    $rotationEvents = 0

    $currentFiles = @(Get-ChildItem -LiteralPath $script:IMELogsPath -File -ErrorAction SilentlyContinue)
    $currentByName = @{}
    foreach ($f in $currentFiles) { $currentByName[$f.Name] = $f }

    # v1.2.1: Pre-compute which current files are actually rotated-away
    # baseline files masquerading under a new dated name. Matched by
    # CreationTime equality against any baseline entry (within 2s tolerance for
    # FS precision). Pass 1 skips these; Pass 2's lost-tail logic handles them
    # by copying only the bytes written after baseline.Length.
    $rotatedAwayCurrentNames = @{}
    foreach ($baseName in $script:BaselinePositions.Keys) {
        $baseEntry = $script:BaselinePositions[$baseName]
        $cur = $currentByName[$baseName]
        $baselineNameReplaced = ($null -eq $cur) -or
                                 ($cur.CreationTime -gt $baseEntry.CreationTime.AddSeconds(1))
        if (-not $baselineNameReplaced) { continue }
        # Find the rotated-away successor
        foreach ($candidate in $currentFiles) {
            if ($candidate.Name -eq $baseName) { continue }
            if ([math]::Abs(($candidate.CreationTime - $baseEntry.CreationTime).TotalSeconds) -le 2) {
                $rotatedAwayCurrentNames[$candidate.Name] = $baseName
                break
            }
        }
    }

    # --- Pass 1: process all current files (skipping rotated-away successors) ---
    foreach ($cur in $currentFiles) {
        if ($rotatedAwayCurrentNames.ContainsKey($cur.Name)) {
            # This is a pre-existing file now under a rotated name - handled in Pass 2
            continue
        }
        $baseEntry = $script:BaselinePositions[$cur.Name]
        $mode = $null; $startPos = 0; $endPos = $cur.Length; $outName = $cur.Name

        if ($null -eq $baseEntry) {
            # Case C - new post-baseline file (name didn't exist at baseline)
            $mode = 'new'
            $startPos = 0
        } elseif ($cur.CreationTime -gt $baseEntry.CreationTime.AddSeconds(1)) {
            # Case B - same name, different file (rotation replaced the baseline-name file)
            $mode = 'rotated-replacement'
            $startPos = 0
            $rotationEvents++
        } else {
            # Case A - same file, read tail
            $mode = 'delta'
            $startPos = $baseEntry.Length
            if ($endPos -le $startPos) { continue }  # no growth
        }

        $bytes = $endPos - $startPos
        if ($bytes -le 0) { continue }
        $totalBytes += $bytes
        $outPath = Join-Path $deltaDir $outName
        $fs = $null; $dst = $null
        try {
            $fs = [System.IO.FileStream]::new($cur.FullName, 'Open', 'Read', 'ReadWrite')
            $null = $fs.Seek($startPos, [System.IO.SeekOrigin]::Begin)
            $dst = [System.IO.FileStream]::new($outPath, 'Create', 'Write')
            $buf = New-Object byte[] 8192
            $remain = $bytes
            while ($remain -gt 0) {
                $take = [math]::Min($buf.Length, $remain)
                $read = $fs.Read($buf, 0, $take)
                if ($read -le 0) { break }
                $dst.Write($buf, 0, $read)
                $remain -= $read
            }
        } finally {
            if ($dst) { $dst.Close() }
            if ($fs)  { $fs.Close() }
        }
    }

    # --- Pass 2: find the "lost tails" of baseline-named files that rotated ---
    # If a file existed at baseline but its current occupant has a newer
    # CreationTime (Case B above), the original file was renamed to a dated
    # variant. Locate it by matching CreationTime exactly against baseline, and
    # copy the bytes from baseline.Length to current end.
    foreach ($baseName in $script:BaselinePositions.Keys) {
        $baseEntry = $script:BaselinePositions[$baseName]
        $cur = $currentByName[$baseName]
        # Only look for rotated tails when the name's current occupant is a
        # replacement (new CreationTime) OR when the baseline-named file is gone.
        $needTail = $false
        if ($null -eq $cur) { $needTail = $true }
        elseif ($cur.CreationTime -gt $baseEntry.CreationTime.AddSeconds(1)) { $needTail = $true }
        if (-not $needTail) { continue }

        # Hunt for the rotated-away file: CreationTime matches baseline (within
        # 2s tolerance for FS timestamp precision).
        $candidate = $currentFiles | Where-Object {
            $_.Name -ne $baseName -and
            [math]::Abs(($_.CreationTime - $baseEntry.CreationTime).TotalSeconds) -le 2
        } | Select-Object -First 1
        if ($null -eq $candidate) { continue }

        if ($candidate.Length -le $baseEntry.Length) { continue }
        $bytes = $candidate.Length - $baseEntry.Length
        $totalBytes += $bytes
        $rotationEvents++
        # Name the output to make the relationship obvious
        $outPath = Join-Path $deltaDir ("ROTATED_" + $baseName + "__" + $candidate.Name)
        $fs = $null; $dst = $null
        try {
            $fs = [System.IO.FileStream]::new($candidate.FullName, 'Open', 'Read', 'ReadWrite')
            $null = $fs.Seek($baseEntry.Length, [System.IO.SeekOrigin]::Begin)
            $dst = [System.IO.FileStream]::new($outPath, 'Create', 'Write')
            $buf = New-Object byte[] 8192
            $remain = $bytes
            while ($remain -gt 0) {
                $take = [math]::Min($buf.Length, $remain)
                $read = $fs.Read($buf, 0, $take)
                if ($read -le 0) { break }
                $dst.Write($buf, 0, $read)
                $remain -= $read
            }
        } finally {
            if ($dst) { $dst.Close() }
            if ($fs)  { $fs.Close() }
        }
    }

    Write-CLog ("       delta bytes written: {0:N0}  rotation events: {1}" -f $totalBytes, $rotationEvents)
}

# --- Full IME log copy (for cross-reference with rolled files) ---
Invoke-Safe 'IME logs (full copy)' {
    $imeFull = $script:FilesSidecar
    Ensure-Dir $imeFull
    Get-ChildItem -LiteralPath $script:IMELogsPath -File -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-Item -LiteralPath $_.FullName -Destination $imeFull -Force -ErrorAction SilentlyContinue
    }
}

# --- Event log exports, time-filtered to trace window ---
# Pad the window by 30s on each side to catch close-to-boundary events
$winStart = $script:TraceStartedAt.ToUniversalTime().AddSeconds(-30)
$winEnd   = $script:TraceEndedAt.ToUniversalTime().AddSeconds(30)

$appChannels = @(
    # Win32 / MSI app deployment
    'Microsoft-Windows-AppxDeployment-Server/Operational'
    'Microsoft-Windows-AppxDeploymentServer/Operational'
    'Microsoft-Windows-AppxPackaging/Operational'
    # MDM / Intune
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug'
    # Company Portal / auth
    'Microsoft-Windows-AAD/Operational'
    'Microsoft-Windows-User Device Registration/Admin'
    'Microsoft-Windows-PushNotification-Platform/Operational'
    # Store (CP is a Store app)
    'Microsoft-Windows-Store/Operational'
    # Transfer
    'Microsoft-Windows-Bits-Client/Operational'
    # Certificate chain validation (enabled at trace start, restored at trace stop)
    'Microsoft-Windows-CAPI2/Operational'
    # App install service
    'Microsoft-Windows-AppReadiness/Operational'
    'Microsoft-Windows-AppReadiness/Admin'
    # v1.2.0: Delivery Optimization (content download for Win32 + Store + updates)
    'Microsoft-Windows-DeliveryOptimization/Operational'
    'Microsoft-Windows-DeliveryOptimization/Analytic'
    # v1.2.0: Windows Update (WU stack drives DO and surfaces app-download errors)
    'Microsoft-Windows-WindowsUpdateClient/Operational'
    'Microsoft-Windows-WUSA/Operational'
    # Task sched (IME runs via scheduled task)
    'Microsoft-Windows-TaskScheduler/Operational'
    # Noisy big channels, time-filtered
    'Application'
    'System'
)

Invoke-Safe 'event log exports (trace window)' {
    $ok = 0; $skip = 0
    foreach ($ch in $appChannels) {
        if (New-EventLogExport -Channel $ch -OutDir $evtDir -StartUtc $winStart -EndUtc $winEnd) { $ok++ } else { $skip++ }
    }
    Write-CLog "       exported $ok  /  unavailable $skip"
}

# v1.2.0: WinGet diagnostic logs (Store apps deployed via WinGet COM + Intune-managed
# packages via WPM). Walks every user profile - the interactive user may not be
# the elevated admin running this script, same reasoning as Collect-IntuneLogs.
Invoke-Safe 'WinGet logs (trace window)' {
    $wingetDir = $script:FilesGeneral
    $copied = 0
    $usersRoot = 'C:\Users'
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $diag = Join-Path $_.FullName 'AppData\Local\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir'
            if (-not (Test-Path -LiteralPath $diag)) { return }
            $dst = Join-Path $wingetDir ("WinGet_" + $_.Name)
            Get-ChildItem -LiteralPath $diag -File -Recurse -ErrorAction SilentlyContinue |
                Where-Object { $_.LastWriteTime -ge $script:TraceStartedAt.AddSeconds(-30) } |
                ForEach-Object {
                    Ensure-Dir $dst
                    Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction SilentlyContinue
                    $copied++
                }
        }
    }
    # WPM (WinGet Package Manager) text logs used for Intune-managed Store apps.
    # These live under SYSTEM temp since IME runs as SYSTEM for WPM.
    $wpmSrc = [Environment]::ExpandEnvironmentVariables('%SystemRoot%\Temp\WinGet\defaultState')
    if (Test-Path -LiteralPath $wpmSrc) {
        $wpmDst = $script:FilesWPM
        Get-ChildItem -LiteralPath $wpmSrc -Filter 'WPM-*.txt' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $script:TraceStartedAt.AddSeconds(-30) } |
            ForEach-Object {
                Ensure-Dir $wpmDst
                Copy-Item -LiteralPath $_.FullName -Destination $wpmDst -Force -ErrorAction SilentlyContinue
                $copied++
            }
    }
    Write-CLog "       copied $copied WinGet/WPM files (trace window)"
}

# v1.2.0: Delivery Optimization logs via Get-DeliveryOptimizationLog. The cmdlet
# reads the DO ETLs and returns structured text; we filter to the trace window.
# This is the primary artifact for diagnosing content-download problems during
# Win32 + Store deployments.
Invoke-Safe 'Delivery Optimization log (trace window)' {
    # v1.2.2: user-specified ODC convention:
    # %COMPUTERNAME%_Get-DeliveryOptimizationLog.txt under Intune\Commands\General
    $doOut = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'Get-DeliveryOptimizationLog'
    try {
        # Get-DeliveryOptimizationLog emits objects with a TimeCreated property
        # whose values are stored as UTC but reported with DateTimeKind=Unspecified -
        # so the same comparison must happen against UTC trace bounds. v1.2.2 used
        # local-time bounds, which silently dropped every entry on non-UTC hosts.
        # v1.2.3 also: (a) widens the pad to 2 minutes, (b) on empty result, dumps
        # the full log unfiltered (matches ODC behavior - the trace window is still
        # documented in _Summary.txt for cross-correlation).
        $padSec  = 120
        $winStartUtc = $script:TraceStartedAt.ToUniversalTime().AddSeconds(-$padSec)
        $winEndUtc   = $script:TraceEndedAt.ToUniversalTime().AddSeconds($padSec)
        $allDo = Get-DeliveryOptimizationLog -ErrorAction Stop
        $doEntries = $allDo | Where-Object {
            $tc = if ($_.TimeCreated.Kind -eq [System.DateTimeKind]::Local) {
                      $_.TimeCreated.ToUniversalTime()
                  } else {
                      # Unspecified or Utc - treat as UTC (matches DO log convention)
                      [System.DateTime]::SpecifyKind($_.TimeCreated, [System.DateTimeKind]::Utc)
                  }
            $tc -ge $winStartUtc -and $tc -le $winEndUtc
        }
        $useFull = $false
        if (-not $doEntries) {
            # Fallback: full log (matches ODC). Better to over-collect than to lose data.
            $doEntries = $allDo
            $useFull = $true
        }
        if ($doEntries) {
            $doEntries | ForEach-Object {
                "{0} | {1} | {2} | {3} | {4}" -f `
                    $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss.fff'),
                    $_.ProcessId,
                    $_.ThreadId,
                    $_.Level,
                    $_.Message
            } | Out-File -FilePath $doOut -Encoding UTF8
            if ($useFull) {
                Write-CLog ("       no entries in window; captured full log ({0} entries)" -f $doEntries.Count) -Level WARN
            } else {
                Write-CLog ("       captured {0} DO log entries" -f $doEntries.Count)
            }
        } else {
            'Get-DeliveryOptimizationLog returned no entries.' | Out-File -FilePath $doOut -Encoding UTF8
            Write-CLog '       Get-DeliveryOptimizationLog returned no entries' -Level WARN
        }
    } catch {
        "Get-DeliveryOptimizationLog unavailable: $($_.Exception.Message)" |
            Out-File -FilePath $doOut -Encoding UTF8
    }
    # Raw DO ETLs (for external analysis if needed - tracerpt, Message Analyzer, etc.)
    $doEtlSrc = [Environment]::ExpandEnvironmentVariables('%WinDir%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs')
    if (Test-Path -LiteralPath $doEtlSrc) {
        $doEtlDst = Join-Path $script:FilesIntune 'DeliveryOptimization_ETL'
        Get-ChildItem -LiteralPath $doEtlSrc -Filter '*.etl' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $script:TraceStartedAt.AddSeconds(-30) } |
            ForEach-Object {
                Ensure-Dir $doEtlDst
                Copy-Item -LiteralPath $_.FullName -Destination $doEtlDst -Force -ErrorAction SilentlyContinue
            }
    }
}

# v1.2.0: Windows Update log. The text WindowsUpdate.log was removed in Win10;
# Get-WindowsUpdateLog merges the current ETLs into a text file on demand.
# We also copy any ETLs modified during the trace window for raw analysis.
Invoke-Safe 'Windows Update log (trace window)' {
    # v1.2.2: %COMPUTERNAME%_WindowsUpdate.log convention, Commands\General
    $wuOut = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'WindowsUpdate' -Extension '.log'
    try {
        # Get-WindowsUpdateLog writes to a specified path. Suppress its own Write-Host
        # output (it announces "Windows Update logs successfully converted"). Sort=true
        # so entries are chronological.
        $null = Get-WindowsUpdateLog -LogPath $wuOut -ErrorAction Stop 4>$null 5>$null 6>$null
        if (Test-Path -LiteralPath $wuOut) {
            $sizeKB = [int]((Get-Item -LiteralPath $wuOut).Length / 1KB)
            Write-CLog "       generated WindowsUpdate.log ($sizeKB KB) - operator may want to grep for trace window timestamps"
        }
    } catch {
        "Get-WindowsUpdateLog unavailable: $($_.Exception.Message)" |
            Out-File -FilePath $wuOut -Encoding UTF8
        Write-CLog "       Get-WindowsUpdateLog failed: $($_.Exception.Message)" -Level WARN
    }
    # Raw WU ETLs modified during the trace window
    $wuEtlSrc = [Environment]::ExpandEnvironmentVariables('%WinDir%\Logs\WindowsUpdate')
    if (Test-Path -LiteralPath $wuEtlSrc) {
        $wuEtlDst = Join-Path $script:FilesIntune 'WindowsUpdate_ETL'
        Get-ChildItem -LiteralPath $wuEtlSrc -Filter '*.etl' -File -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTime -ge $script:TraceStartedAt.AddSeconds(-30) } |
            ForEach-Object {
                Ensure-Dir $wuEtlDst
                Copy-Item -LiteralPath $_.FullName -Destination $wuEtlDst -Force -ErrorAction SilentlyContinue
            }
    }
}

# --- Registry: IME + EnterpriseDesktopAppManagement + PolicyManager apps ---
Invoke-Safe 'registry (end-state IME + app mgmt)' {
    $regKeys = @(
        'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension',
        'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement',
        'HKLM\SOFTWARE\Microsoft\EnterpriseModernAppManagement',
        'HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\EnterpriseModernAppManagement',
        'HKLM\SOFTWARE\Microsoft\Provisioning\NodeCache\CSP',
        'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
    )
    foreach ($k in $regKeys) { Export-RegKey -Key $k -OutDir $regDir }
}

# --- End-state installed apps ---
Invoke-Safe 'end-state: installed apps' {
    Get-InstalledAppInventory | Export-Csv -Path (Get-CmdOutPath -Dir $cmdDir -OutputFileName 'installed_apps_endstate' -Extension '.csv') -NoTypeInformation
}

# v1.2.1: end-state AppX inventory for Store/MSIX diff
Invoke-Safe 'end-state: AppX/MSIX inventory' {
    try {
        Get-AppxPackage -AllUsers -ErrorAction Stop |
            Select-Object Name, Version, PackageFullName, Publisher,
                          @{n='Users';e={ ($_.PackageUserInformation | ForEach-Object { $_.UserSecurityId.Username }) -join '; ' }} |
            Export-Csv -Path (Get-CmdOutPath -Dir $cmdDir -OutputFileName 'appx_endstate' -Extension '.csv') -NoTypeInformation
    } catch {
        "Get-AppxPackage -AllUsers failed: $($_.Exception.Message)" | Out-File (Get-CmdOutPath -Dir $cmdDir -OutputFileName 'appx_endstate' -Extension '.csv') -Encoding UTF8
    }
}

# --- App install diff (baseline vs end-state) ---
Invoke-Safe 'diff: apps added / removed / changed during trace window' {
    $baseCsv = Join-Path $baseDir 'installed_apps_baseline.csv'
    $endCsv  = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'installed_apps_endstate' -Extension '.csv'
    $out = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'installed_apps_diff'

    # --- Win32/MSI diff (registry Uninstall) ---
    if ((Test-Path $baseCsv) -and (Test-Path $endCsv)) {
        $bk = @{}
        Import-Csv $baseCsv | ForEach-Object { $bk[("{0}|{1}|{2}" -f $_.DisplayName, $_.DisplayVersion, $_.Scope)] = $_ }
        $ek = @{}
        Import-Csv $endCsv  | ForEach-Object { $ek[("{0}|{1}|{2}" -f $_.DisplayName, $_.DisplayVersion, $_.Scope)] = $_ }

        $added   = $ek.Keys | Where-Object { -not $bk.ContainsKey($_) } | ForEach-Object { $ek[$_] }
        $removed = $bk.Keys | Where-Object { -not $ek.ContainsKey($_) } | ForEach-Object { $bk[$_] }

        'WIN32 / MSI / EXE APPS' | Out-File $out -Encoding UTF8
        '=======================' | Out-File $out -Encoding UTF8 -Append
        '(source: HKLM + HKCU Uninstall registry keys)' | Out-File $out -Encoding UTF8 -Append
        '' | Out-File $out -Encoding UTF8 -Append
        'Added during trace window:' | Out-File $out -Encoding UTF8 -Append
        '-' * 50 | Out-File $out -Encoding UTF8 -Append
        if ($added) {
            $added | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher, Scope, InstallDate -AutoSize |
                Out-String -Width 300 | Out-File $out -Encoding UTF8 -Append
        } else {
            '(none)' | Out-File $out -Encoding UTF8 -Append
        }
        '' | Out-File $out -Encoding UTF8 -Append
        'Removed during trace window:' | Out-File $out -Encoding UTF8 -Append
        '-' * 50 | Out-File $out -Encoding UTF8 -Append
        if ($removed) {
            $removed | Sort-Object DisplayName | Format-Table DisplayName, DisplayVersion, Publisher, Scope, InstallDate -AutoSize |
                Out-String -Width 300 | Out-File $out -Encoding UTF8 -Append
        } else {
            '(none)' | Out-File $out -Encoding UTF8 -Append
        }
    } else {
        'WIN32 / MSI / EXE APPS' | Out-File $out -Encoding UTF8
        '(baseline or endstate CSV missing, skipping diff)' | Out-File $out -Encoding UTF8 -Append
    }

    # v1.2.1: --- AppX/MSIX/Store diff (Get-AppxPackage) ---
    # Store apps deployed via EnterpriseModernAppManagement CSP (Company Portal
    # click through) don't appear in HKLM\...\Uninstall. The registry path for
    # them is AppModel\Repository\Packages under HKCU per-user, but the
    # supported query is Get-AppxPackage.
    '' | Out-File $out -Encoding UTF8 -Append
    '' | Out-File $out -Encoding UTF8 -Append
    'STORE / MSIX / APPX PACKAGES' | Out-File $out -Encoding UTF8 -Append
    '============================' | Out-File $out -Encoding UTF8 -Append
    '(source: Get-AppxPackage -AllUsers; diff on PackageFullName)' | Out-File $out -Encoding UTF8 -Append
    '' | Out-File $out -Encoding UTF8 -Append

    $baseAppx = Join-Path $baseDir 'appx_baseline.csv'
    $endAppx  = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'appx_endstate' -Extension '.csv'
    if ((Test-Path $baseAppx) -and (Test-Path $endAppx)) {
        $bpk = @{}
        try { Import-Csv $baseAppx -ErrorAction Stop | ForEach-Object { if ($_.PackageFullName) { $bpk[$_.PackageFullName] = $_ } } } catch {}
        $epk = @{}
        try { Import-Csv $endAppx  -ErrorAction Stop | ForEach-Object { if ($_.PackageFullName) { $epk[$_.PackageFullName] = $_ } } } catch {}

        $appxAdded   = $epk.Keys | Where-Object { -not $bpk.ContainsKey($_) } | ForEach-Object { $epk[$_] }
        $appxRemoved = $bpk.Keys | Where-Object { -not $epk.ContainsKey($_) } | ForEach-Object { $bpk[$_] }

        # Also detect version upgrades (Name same but PackageFullName changed)
        $baseNames = @{}; foreach ($p in $bpk.Values) { if ($p.Name) { $baseNames[$p.Name] = $p } }
        $endNames  = @{}; foreach ($p in $epk.Values) { if ($p.Name) { $endNames[$p.Name]  = $p } }
        $upgraded = @()
        foreach ($n in $endNames.Keys) {
            if ($baseNames.ContainsKey($n) -and
                $baseNames[$n].PackageFullName -ne $endNames[$n].PackageFullName) {
                $upgraded += [PSCustomObject]@{
                    Name            = $n
                    FromVersion     = $baseNames[$n].Version
                    ToVersion       = $endNames[$n].Version
                    FromPackageFull = $baseNames[$n].PackageFullName
                    ToPackageFull   = $endNames[$n].PackageFullName
                    Publisher       = $endNames[$n].Publisher
                }
            }
        }

        'Added during trace window:' | Out-File $out -Encoding UTF8 -Append
        '-' * 50 | Out-File $out -Encoding UTF8 -Append
        if ($appxAdded) {
            $appxAdded | Sort-Object Name | Format-Table Name, Version, Publisher, PackageFullName -AutoSize |
                Out-String -Width 400 | Out-File $out -Encoding UTF8 -Append
        } else {
            '(none)' | Out-File $out -Encoding UTF8 -Append
        }
        '' | Out-File $out -Encoding UTF8 -Append
        'Removed during trace window:' | Out-File $out -Encoding UTF8 -Append
        '-' * 50 | Out-File $out -Encoding UTF8 -Append
        if ($appxRemoved) {
            $appxRemoved | Sort-Object Name | Format-Table Name, Version, Publisher, PackageFullName -AutoSize |
                Out-String -Width 400 | Out-File $out -Encoding UTF8 -Append
        } else {
            '(none)' | Out-File $out -Encoding UTF8 -Append
        }
        '' | Out-File $out -Encoding UTF8 -Append
        'Upgraded during trace window (same Name, different PackageFullName):' | Out-File $out -Encoding UTF8 -Append
        '-' * 50 | Out-File $out -Encoding UTF8 -Append
        if ($upgraded) {
            $upgraded | Sort-Object Name | Format-Table Name, FromVersion, ToVersion, Publisher -AutoSize |
                Out-String -Width 400 | Out-File $out -Encoding UTF8 -Append
        } else {
            '(none)' | Out-File $out -Encoding UTF8 -Append
        }
    } else {
        '(baseline or endstate AppX CSV missing, skipping diff)' | Out-File $out -Encoding UTF8 -Append
    }
}

# --- IME log error scan ---
Invoke-Safe 'IME delta: scan for errors/warnings' {
    $deltaDir = Join-Path $trcDir 'IME_Delta'
    $out = Join-Path $trcDir 'IME_Delta_Errors.txt'
    if (-not (Test-Path -LiteralPath $deltaDir)) { return }
    "IME delta log entries matching Error / Warning / Exception / Failed during trace window:" | Out-File $out -Encoding UTF8
    "=================================================================================" | Out-File $out -Encoding UTF8 -Append
    Get-ChildItem -LiteralPath $deltaDir -File -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name
        "" | Out-File $out -Encoding UTF8 -Append
        "=== $name ===" | Out-File $out -Encoding UTF8 -Append
        Select-String -LiteralPath $_.FullName -Pattern '(?i)\b(error|exception|failed|failure|warn(ing)?)\b' -ErrorAction SilentlyContinue |
            ForEach-Object { "L$($_.LineNumber): $($_.Line.Trim())" } |
            Out-File $out -Encoding UTF8 -Append
    }
}

#endregion

#region Summary

# v1.2.2: Intune.xml manifest at stage root (ODC convention). Enumerates every
# collected file under Package>Collection>CollectedItem. Win32 Analyzer and
# Store Analyzer parse this to drive their collection-status view.
Invoke-Safe 'write Intune.xml manifest' {
    $manifestPath = Join-Path $script:StageRoot 'Intune.xml'
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine('<?xml version="1.0" encoding="utf-8"?>')
    [void]$sb.AppendLine('<DataPoints xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="urn:Microsoft.One.DataCollector">')
    [void]$sb.AppendLine('  <Package ID="Intune">')

    $sections = @{}
    if (Test-Path -LiteralPath $script:IntuneRoot) {
        Get-ChildItem -LiteralPath $script:IntuneRoot -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                $rel = $_.FullName.Substring($script:IntuneRoot.Length).TrimStart('\')
                $parts = $rel -split '\\'
                if ($parts.Count -lt 2) { return }
                $section = $parts[0]
                $team    = if ($parts.Count -ge 3) { $parts[1] } else { '(root)' }
                $key = "$section|$team"
                if (-not $sections.ContainsKey($key)) { $sections[$key] = @() }
                $sections[$key] += [PSCustomObject]@{
                    Path = "Intune\$rel"
                    Name = $_.Name
                    Size = $_.Length
                }
            }
    }

    foreach ($key in ($sections.Keys | Sort-Object)) {
        $split = $key -split '\|', 2
        $section = $split[0]; $team = $split[1]
        $collectionName = "$section`_$team"
        $colEsc = [System.Security.SecurityElement]::Escape($collectionName)
        $teamEsc = [System.Security.SecurityElement]::Escape($team)
        [void]$sb.AppendLine(('    <Collection Name="{0}" Section="{1}" Team="{2}">' -f $colEsc, $section, $teamEsc))
        foreach ($f in $sections[$key]) {
            $pEsc = [System.Security.SecurityElement]::Escape($f.Path)
            $nEsc = [System.Security.SecurityElement]::Escape($f.Name)
            [void]$sb.AppendLine(('      <CollectedItem Path="{0}" FileName="{1}" Status="Collected" SizeBytes="{2}" />' -f $pEsc, $nEsc, $f.Size))
        }
        [void]$sb.AppendLine('    </Collection>')
    }

    [void]$sb.AppendLine('  </Package>')
    [void]$sb.AppendLine('</DataPoints>')
    $sb.ToString() | Out-File -FilePath $manifestPath -Encoding UTF8
    Write-CLog ("       manifest: {0} collections" -f $sections.Count)
}

Invoke-Safe 'write _Summary.txt' {
    $elapsed = (Get-Date) - $script:StartTime
    $traceDur = $script:TraceEndedAt - $script:TraceStartedAt
    $stageSize = 0
    Get-ChildItem -LiteralPath $script:StageRoot -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { $stageSize += $_.Length }

    $lines = @()
    $lines += "Trace-IntuneAppDeploy v$APP_VERSION  ($APP_BUILD)"
    $lines += ''
    $lines += "Run start         : $($script:StartTime.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Run end           : $((Get-Date).ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Run elapsed       : {0:N0} seconds" -f $elapsed.TotalSeconds
    $lines += ''
    $lines += "Trace started     : $($script:TraceStartedAt.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Trace ended       : $($script:TraceEndedAt.ToString('yyyy-MM-dd HH:mm:ss'))"
    $lines += "Trace duration    : {0:N0} seconds ({1:N1} min)" -f $traceDur.TotalSeconds, $traceDur.TotalMinutes
    $lines += "Stop reason       : $(if ($userInterrupted) {'operator'} else {'auto-timeout'})"
    $lines += ''
    $lines += "Computer          : $script:Computer"
    $lines += "User              : $env:USERDOMAIN\$env:USERNAME"
    $lines += "MaxMinutes        : $MaxMinutes"
    $lines += "NetworkTrace      : $(-not $NoNetworkTrace)"
    if (-not $NoNetworkTrace) {
        $lines += "  netsh etl       : $script:NetTraceEtl"
        if (Test-Path -LiteralPath $script:NetTraceEtl) {
            $lines += "  netsh etl size  : {0:N2} MB" -f ((Get-Item -LiteralPath $script:NetTraceEtl).Length/1MB)
        }
    }
    $lines += ''
    $lines += "Stage dir         : $script:StageRoot"
    $lines += "Stage size        : {0:N2} MB" -f ($stageSize/1MB)
    $lines += "Zip target        : $script:ZipPath"

    # App diff summary
    $diffPath = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'installed_apps_diff'
    if (Test-Path -LiteralPath $diffPath) {
        $lines += ''
        $lines += '--- APP INSTALL DIFF ---'
        $lines += Get-Content -LiteralPath $diffPath
    }

    $lines | Out-File -FilePath $script:Summary -Encoding UTF8
}

#endregion

#region Compress

Invoke-Safe 'compress to ZIP' {
    if (Test-Path -LiteralPath $script:ZipPath) {
        Remove-Item -LiteralPath $script:ZipPath -Force -ErrorAction SilentlyContinue
    }
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $script:StageRoot,
        $script:ZipPath,
        [System.IO.Compression.CompressionLevel]::Optimal,
        $false
    )
}

if (Test-Path -LiteralPath $script:ZipPath) {
    $zipSize = (Get-Item -LiteralPath $script:ZipPath).Length
    # Clean stage (ZIP is the deliverable)
    Remove-Item -LiteralPath $script:StageRoot -Recurse -Force -ErrorAction SilentlyContinue

    Write-Host ''
    Write-Host '==============================================================' -ForegroundColor Green
    Write-Host ('  ZIP: {0} ({1:N2} MB)' -f $script:ZipPath, ($zipSize/1MB)) -ForegroundColor Green
    Write-Host '==============================================================' -ForegroundColor Green
    Write-Host ''

    if (-not $NoOpen) {
        Start-Process -FilePath explorer.exe -ArgumentList "/select,`"$script:ZipPath`""
    }
} else {
    Write-Host ''
    Write-Host ("ZIP creation failed. Staging retained at: $script:StageRoot") -ForegroundColor Red
    Write-Host ''
}

#endregion
