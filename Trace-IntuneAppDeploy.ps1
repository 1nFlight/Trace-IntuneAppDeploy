#Requires -Version 5.1
<#
.SYNOPSIS
    Live trace collector for Intune Company Portal Win32 / MSIX / LOB app deployments.

.DESCRIPTION
    Companion to Collect-IntuneLogs.ps1. Whereas that tool captures a *snapshot*
    after-the-fact, this one captures a *trace* across a known user-initiated
    deployment window:

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
    # One-liner
    irm https://raw.githubusercontent.com/1nFlight/ODC-Reduced/main/Trace-IntuneAppDeploy.ps1 | iex

.NOTES
    Requires administrator elevation.
    Requires console host (not PowerShell ISE) for the live-tail UX.
    Do not run concurrently with another netsh trace session  -  this script
    aborts with a clear error if one is already active.

    Changelog:
        1.3.6  2026-04-24  Forward-ported three published fixes from the
                           1.2.x branch that v1.3.0-1.3.5 had regressed:

                           (1) UTF-8 BOM removal. v1.3.0-1.3.5 were saved
                               with BOM, which 'irm <url> | iex' surfaces
                               as a literal U+FEFF character at position 0,
                               making the parser stop recognizing the
                               leading '#Requires -Version 5.1' as a
                               directive and erroring on [CmdletBinding()]
                               / param(). File now saved as UTF-8 no-BOM
                               with LF line endings (.gitattributes in
                               the repo enforces this).

                           (2) DO log Format-List emission. v1.3.0-1.3.5
                               wrote Get-DeliveryOptimizationLog output as
                               a flat pipe-separated single-line-per-entry
                               format. The downstream Store / Win32 HTML
                               analyzers parse the DO log as Format-List
                               style blocks (Key : Value lines, blank line
                               between records). That mismatch made every
                               DO job invisible: the analyzer would load
                               the (multi-MB) file and still report 'No
                               Delivery Optimization jobs in this log'.
                               Now emits proper blocks with TimeCreated
                               normalized to ISO-8601 UTC plus LevelName
                               / Function / ErrorCode / LineNumber /
                               Message fields. Validated against parseDOLog
                               with synthesized input (3 events -> 1 fully
                               populated job).

                           (3) DO log UTC timezone fix. The cmdlet returns
                               TimeCreated as UTC values stored with
                               DateTimeKind=Unspecified. v1.3.0-1.3.5
                               compared those against local-time trace
                               bounds, silently dropping every entry on
                               non-UTC hosts. Window comparison now
                               normalizes both sides to UTC, with a 120s
                               pad and a full-log fallback when the window
                               returns empty (matches ODC behavior - the
                               trace window stays documented in
                               _Summary.txt for cross-correlation).

        1.3.5  2026-04-22  TLS/CAPI diagnostic coverage. The NetTrace
                           Analyzer's CAPI/TLS detection pipeline expects
                           three event channels that were missing from
                           Trace ZIPs:

                           (1) Microsoft-Windows-CAPI2/Operational -
                               certificate chain validation failures
                               (untrusted root, expired cert, revoked
                               cert, CRL/OCSP retrieval errors). This is
                               the dominant silent-failure mode when a
                               MITM proxy or broken CRL endpoint breaks
                               TLS to Intune/Store endpoints.

                           (2) Microsoft-Windows-Schannel-Events/
                               Operational - TLS protocol negotiation,
                               cipher suite issues.

                           (3) Microsoft-Windows-WinHTTP/Operational -
                               WinHTTP-level handshake and request
                               failures (relevant to IME which uses
                               WinHTTP for calls to manage.microsoft.com).

                           All three channels are now in the event export
                           list. Second part: opt-in -CaptureTlsDiagnostics
                           switch that enables CAPI2/Operational at trace
                           start and disables it after. CAPI2 is an
                           Analytic channel disabled by default on Windows,
                           so without the switch the CAPI2.evtx export
                           will be empty on most devices. With the switch:

                           - Checks current channel state via 'wevtutil
                             gl' to detect pre-existing enablement
                           - Only disables the channel at cleanup IF we
                             were the ones who enabled it (preserves
                             system state if CAPI2 was already on when
                             we started)
                           - Disable happens right after 'netsh trace
                             stop' but BEFORE the event-log export block
                             - mandatory ordering because analytic
                             channels with circular retention cannot be
                             exported while enabled (per MS docs:
                             "you must first disable that log before you
                             can view the events")
                           - Does NOT touch Schannel's EventLogging
                             registry value. Increasing SChannel log
                             verbosity beyond default (errors-only)
                             requires a reboot to take effect -
                             incompatible with in-situ trace semantics.
                             Operators who need full SChannel detail
                             must pre-configure the registry and reboot
                             before starting the trace.

                           Usage:
                             .\Trace-IntuneAppDeploy.ps1 -CaptureTlsDiagnostics

                           Note on volume: CAPI2 can generate tens of
                           thousands of events per minute on a busy
                           system. A 15-minute trace with active TLS
                           activity may produce ~200K CAPI2 events.
                           The channel is reset to disabled at trace
                           end regardless of -CaptureTlsDiagnostics so
                           the enable window is bounded.

        1.3.4  2026-04-22  Root cause identified and fixed:

                           The v1.3.3 diagnostic caught the failure on
                           EVERY record ("12 app record(s) skipped during
                           emit build") with message "Argument types do
                           not match" at step=build-object (the
                           $appsArr += [ordered]@{...} construction).

                           Root cause: PowerShell's hashtable-literal
                           construction evaluates every value expression
                           as a single binder invocation. When the literal
                           contains both $null values and [HashSet[string]]
                           values (even after @()-coercion), PS 7 can
                           throw "Argument types do not match" in
                           System.Linq.Expressions.Expression.Constant
                           during the dynamic call-site binding. This is
                           a known class of issue
                           (PowerShell/PowerShell#8661, similar to
                           [Math]::Round($null) failing with the same
                           message).

                           Fix: replaced $appsArr += [ordered]@{...} with
                           explicit PSCustomObject + Add-Member builds,
                           one property at a time. PSCustomObject property
                           assignment goes through a simpler code path
                           that accepts heterogeneous types without the
                           dynamic binder constraint. This matches the
                           pattern all modern PowerShell JSON serialization
                           code uses.

                           Also:
                           - HashSet[string] -> array materialized
                             explicitly with foreach loops writing [string]
                             values instead of @() coercion, so output is
                             guaranteed homogeneous string[].
                           - Timeline entries rebuilt as PSCustomObject
                             one field at a time (they were
                             OrderedDictionary from Add-Timeline).
                           - Added $lastFailStep to the per-record error
                             log so the failing construction stage is
                             visible if something still breaks, not just
                             the exception message.
                           - Switched $appsArr from @() to
                             System.Collections.Generic.List[object] for
                             O(1) append; final .ToArray() at end.

        1.3.3  2026-04-22  v1.3.2 still crashed with "Argument types do not
                           match" after CP FinalStatus pass but before
                           correlation_map.json was written. The actual bug
                           could be in one of several places: the scriptblock
                           $toIso invocation via & operator, a specific app
                           record with an unexpected field type from merge
                           operations, or ConvertTo-Json hitting a timeline
                           entry with some DateTime residue.

                           Rather than play whack-a-mole on every possible
                           root cause, this version restructures the emit
                           path so any single-record failure cannot abort
                           the whole block:

                           (1) $appsArr build loop wraps EACH record in its
                           own try/catch. If one record's field conversion
                           throws, it's skipped and we continue. A counter
                           and lastFailKey/lastFailMsg surface which record
                           failed and why, logged via Write-CLog -Level
                           ERROR so the collector output names the bad
                           record directly.

                           (2) Dropped the $toIso scriptblock indirection.
                           Inline DateTime -> ISO conversion with explicit
                           $null -eq checks and [datetime] type tests.
                           One less abstraction layer for the error to
                           hide behind.

                           (3) Per-record ordered dict now uses local
                           variables ($fsStr, $lsStr, $wgIds, $doIds, $hrs,
                           $ops, $tl) populated piece by piece with null
                           guards, then assembled. If a field value is
                           pathological, we see which one in the per-record
                           catch.

                           (4) ConvertTo-Json wrapped in its own try/catch
                           with a minimal-fallback emit path. If the full
                           correlation structure can't serialize, we still
                           write a skeleton JSON with the error message.

                           (5) Snapshot $apps.Keys via @($apps.Keys) before
                           iterating, so if any upstream code mutates the
                           dict during iteration we still complete the
                           pass on the original key set.

                           Net effect: the collector ZIP always contains
                           correlation_map.json (even if minimal) and the
                           _Collector.log gets a precise diagnostic pointer
                           to the exact record that broke, not a generic
                           "Argument types do not match" with no context.

                           The underlying cause of the exception will now
                           be visible in the _Collector.log (or its WARN
                           line) as the lastFailMsg/lastFailKey, which we
                           can use to fix the specific field handling in
                           v1.3.4 if needed.
        1.3.2  2026-04-22  Flow summary emit crashed with "Argument types
                           do not match" when sorting $appsArr by
                           first_seen. Mix of ISO-8601 string and $null
                           values in that field breaks
                           Sort-Object -Property { ... } scriptblock form
                           in PowerShell 7.x. Replaced with the hashtable
                           Expression form that coerces $null to a
                           sentinel string that sorts last, so apps with
                           real timestamps come first and CP-only records
                           (ones CP saw but AppWorkload did not this
                           trace) come after.

                           Side effect in v1.3.1: when this sort threw,
                           the entire Invoke-Safe block aborted BEFORE
                           correlation_map.json and _FlowSummary.txt were
                           written, even though CP FinalStatus parsing
                           had already produced 14 app-state entries and
                           AppWorkload had matched 14 correlation events.
                           All that work was discarded. Fix ensures the
                           two output artifacts land even if downstream
                           rendering has issues.
        1.3.1  2026-04-22  Three bugs in v1.3.0 surfaced by the first live
                           collection run, plus one new correlation pass:

                           (1) Correlation pass crashed on
                           "Cannot overwrite variable PID because it is
                           read-only or constant." Root cause: used $pid
                           as a local variable in the WinGet Store-handoff
                           match block. $PID is a PowerShell automatic
                           variable (current process ID), always read-only.
                           Renamed to $productId.

                           (2) baseline: user session context (JSON) failed
                           with "cannot call a method on a null-valued
                           expression". Two causes: $script:TraceStartedAt
                           was referenced from baseline section but it is
                           not set until the trace start section (line 926,
                           baseline runs earlier). Replaced with Get-Date
                           captured at the time the baseline block runs.
                           Also hardened .ToString() calls on
                           Get-AppxPackage fields (Version, InstallState,
                           UserSecurityId) that can be null on framework
                           apps.

                           (3) WinGet collection aggregate totals showed
                           "total: 0 file(s) across 5 source(s); 0 in-
                           window, 0 historical, 0 WPM" even though the
                           per-source lines correctly showed 43 files
                           total with tagging working. Root cause:
                           Measure-Object -Property X cannot read named
                           fields off [ordered]@{} dictionary items.
                           Replaced with explicit accumulation loop.

                           (4) NEW: Correlation pass now includes hop 10
                           (CP terminal state). CP's LocalState\<userGuid>
                           \FinalStatus.json is parsed per user and matched
                           to IME records by ApplicationKey GUID. Each app
                           record gets cp_terminal_state (int code),
                           cp_terminal_state_name (human label:
                           Installed / Failed / InstallInProgress / etc),
                           cp_device_key (Entra device id), and a
                           "CP:FinalStatus:<label>" timeline event at the
                           FinalStatus.json LastWriteTime.

                           Also discovered on first run: CP logs collection
                           is working. Per-user subfolders under
                           Files\CompanyPortalLogs\ contain the main
                           Log_N.log, the gold Log.IntuneManagementExtension
                           Bridge_N.log (CP<->IME handshake, tracks
                           "Received status update for Win32 application
                           <guid>"), Log.BridgeLauncher_N.log, and per-AAD-
                           user subfolders with the status JSON set
                           (AppxLocalAppStatus, Win32LocalAppStatus,
                           MsiLocalAppStatus, FinalStatus, etc). No
                           changes needed there - layout confirmed correct.

        1.3.0  2026-04-22  Full install-flow coverage for IME Company Portal
                           Store deployments. Addresses gaps exposed by real
                           traces where the store-analyzer v2.4.0 correctly
                           flagged signal missing despite channels being
                           captured. Four changes:

                           (1) Company Portal log collection no longer time-
                           filtered. CP's LocalState\Log_*.log files are
                           small and only get written when the user
                           interacts with the app. Filtering by LastWriteTime
                           against the trace window was zeroing out the
                           collection when users triggered installs BEFORE
                           starting the trace - the most common real case.
                           New behavior: full directory copy of LocalState,
                           LocalCache, TempState, RoamingState for every
                           user profile that has Microsoft.CompanyPortal_
                           8wekyb3d8bbwe. Files cap at a few MB per user;
                           well worth the ZIP size.

                           (2) WinGet log collection now mirrors ODC's
                           Intune.xml coverage. Previous versions only
                           captured C:\Windows\Temp\WinGet\defaultState
                           (SYSTEM-context). ODC's manifest collects from
                           FOUR paths; Trace was missing three of them:
                             - %SystemRoot%\Temp\WinGet\defaultState
                               (SYSTEM; had this)
                             - %LOCALAPPDATA%\Temp\WinGet\defaultState
                               (USER-context, walked per-profile; MISSING)
                             - %LOCALAPPDATA%\Packages\Microsoft.
                               DesktopAppInstaller_8wekyb3d8bbwe\
                               LocalState\DiagOutputDir
                               (DAI package log store; MISSING)
                             - WPM-*.txt files from any of the above
                               routed to Intune\Files\WPM\ per ODC
                               convention (MISSING)
                           SYSTEM logs stay flat in Files\General\ to
                           match ODC layout; per-user logs go under
                           Files\General\<UserName>\ to prevent filename
                           collisions across profiles. Filename-based
                           in-window tagging (WinGet-*-YYYY-MM-DD-HH-MM-SS
                           .mmm.log) applies to all paths: files inside
                           trace window +-120s keep original names, files
                           outside get "Historical__" prefix so the store
                           analyzer can segregate signal from noise. The
                           correlation pass recurses Files\General\ to
                           read per-user and SYSTEM winget logs together.

                           (3) dosvc.etl (raw Delivery Optimization ETL)
                           now captured from
                           %SystemRoot%\ServiceProfiles\NetworkService\
                           AppData\Local\Microsoft\Windows\
                           DeliveryOptimization\Logs\*.etl
                           Get-DeliveryOptimizationLog output is a textual
                           summary that the service re-renders from these
                           ETLs; when troubleshooting content-download
                           attribution (CDN hostname, content ID, peer
                           bytes, caller identity StoreInstaller vs
                           WinGet), the raw ETL is authoritative.
                           Copy-while-open is safe; no service stop needed.

                           (4) correlation_map.json + flow_summary.txt
                           post-processing pass. After all logs are
                           collected, a final pass walks AppWorkload.log,
                           AgentExecutor.log, WinGetCOM-*.log, and the key
                           event channels to extract every correlation ID
                           observed (IME ApplicationId, Store ProductId,
                           WinGet ActivityID, Store PackageFullName,
                           PackageFamilyName, HRESULTs) and joins them
                           into a single per-app record. Two outputs:
                             - Intune\Commands\General\
                               <computer>_correlation_map.json - machine-
                               readable pre-joined index for the analyzer
                               to load directly
                             - _FlowSummary.txt at ZIP root - human-
                               readable timeline of the install flow for
                               each app, from IME policy receipt to
                               terminal HRESULT (or "no terminal result
                               observed in trace window")

                           Event channel additions:
                             Microsoft-Windows-Push-To-Install/Admin
                             Microsoft-Windows-AppxDeployment/Operational
                             Microsoft-Windows-AppReadiness-API/Operational

                           User session context emission:
                             Intune\Commands\General\
                             <computer>_user_context.json captures logged-
                             on user SIDs, IME/dosvc service accounts, and
                             per-user CompanyPortal + DesktopAppInstaller
                             package registration. Lets the analyzer
                             correlate install-scope choices correctly.
        1.2.9  2026-04-22  Event log coverage gaps exposed by real trace:
                           winget->Store handoff showed no Store-side events
                           because Microsoft-Windows-Store/Operational is
                           Store UI-only (app launches, tile activation),
                           not deployment. Added the channels that actually
                           log Store backend operations:
                             Microsoft-Windows-StoreAgent/Admin
                             Microsoft-Windows-StoreAgent/Operational
                             Microsoft-Windows-StoreAgent-Diag/Operational
                             Microsoft-Windows-StoreAgent-Diag/Debug
                             Microsoft-Windows-TWinUI/Operational
                             Microsoft-Windows-Shell-Core/Operational
                             Microsoft-Windows-AppxPackaging/Debug
                           Also bumped window padding from 30s to 120s each
                           side. Real trace showed install events landing
                           20-60s BEFORE operator pressed ENTER - they
                           triggered the install then started the trace.
                           Event log exports are cheap (KB not MB), so the
                           wider window costs nothing and robustly catches
                           pre-trace activity.
        1.2.8  2026-04-22  Simplified SYSTEM-context WinGet collection per
                           user spec after real-world trace feedback.
                           Correct SYSTEM WinGet path when %TEMP% resolves
                           as NT AUTHORITY\SYSTEM is
                           C:\Windows\Temp\WinGet\defaultState - NOT
                           systemprofile\AppData\Local\Temp\WinGet as
                           previous versions assumed. IME's AgentExecutor
                           inherits SYSTEM's %TEMP% = C:\Windows\Temp,
                           so winget there writes to
                           C:\Windows\Temp\WinGet\defaultState.
                           Replaced the multi-profile/multi-path/
                           filename-timestamp-parsing logic with a straight
                           directory copy to match the ask:
                             - Copy all files from
                               C:\Windows\Temp\WinGet\defaultState
                               flat to Intune\Files\General
                             - No filename changes
                             - No per-profile subfolders
                             - No time filter (WinGet's own 100-file /
                               7-day retention bounds size)
                             - Skip cleanly if directory does not exist
                               (SYSTEM-context WinGet never ran)
                           Dropped: user-profile walk, filename-timestamp
                           regex, CreationTime fallback, per-profile
                           diagnostic counts, collision-guard GUID suffix,
                           WPM routing to Files\WPM, Temp\ subfolder for
                           non-WPM scratch. All unnecessary complexity for
                           the actual spec.
        1.2.7  2026-04-22  WinGet trace-window filter, v3 (correct approach).
                           v1.2.4 filtered by CreationTime/LastWriteTime and
                           missed sessions because the COM server keeps files
                           open long past session end, so timestamps drift.
                           v1.2.6 removed the filter entirely, which over-
                           collected (7 days of history). v1.2.7 parses the
                           session timestamp embedded in the filename itself -
                           WinGet creates log files named:
                             WinGet-YYYY-MM-DD-HH-MM-SS.mmm.log
                             WinGet-<pkg-id>-YYYY-MM-DD-HH-MM-SS.mmm.log
                             WinGetCOM-YYYY-MM-DD-HH-MM-SS.mmm.log
                           The timestamp in the filename maps 1:1 to session
                           start (when WinGet opened the file), independent of
                           when it was last written or closed. Filter:
                             [TraceStart - 60s, TraceEnd + 60s]
                           Falls back to CreationTime for files whose name
                           doesn't match the pattern (WPM-*.txt, settings
                           JSON, session scratch files under Temp\WinGet\).
                           Per-profile log now shows in-window vs total
                           candidates:
                             Announ: 3/47 file(s) in window (LocalState OK, Temp\WinGet OK)
                           3 WinGet sessions started during the trace out of
                           47 retained files across both directories.
        1.2.6  2026-04-22  Three fixes from real v1.2.2 trace feedback:
                           (1) dsregcmd_status.txt now emitted to BOTH
                               Baseline\ (pre-trace snapshot) AND
                               Intune\Commands\General\<COMPUTERNAME>_
                               dsregcmd_status.txt (ODC location the
                               analyzers scan).
                           (2) Baseline registry exports (IntuneManagementExt
                               + EnterpriseDesktopAppManagement) now emitted
                               to BOTH Baseline\ AND Intune\RegistryKeys\.
                               Analyzers pick them up via path classification.
                           (3) WinGet time filter REMOVED. v1.2.4-1.2.5 kept
                               filtering by CreationTime/LastWriteTime >=
                               TraceStart-60s. Real traces showed zero files
                               caught because the WinGet COM server keeps
                               session files open across hours and timestamps
                               don't reflect click time. WinGet's own retention
                               (100-file cap, 7 days) bounds the collection
                               size already. Now captures everything in
                               DiagOutputDir + any WinGet-*.log/WinGetCOM-*.log
                               anywhere under LocalState, no time filter.
                           Added per-profile diagnostic logging to
                           _Collector.log: each profile now reports copied
                           count + whether LocalState and Temp\WinGet paths
                           actually exist. Makes zero-file results debuggable:
                           you'll see "SYSTEM: 0 file(s) (no LocalState, no
                           Temp\WinGet)" vs "Announ: 0 file(s) (LocalState OK,
                           Temp\WinGet OK)" - the second case means the
                           operator had the paths but no actual WinGet
                           activity; the first case means SYSTEM-context WinGet
                           never ran on that machine.
        1.2.5  2026-04-22  Edge HAR manual-drop support.
                           Browser HAR fills a gap netsh trace can't: it shows
                           the user's decrypted HTTP traffic to the Intune web
                           Company Portal (portal.manage.microsoft.com) while
                           netsh trace captures the TLS-encrypted bytes.
                           Approach: operator manually captures HAR via Edge
                           DevTools during the trace window and drops the .har
                           file into <stage>\Network\ManualHAR\ before ENTER.
                           No CDP automation - the manual route is the standard
                           support-engineer workflow and avoids the operational
                           fragility of a DevTools Protocol client.
                           Changes:
                             - Pre-creates Network\ManualHAR\ at stage setup
                               (so the drop target exists before the banner
                               points to it).
                             - TRACE ACTIVE banner now includes HAR capture
                               instructions with the exact drop path.
                             - Post-trace step detects *.har files, validates
                               they're HAR 1.x JSON, extracts entry count +
                               hosts contacted, writes a _HAR_Summary.txt
                               alongside them. HARs > 50 MB are cataloged but
                               not parsed (time budget).
        1.2.4  2026-04-22  Three critical fixes after user reported empty
                           Files\General and missing CP logs from a real trace:
                           (1) WinGet Temp path was wrong: previous versions
                               checked %SystemRoot%\Temp\WinGet\defaultState
                               (C:\Windows\Temp\WinGet\defaultState) which is
                               NOT where WinGet writes. Corrected to
                               <profile>\AppData\Local\Temp\WinGet\ walked
                               recursively for every user profile + SYSTEM.
                               This is where WPM-*.txt and session-scoped
                               install logs actually land.
                           (2) Company Portal logs were missing entirely from
                               the Trace script (only Collect had them). Added
                               a dedicated CP collection step that walks every
                               user profile's CompanyPortal_8wekyb3d8bbwe
                               package, pulling LocalState, LocalCache,
                               TempState, RoamingState subfolders filtered to
                               the trace window.
                           (3) Time filter relaxed from LastWriteTime >=
                               TraceStart-30s to max(CreationTime, LastWriteTime)
                               >= TraceStart-60s. LastWriteTime-only was
                               missing files created before ENTER was pressed
                               but still being written during the trace (CP
                               open prior to trace start, for instance). The
                               60s pre-buffer catches that.
                           Also covers Temp\WinGet\ non-log extensions
                           (.txt, .json, .yaml, .xml) to get the full session
                           state, not just log files.
        1.2.3  2026-04-22  WinGet log gap fix (pairs with Collect v1.2.1).
                           v1.2.2 walked only C:\Users\*\AppData\Local\Packages\
                           Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\
                           LocalState\DiagOutputDir. When IME deploys Win32
                           apps via WinGet (AgentExecutor as SYSTEM), WinGet
                           writes WinGet-*.log / WinGetCOM-*.log to the SYSTEM
                           profile at C:\Windows\System32\config\systemprofile\
                           AppData\Local\Packages\...\LocalState\DiagOutputDir -
                           which wasn't captured.
                           Changes (same as Collect v1.2.1):
                             - SYSTEM profile added to walk
                             - Pattern broadened beyond DiagOutputDir subdir
                             - Output flattened under WinGet_<profile>\
                             - Filename collision guard
                           Trace-window LastWriteTime filter preserved.
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

    # v1.3.5: When set, enables Microsoft-Windows-CAPI2/Operational for the
    # trace window and disables it afterwards. CAPI2 is the authoritative
    # source for certificate chain validation failures (untrusted root,
    # expired, revoked, CRL/OCSP retrieval errors) which is the dominant
    # silent-failure mode when MITM proxies or broken CRL endpoints break
    # TLS to Intune/Store endpoints. Channel is disabled by default on
    # Windows; without this switch, CAPI2.evtx export will be empty.
    # Generates high event volume (tens of thousands per minute on busy
    # boxes). Disabled again in finally block even if trace script crashes.
    [switch]$CaptureTlsDiagnostics,

    [switch]$NoOpen
)

#region Constants

$APP_VERSION = '1.3.6'
$APP_BUILD   = '2026-04-22'

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
# v1.2.5: pre-create drop folder for operator-captured Edge HAR files.
# Browser HAR is scoped to traffic the *user's browser* makes to the Intune
# web portals - it complements (doesn't replace) the netsh trace, which
# catches IME/AgentExecutor/WinGet traffic invisible to the browser.
Ensure-Dir (Join-Path $script:StageRoot 'Network\ManualHAR')
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
    # v1.2.6: emit to both Baseline\ (pre-trace snapshot context) AND
    # Intune\Commands\General\ (ODC location where Win32/Store analyzers look).
    # The analyzers classify by path+filename regex, so they need the file at
    # the Intune\ location with the %COMPUTERNAME%_ prefix.
    $rawOut = & dsregcmd.exe /status 2>&1 | Out-String
    $rawOut | Out-File -FilePath (Join-Path $baseDir 'dsregcmd_status.txt') -Encoding UTF8
    $rawOut | Out-File -FilePath (Get-CmdOutPath -Dir $cmdDir -OutputFileName 'dsregcmd_status') -Encoding UTF8
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
    # v1.2.6: mirror to Intune\RegistryKeys\ too. Analyzers scan that path for
    # EDAM / IME registry exports; keeping a copy in Baseline\ preserves the
    # pre-trace context for diffing.
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension'    -OutDir $baseDir
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement' -OutDir $baseDir
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\IntuneManagementExtension'    -OutDir $regDir
    Export-RegKey -Key 'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement' -OutDir $regDir
}

# v1.3.0: User session context. Store-app install scope (User vs Machine) and
# which SID owns the AppX registration affects where content lands and which
# CompanyPortal log instance contains the trigger event. Emit a machine-
# readable snapshot of:
#   - Who is logged on interactively + their SIDs + session IDs
#   - IME service account (always SYSTEM but confirm)
#   - dosvc service account (NetworkService)
#   - CompanyPortal + DesktopAppInstaller AppX registration per user
# The store analyzer consumes this to correlate install scope across tabs.
Invoke-Safe 'baseline: user session context (JSON)' {
    $ctxOut = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'user_context'
    # Get-CmdOutPath defaults to .txt; rewrite for .json
    $ctxOut = [System.IO.Path]::ChangeExtension($ctxOut, 'json')
    $context = [ordered]@{
        computer        = $env:COMPUTERNAME
        # v1.3.1: $script:TraceStartedAt is not set at baseline time (it's set
        # at line 926, right before netsh trace starts; baseline blocks run
        # earlier). Use current time as baseline timestamp for this JSON.
        baseline_at     = (Get-Date).ToString('o')
        logged_on_users = @()
        service_accounts = [ordered]@{
            IntuneManagementExtension = $null
            DeliveryOptimization      = $null
            AppXSVC                   = $null
        }
        package_registration = [ordered]@{
            CompanyPortal      = @()
            DesktopAppInstaller = @()
        }
    }

    # Logged-on users (interactive sessions only)
    try {
        $sessions = @()
        $queryUser = & query.exe user 2>$null
        if ($queryUser) {
            # "query user" output is positional; parse it roughly.
            # Columns: USERNAME SESSIONNAME ID STATE IDLE-TIME LOGON-TIME
            $queryUser | Select-Object -Skip 1 | ForEach-Object {
                $line = $_.TrimStart('>').Trim()
                if ($line -match '^(\S+)\s+(\S+)?\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+)$') {
                    $sessions += [ordered]@{
                        username     = $matches[1]
                        sessionName  = $matches[2]
                        sessionId    = [int]$matches[3]
                        state        = $matches[4]
                        logonTime    = $matches[6]
                    }
                }
            }
        }
        # Augment with SIDs from HKLM\SAM-friendly profile list
        foreach ($s in $sessions) {
            try {
                $ntAcct = New-Object System.Security.Principal.NTAccount($s.username)
                $sid    = $ntAcct.Translate([System.Security.Principal.SecurityIdentifier]).Value
                $s.sid  = $sid
            } catch {
                $s.sid  = $null
            }
            $context.logged_on_users += $s
        }
    } catch {
        Write-CLog ("       query user failed: {0}" -f $_.Exception.Message) -Level SKIP
    }

    # Service accounts
    try {
        $imeSvc = Get-CimInstance Win32_Service -Filter "Name='IntuneManagementExtension'" -ErrorAction SilentlyContinue
        if ($imeSvc) { $context.service_accounts.IntuneManagementExtension = $imeSvc.StartName }
        $doSvc = Get-CimInstance Win32_Service -Filter "Name='DoSvc'" -ErrorAction SilentlyContinue
        if ($doSvc)  { $context.service_accounts.DeliveryOptimization      = $doSvc.StartName }
        $axSvc = Get-CimInstance Win32_Service -Filter "Name='AppXSvc'" -ErrorAction SilentlyContinue
        if ($axSvc)  { $context.service_accounts.AppXSVC                    = $axSvc.StartName }
    } catch { }

    # AppX package registration - CompanyPortal + DesktopAppInstaller per user.
    # These are the two packages that matter for IME Company Portal Store
    # installs - CP triggers the flow, DesktopAppInstaller hosts winget.
    foreach ($pkgName in @('Microsoft.CompanyPortal','Microsoft.DesktopAppInstaller')) {
        try {
            $pkgs = Get-AppxPackage -AllUsers -Name $pkgName -ErrorAction SilentlyContinue
            $key = if ($pkgName -eq 'Microsoft.CompanyPortal') { 'CompanyPortal' } else { 'DesktopAppInstaller' }
            foreach ($p in $pkgs) {
                # v1.3.1: harden against null-valued Version / InstallState /
                # UserSecurityId on framework apps that don't populate every
                # field. The ToString() calls were throwing "cannot call a
                # method on a null-valued expression".
                $ver = if ($p.Version) { $p.Version.ToString() } else { $null }
                $entry = [ordered]@{
                    name            = $p.Name
                    version         = $ver
                    packageFullName = $p.PackageFullName
                    installLocation = $p.InstallLocation
                    users           = @()
                }
                if ($p.PackageUserInformation) {
                    foreach ($pui in $p.PackageUserInformation) {
                        $entry.users += [ordered]@{
                            sid      = if ($pui.UserSecurityId) { $pui.UserSecurityId.Sid } else { $null }
                            username = if ($pui.UserSecurityId) { $pui.UserSecurityId.Username } else { $null }
                            state    = if ($pui.InstallState) { $pui.InstallState.ToString() } else { $null }
                        }
                    }
                }
                $context.package_registration.$key += $entry
            }
        } catch {
            Write-CLog ("       {0} registration lookup failed: {1}" -f $pkgName, $_.Exception.Message) -Level SKIP
        }
    }

    # Emit JSON (depth 10 handles the nested user/package arrays)
    $context | ConvertTo-Json -Depth 10 | Out-File -FilePath $ctxOut -Encoding UTF8
    Write-CLog ("       user context JSON: {0} session(s), CP pkg entries={1}, DAI pkg entries={2}" -f `
        $context.logged_on_users.Count,
        $context.package_registration.CompanyPortal.Count,
        $context.package_registration.DesktopAppInstaller.Count)
}

#endregion

#region Start Traces

$script:TraceStartedAt = Get-Date
$script:NetTraceRunning = $false
$script:NetTraceEtl     = Join-Path $netDir ("NetTrace_{0}.etl" -f $script:Timestamp)

# v1.3.5: -CaptureTlsDiagnostics opt-in. Track whether WE enabled CAPI2
# (vs. it was already on), so cleanup only touches what we changed.
$script:Capi2WasEnabled       = $false  # actual channel state when we looked
$script:Capi2EnabledByScript  = $false  # true iff we turned it on

if ($CaptureTlsDiagnostics) {
    Invoke-Safe 'enable CAPI2/Operational for TLS diagnostics' {
        # Query current enable state. wevtutil gl returns lines like "enabled: true"
        $getOut = & wevtutil.exe gl 'Microsoft-Windows-CAPI2/Operational' 2>&1
        $script:Capi2WasEnabled = ($getOut -match 'enabled:\s*true').Count -gt 0

        if ($script:Capi2WasEnabled) {
            Write-CLog '       CAPI2/Operational already enabled (not changing state)'
        } else {
            # Must pass /q:true explicitly because the channel may not have a
            # channel config; /q is required for enabling some analytic channels.
            & wevtutil.exe sl 'Microsoft-Windows-CAPI2/Operational' /e:true /q:true 2>&1 | Out-Null
            if ($LASTEXITCODE -eq 0) {
                $script:Capi2EnabledByScript = $true
                Write-CLog '       CAPI2/Operational enabled for trace window'
            } else {
                Write-CLog ("       CAPI2/Operational enable returned exit {0} (will still attempt export)" -f $LASTEXITCODE) -Level WARN
            }
        }
    }
} else {
    Write-CLog '       -CaptureTlsDiagnostics not set; CAPI2/Operational will be exported as-is (likely empty on default systems)' -Level SKIP
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
Write-Host '  OPTIONAL - Edge HAR capture (for web Company Portal scenarios):' -ForegroundColor DarkYellow
Write-Host '    In Edge, open DevTools with F12, go to the Network tab, tick'
Write-Host '    "Preserve log", clear existing entries, then reproduce the click.'
Write-Host '    When done: right-click any row -> "Save all as HAR with content".'
Write-Host '    Save the .har file to:' -ForegroundColor DarkYellow
Write-Host ('      {0}' -f (Join-Path $script:StageRoot 'Network\ManualHAR')) -ForegroundColor DarkCyan
Write-Host '    before pressing ENTER. Any .har in that folder gets packaged.'
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

# v1.3.5: Restore CAPI2/Operational to its pre-trace state. Runs AFTER the
# event log exports consume the channel (in the post-trace section below),
# so the window of data is still captured. Critical: runs whether or not
# the user aborted - we never leave CAPI2 enabled if we were the ones
# who enabled it. Wrapped in try/catch; failure here is logged but does
# not affect the rest of the trace output.
#
# Rationale for NOT doing this in a try/finally at the very top of the
# script: we want the channel to remain enabled during the event log
# export block below, which only runs in the post-trace section. Moving
# the disable here (right after netsh stop, still before post-trace
# collection) means CAPI2 events generated during the trace window are
# still in the channel buffer when wevtutil epl reads it later; the epl
# operation reads from the channel log file, not the live provider, so
# it does not matter that we've disabled the provider by then.
if ($script:Capi2EnabledByScript) {
    try {
        & wevtutil.exe sl 'Microsoft-Windows-CAPI2/Operational' /e:false 2>&1 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-CLog 'CAPI2/Operational disabled (restored to pre-trace state)' -Level OK
        } else {
            Write-CLog ("CAPI2/Operational disable returned exit {0}" -f $LASTEXITCODE) -Level WARN
        }
    } catch {
        Write-CLog ("Exception disabling CAPI2/Operational: {0}" -f $_.Exception.Message) -Level ERROR
    }
    $script:Capi2EnabledByScript = $false
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
# v1.2.9: pad window by 120s each side. v1.2.8 used 30s pads but real traces
# showed install events landing 20-60s BEFORE the operator pressed ENTER (they
# triggered the install and then started the trace). Event log exports are
# cheap - a wider window costs KB not MB - so err generous.
$winStart = $script:TraceStartedAt.ToUniversalTime().AddSeconds(-120)
$winEnd   = $script:TraceEndedAt.ToUniversalTime().AddSeconds(120)

$appChannels = @(
    # Win32 / MSI app deployment
    'Microsoft-Windows-AppxDeployment-Server/Operational'
    'Microsoft-Windows-AppxDeploymentServer/Operational'
    'Microsoft-Windows-AppxPackaging/Operational'
    # v1.2.9: AppxPackaging debug channel surfaces package manifest parse errors
    'Microsoft-Windows-AppxPackaging/Debug'
    # MDM / Intune
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin'
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Operational'
    'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Debug'
    # Company Portal / auth
    'Microsoft-Windows-AAD/Operational'
    'Microsoft-Windows-User Device Registration/Admin'
    'Microsoft-Windows-PushNotification-Platform/Operational'
    # Store client + UI
    'Microsoft-Windows-Store/Operational'
    # v1.2.9: TWinUI covers Store app UX events (app launches, tile activation,
    # "can't open this app" dimmed-tile failures).
    'Microsoft-Windows-TWinUI/Operational'
    # v1.2.9: Store Agent drives the download + install pipeline behind Store UI.
    # Without these channels, winget->Store handoffs show no Store-side activity
    # because the "Store" channel is UI-only.
    'Microsoft-Windows-StoreAgent/Admin'
    'Microsoft-Windows-StoreAgent/Operational'
    'Microsoft-Windows-StoreAgent-Diag/Operational'
    'Microsoft-Windows-StoreAgent-Diag/Debug'
    # v1.2.9: Shell-Core fires shell-initiated install events (Start menu,
    # "install" from file explorer context menu, protocol handlers).
    'Microsoft-Windows-Shell-Core/Operational'
    # v1.3.0: Push-To-Install is where Store-initiated installs originate when
    # the Store backend pushes an install to this user's session (common with
    # Intune Company Portal Store app deployments). The Operational subchannel
    # is already captured via PushNotification-Platform above; Admin surfaces
    # the administrative-level push events.
    'Microsoft-Windows-Push-To-Install/Admin'
    # v1.3.0: AppxDeployment (no -Server suffix) exists on some Windows builds
    # as the newer unified channel alongside AppxDeployment-Server. Capture
    # both so we cover old and new builds without version detection.
    'Microsoft-Windows-AppxDeployment/Operational'
    # v1.3.0: AppReadiness-API is the newer API-level channel that complements
    # AppReadiness/Operational and /Admin. Fires on first-launch readiness
    # checks and app init failures that happen AFTER deployment.
    'Microsoft-Windows-AppReadiness-API/Operational'
    # Transfer
    'Microsoft-Windows-Bits-Client/Operational'
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
    # v1.3.5: TLS/Cert chain diagnostics. CAPI2 surfaces certificate chain
    # validation failures (untrusted root, expired cert, revoked cert, CRL/
    # OCSP retrieval failures). Schannel-Events surfaces TLS protocol
    # negotiation issues. WinHTTP surfaces HTTP-level handshake failures.
    # These three channels feed the NetTrace Analyzer's CAPI/TLS detection
    # pipeline; the Trace ZIP was previously missing all three.
    #
    # Note: CAPI2/Operational is DISABLED by default on Windows. Exporting
    # a disabled channel returns empty results. To get actual data, either:
    #   (a) operator enables it manually before starting the trace, OR
    #   (b) use the -CaptureTlsDiagnostics switch (added in v1.3.5) which
    #       enables CAPI2 automatically for the trace window and disables
    #       it after.
    # Schannel-Events is similarly volume-gated by the EventLogging registry
    # value; default (1) logs only errors. The switch does not touch the
    # registry because Schannel event logging changes require a reboot to
    # take effect - not suitable for an in-situ trace.
    'Microsoft-Windows-CAPI2/Operational'
    'Microsoft-Windows-Schannel-Events/Operational'
    'Microsoft-Windows-WinHTTP/Operational'
    # Noisy big channels, time-filtered
    'Application'
    'System'
)

Invoke-Safe 'event log exports (trace window +-120s)' {
    $ok = 0; $skip = 0
    foreach ($ch in $appChannels) {
        if (New-EventLogExport -Channel $ch -OutDir $evtDir -StartUtc $winStart -EndUtc $winEnd) { $ok++ } else { $skip++ }
    }
    Write-CLog "       exported $ok  /  unavailable $skip"
}

# v1.2.0: WinGet diagnostic logs. Walks every user profile - the interactive
# user may not be the elevated admin running this script, same reasoning as
# Collect-IntuneLogs.
#
# v1.3.0: Corrected to mirror ODC's Intune.xml coverage. ODC collects WinGet
# logs from FOUR paths, and the Trace script was only covering one. The paths:
#
#   (1) %SystemRoot%\Temp\WinGet\defaultState          -> SYSTEM-context winget
#       (IME AgentExecutor runs as SYSTEM; its %TEMP% resolves to
#       C:\Windows\Temp, so winget invoked from SYSTEM writes here)
#
#   (2) %LOCALAPPDATA%\Temp\WinGet\defaultState        -> USER-context winget
#       (when the user launches winget.exe from their own terminal, or when
#       winget COM is invoked in the user's session by something other than
#       SYSTEM IME. Walked PER-USER.)
#
#   (3) %LOCALAPPDATA%\Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\
#       LocalState\DiagOutputDir                       -> DAI package log store
#       (the Store-packaged winget app's own diagnostic output dir, per user)
#
#   (4) %TEMP%\winget\defaultState\WPM-*.txt           -> WPM scratch files
#       (collected separately into Intune\Files\WPM\ per ODC convention;
#       the SYSTEM and USER-context paths both can contain these)
#
# In-window filename tagging applies to all four paths. WinGet names each log
# file by session start timestamp:
#   WinGetCOM-YYYY-MM-DD-HH-MM-SS.mmm.log
#   WinGet-YYYY-MM-DD-HH-MM-SS.mmm.log
#   WinGet-<pkgid>-YYYY-MM-DD-HH-MM-SS.mmm.log
# Files whose parsed timestamp falls outside the trace window +-120s get
# "Historical__" prefix; in-window files keep their original name. Files
# without parseable timestamps (e.g., WPM-*.txt) are considered non-time-
# sensitive and don't get the prefix.
#
# Per-user files go under Intune\Files\General\<UserName>\ to prevent
# filename collisions across profiles (two users could have a WinGetCOM log
# with the same timestamp from the same winget COM server). SYSTEM files
# go flat in Intune\Files\General\ to match ODC's output layout.
Invoke-Safe 'WinGet logs (SYSTEM + per-user, ODC-compliant paths)' {
    $dst = $script:FilesGeneral
    $wpmDst = Join-Path $script:IntuneRoot 'Files\WPM'
    Ensure-Dir $dst
    # Same 120s pad as event log exports; use local time (WinGet filenames are local).
    $wgStart = $script:TraceStartedAt.AddSeconds(-120)
    $wgEnd   = $script:TraceEndedAt.AddSeconds(120)

    # Helper: parse filename timestamp, tag as historical if outside window.
    # Returns [bool] $isInWindow.
    function Test-WinGetFileInWindow {
        param([string]$FileName)
        $m = [regex]::Match($FileName, '(\d{4})-(\d{2})-(\d{2})-(\d{2})-(\d{2})-(\d{2})\.(\d{3})')
        if (-not $m.Success) { return $false }  # unparseable -> historical
        try {
            $t = [DateTime]::new(
                [int]$m.Groups[1].Value, [int]$m.Groups[2].Value, [int]$m.Groups[3].Value,
                [int]$m.Groups[4].Value, [int]$m.Groups[5].Value, [int]$m.Groups[6].Value,
                [int]$m.Groups[7].Value)
            return ($t -ge $wgStart -and $t -le $wgEnd)
        } catch { return $false }
    }

    # Helper: copy one winget source dir with filename-window tagging.
    # WPM-*.txt files are routed to Intune\Files\WPM\ per ODC convention,
    # the rest go to the provided $DestRoot (which may be user-scoped).
    function Copy-WinGetDir {
        param([string]$Source, [string]$DestRoot, [string]$Label)
        if (-not (Test-Path -LiteralPath $Source)) { return $null }
        $result = [ordered]@{
            label = $Label; source = $Source
            copied = 0; inWindow = 0; historical = 0; wpm = 0
        }
        Ensure-Dir $DestRoot
        Get-ChildItem -LiteralPath $Source -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
            # Route WPM-*.txt separately (matches ODC Team="WPM" stanza)
            if ($_.Name -like 'WPM-*.txt') {
                Ensure-Dir $wpmDst
                Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $wpmDst $_.Name) -Force -ErrorAction SilentlyContinue
                $result.wpm++
                $result.copied++
                return
            }
            $isInWindow = Test-WinGetFileInWindow $_.Name
            $destName = if ($isInWindow) { $_.Name } else { "Historical__$($_.Name)" }
            Copy-Item -LiteralPath $_.FullName -Destination (Join-Path $DestRoot $destName) -Force -ErrorAction SilentlyContinue
            if ($isInWindow) { $result.inWindow++ } else { $result.historical++ }
            $result.copied++
        }
        return $result
    }

    $results = New-Object System.Collections.Generic.List[object]

    # (1) SYSTEM-context winget: flat under Files\General to match ODC layout.
    $r = Copy-WinGetDir -Source 'C:\Windows\Temp\WinGet\defaultState' -DestRoot $dst -Label 'SYSTEM:defaultState'
    if ($r) { $results.Add($r) }
    else    { Write-CLog '       SYSTEM defaultState dir absent (no SYSTEM-context winget on this device)' -Level SKIP }

    # (2)+(3) Per-user: walk every user profile for Temp\WinGet and DAI DiagOutputDir.
    $usersRoot = 'C:\Users'
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userName = $_.Name
            $userAppData = Join-Path $_.FullName 'AppData\Local'

            # (2) User-context Temp winget
            $userTempWinGet = Join-Path $userAppData 'Temp\WinGet\defaultState'
            if (Test-Path -LiteralPath $userTempWinGet) {
                $userDst = Join-Path $dst $userName
                $r = Copy-WinGetDir -Source $userTempWinGet -DestRoot $userDst -Label ("USER:$userName`:Temp")
                if ($r) { $results.Add($r) }
            }

            # (3) DAI package diag output dir
            $daiDiag = Join-Path $userAppData 'Packages\Microsoft.DesktopAppInstaller_8wekyb3d8bbwe\LocalState\DiagOutputDir'
            if (Test-Path -LiteralPath $daiDiag) {
                $userDst = Join-Path $dst $userName
                $r = Copy-WinGetDir -Source $daiDiag -DestRoot $userDst -Label ("USER:$userName`:DAI")
                if ($r) { $results.Add($r) }
            }
        }
    }

    # Aggregate log summary
    # v1.3.1: previous version used Measure-Object -Property ... on [ordered]@{}
    # items, which doesn't work - OrderedDictionary elements don't expose named
    # properties to Measure-Object. Explicit accumulation instead.
    $totCopied = 0; $totInWin = 0; $totHist = 0; $totWpm = 0
    foreach ($r in $results) {
        $totCopied += [int]$r.copied
        $totInWin  += [int]$r.inWindow
        $totHist   += [int]$r.historical
        $totWpm    += [int]$r.wpm
    }
    Write-CLog ("       total: {0} file(s) across {1} source(s); {2} in-window, {3} historical, {4} WPM" -f `
        $totCopied, $results.Count, $totInWin, $totHist, $totWpm)
    foreach ($r in $results) {
        Write-CLog ("         {0,-32}  copied={1,-3}  inWin={2,-3}  hist={3,-3}  wpm={4,-3}" -f `
            $r.label, $r.copied, $r.inWindow, $r.historical, $r.wpm)
    }
}
# v1.2.4: Company Portal logs. Totally missing from v1.2.0-1.2.3 Trace - only
# the Collect script was picking these up. For CP-initiated deploys (the
# primary scenario this Trace script targets) this is a critical gap.
# CP logs live at:
#   C:\Users\<user>\AppData\Local\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe\
#     LocalState\                      <- main state + DiagOutputDir + Log_*.log
#     LocalCache\                       <- *.log
#     TempState\                        <- *.log
#     RoamingState\                     <- *.log (rare)
#
# v1.3.0: Time filter removed. CP only writes to its log files when the user
# interacts with the UI. When the user triggers an install BEFORE starting the
# trace (the common real case), the LastWriteTime filter zeroed out the
# collection even though the Log_*.log file sitting on disk contains the
# relevant install-trigger entries. The files are small (few MB per user
# total) and CP's own rotation bounds the size - always take everything.
Invoke-Safe 'Company Portal logs (all user profiles, full copy)' {
    $cpRoot = Join-Path $script:IntuneRoot 'Files\CompanyPortalLogs'
    $usersRoot = 'C:\Users'
    $totalFiles = 0
    $userCount  = 0
    if (Test-Path $usersRoot) {
        Get-ChildItem $usersRoot -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            $userName = $_.Name
            $pkgRoot  = Join-Path $_.FullName 'AppData\Local\Packages\Microsoft.CompanyPortal_8wekyb3d8bbwe'
            if (-not (Test-Path -LiteralPath $pkgRoot)) { return }
            $userCount++
            $userDst = Join-Path $cpRoot $userName

            foreach ($sub in @('LocalState', 'LocalCache', 'TempState', 'RoamingState')) {
                $srcSub = Join-Path $pkgRoot $sub
                if (-not (Test-Path -LiteralPath $srcSub)) { continue }
                Get-ChildItem -LiteralPath $srcSub -Recurse -File -Force -ErrorAction SilentlyContinue |
                    Where-Object {
                        # Filter only by extension / DiagOutputDir presence, NOT by time.
                        # We want the full Log_*.log content regardless of when it was
                        # last touched - the active log file may not have been written
                        # during the trace window but its TAIL covers the trigger event.
                        $_.Extension -match '^\.(log|txt|etl|json|xml|dat)$' -or
                        $_.Directory.Name -eq 'DiagOutputDir'
                    } |
                    ForEach-Object {
                        # Preserve subfolder structure under <userDst>\<sub>\
                        $rel = $_.FullName.Substring($srcSub.Length).TrimStart('\')
                        $dst = Join-Path (Join-Path $userDst $sub) $rel
                        Ensure-Dir (Split-Path $dst -Parent)
                        Copy-Item -LiteralPath $_.FullName -Destination $dst -Force -ErrorAction SilentlyContinue
                        $totalFiles++
                    }
            }
        }
    }
    Write-CLog ("       CP files copied: {0} across {1} user profile(s)" -f $totalFiles, $userCount)
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
        # so the same comparison must happen against UTC trace bounds. v1.3.0-1.3.5
        # used local-time bounds, which silently dropped every entry on non-UTC hosts.
        # v1.3.6: (a) widens the pad to 120s, (b) on empty result, dumps the full log
        # unfiltered (matches ODC behavior - the trace window is still documented in
        # _Summary.txt for cross-correlation).
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
            # v1.3.6: emit Format-List style blocks (key : value, blank line between
            # records). This matches the layout downstream analyzers (Store /
            # Win32) parse with `split on blank line` + `Key: Value` regexes.
            # The previous flat pipe-separated format was unparseable, leading to
            # "No Delivery Optimization jobs in this log" even when the file was
            # multi-MB. TimeCreated is normalized to ISO-8601 UTC so JS
            # `new Date()` parses it deterministically regardless of host culture.
            $doEntries |
                Select-Object `
                    @{n='TimeCreated';e={
                        $tc = if ($_.TimeCreated.Kind -eq [System.DateTimeKind]::Local) {
                                  $_.TimeCreated.ToUniversalTime()
                              } else {
                                  [System.DateTime]::SpecifyKind($_.TimeCreated, [System.DateTimeKind]::Utc)
                              }
                        $tc.ToString("yyyy-MM-ddTHH:mm:ss.fffK")
                    }},
                    @{n='LevelName';e={ if ($_.LevelName) { $_.LevelName } else { switch ($_.Level) { 1 {'Critical'} 2 {'Error'} 3 {'Warning'} 4 {'Information'} 5 {'Verbose'} default {"Level$($_.Level)"} } } }},
                    @{n='ProcessId';e={ $_.ProcessId }},
                    @{n='ThreadId';e={ $_.ThreadId }},
                    @{n='Function';e={ $_.Function }},
                    @{n='ErrorCode';e={ $_.ErrorCode }},
                    @{n='LineNumber';e={ $_.LineNumber }},
                    @{n='Message';e={ $_.Message }} |
                Format-List |
                Out-File -FilePath $doOut -Encoding UTF8 -Width 4096
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
    # v1.3.0: Raw DO ETLs. These are the authoritative source for
    # content-download attribution (CDN hostname, content ID, peer bytes,
    # caller identity StoreInstaller vs WinGet) - Get-DeliveryOptimizationLog
    # emits a textual RE-RENDER of these ETLs, so when troubleshooting
    # caller-identity questions the text is insufficient.
    # Active ETL files are always safe to copy open; do not stop dosvc
    # (stopping the service loses in-flight peer connections).
    # Previously filtered by LastWriteTime >= trace start; that missed files
    # whose active-session write-through hadn't hit disk yet during a short
    # window. Now: copy ALL *.etl files in the DO Logs dir. Size stays
    # reasonable (<50 MB typical) because DO rotates its own files.
    $doEtlSrc = [Environment]::ExpandEnvironmentVariables('%WinDir%\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs')
    if (Test-Path -LiteralPath $doEtlSrc) {
        $doEtlDst = Join-Path $script:FilesIntune 'DeliveryOptimization_ETL'
        Ensure-Dir $doEtlDst
        $etlCount = 0
        Get-ChildItem -LiteralPath $doEtlSrc -Filter '*.etl' -File -ErrorAction SilentlyContinue |
            ForEach-Object {
                Copy-Item -LiteralPath $_.FullName -Destination $doEtlDst -Force -ErrorAction SilentlyContinue
                $etlCount++
            }
        Write-CLog ("       copied {0} DO ETL file(s) from {1}" -f $etlCount, $doEtlSrc)
    } else {
        Write-CLog ("       DO ETL path not present: {0}" -f $doEtlSrc) -Level SKIP
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

# v1.2.5: detect operator-dropped Edge HAR files. Browser HAR captures the
# user-facing Intune web CP traffic that netsh trace can't decrypt (TLS) and
# the IME collection can't see (browser runs as user, not SYSTEM). Operator
# drops .har files into Network\ManualHAR\ before pressing ENTER; this step
# catalogs what was dropped and validates the file is real HAR JSON.
Invoke-Safe 'Edge HAR files (manual drop detection)' {
    $harDir = Join-Path $script:StageRoot 'Network\ManualHAR'
    if (-not (Test-Path -LiteralPath $harDir)) {
        Write-CLog "       no Network\ManualHAR directory (unexpected) - skip" -Level SKIP
        return
    }
    $hars = @(Get-ChildItem -LiteralPath $harDir -Filter '*.har' -File -ErrorAction SilentlyContinue)
    if ($hars.Count -eq 0) {
        Write-CLog "       no HAR files dropped by operator (skipping)" -Level SKIP
        return
    }

    $summary = Join-Path $harDir '_HAR_Summary.txt'
    'Edge HAR files captured during trace window' | Out-File $summary -Encoding UTF8
    '=' * 50 | Out-File $summary -Encoding UTF8 -Append
    '' | Out-File $summary -Encoding UTF8 -Append

    $validCount = 0
    foreach ($h in $hars) {
        $line = "{0}  ({1:N1} KB)" -f $h.Name, ($h.Length / 1KB)
        # Lightweight validation: read first 8 KB, check it's JSON with a 'log'
        # root property (HAR 1.2 spec: top-level is {"log":{"version":"1.2",...}})
        $isValidHar = $false
        $entryCount = 0
        $domains = @()
        try {
            $sample = Get-Content -LiteralPath $h.FullName -TotalCount 2000 -ErrorAction Stop -Raw
            if ($sample -match '"log"\s*:\s*\{' -and $sample -match '"version"\s*:\s*"1\.[01]"') {
                $isValidHar = $true
            }
            # For small-to-medium HARs, parse + extract stats. Skip if > 50 MB
            # to avoid blowing the ZIP step's time budget.
            if ($isValidHar -and $h.Length -lt 50MB) {
                $obj = Get-Content -LiteralPath $h.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                if ($obj.log -and $obj.log.entries) {
                    $entryCount = @($obj.log.entries).Count
                    $domains = @($obj.log.entries |
                        ForEach-Object {
                            try { ([System.Uri]$_.request.url).Host } catch { $null }
                        } | Where-Object { $_ } | Sort-Object -Unique)
                }
            }
        } catch { }

        if ($isValidHar) {
            $validCount++
            $line += "  [valid HAR, $entryCount entries]"
        } else {
            $line += "  [WARNING: doesn't look like HAR 1.x JSON]"
        }
        $line | Out-File $summary -Encoding UTF8 -Append
        if ($domains) {
            "  Hosts contacted: $($domains -join ', ')" | Out-File $summary -Encoding UTF8 -Append
        }
        '' | Out-File $summary -Encoding UTF8 -Append
    }

    Write-CLog ("       {0} HAR file(s) ingested ({1} valid)" -f $hars.Count, $validCount)
}

# v1.3.0: Correlation map + flow summary. Post-processes the collected logs
# to extract every app-deployment correlation ID and emits two artifacts:
#   - <computer>_correlation_map.json (machine-readable, store analyzer loads
#     this directly instead of re-joining from raw logs every time)
#   - _FlowSummary.txt at ZIP root (human-readable install flow timeline)
#
# Scope: only the in-window files (AppWorkload IME_Delta, in-window WinGet
# COM logs, trace-window event logs). Historical data is explicitly excluded
# - the summary describes THIS trace's install activity, not lifetime history.
Invoke-Safe 'correlation map + flow summary' {
    $correlationPath = Get-CmdOutPath -Dir $cmdDir -OutputFileName 'correlation_map'
    $correlationPath = [System.IO.Path]::ChangeExtension($correlationPath, 'json')
    $flowSummaryPath = Join-Path $script:StageRoot '_FlowSummary.txt'

    $apps = @{}   # key: ime_app_id (guid) -> record; fallback key: store_product_id
    $events = New-Object System.Collections.Generic.List[object]

    # Helper: canonicalize HRESULT to 0x######## lowercase
    function Format-HResult {
        param([string]$Raw)
        if (-not $Raw) { return $null }
        $v = $Raw.Trim()
        if ($v -match '^-?\d+$') {
            # decimal signed
            try {
                $i = [int64]$v
                $u = [uint32]([uint64]($i -band 0xFFFFFFFF))
                return ('0x{0:x8}' -f $u)
            } catch { return $v }
        }
        if ($v -match '^0[xX][0-9a-fA-F]+$') {
            return ('0x{0:x8}' -f [uint32]([Convert]::ToUInt32($v.Substring(2), 16)))
        }
        return $v
    }

    # Helper: get-or-create app record keyed by IME ApplicationId (guid) OR
    # by Store ProductId when no ApplicationId seen yet.
    # When BOTH IDs are provided, also merges an existing pid-keyed record
    # into the ime-id-keyed one (we now have better identity).
    # When caller provides only a ProductId, we search both by "pid:<id>" key
    # AND by matching an existing IME-id-keyed record's store_product_id field
    # (covers the common case where policy receipt was seen first and
    # established an IME-id-keyed record; the later AgentExecutor launch
    # carries only the ProductId).
    function Get-AppRecord {
        param([string]$ImeId, [string]$ProductId, [string]$DisplayName)
        # Exact hit on IME id
        if ($ImeId -and $apps.ContainsKey($ImeId)) {
            $rec = $apps[$ImeId]
            # If caller provided a ProductId and we have a pid: record, merge it in
            if ($ProductId -and $apps.ContainsKey("pid:$ProductId")) {
                $pidRec = $apps["pid:$ProductId"]
                foreach ($op in $pidRec.operation_types) { [void]$rec.operation_types.Add($op) }
                foreach ($a  in $pidRec.winget_activity_ids) { [void]$rec.winget_activity_ids.Add($a) }
                foreach ($j  in $pidRec.do_job_ids) { [void]$rec.do_job_ids.Add($j) }
                foreach ($h  in $pidRec.hresults_observed) { [void]$rec.hresults_observed.Add($h) }
                foreach ($tl in $pidRec.timeline) { [void]$rec.timeline.Add($tl) }
                if (-not $rec.store_product_id) { $rec.store_product_id = $pidRec.store_product_id }
                if (-not $rec.store_pfn) { $rec.store_pfn = $pidRec.store_pfn }
                if (-not $rec.store_pfn_short) { $rec.store_pfn_short = $pidRec.store_pfn_short }
                # v1.3.2: explicit null guards (see Update-Timespan for rationale)
                if ($pidRec.first_seen) {
                    if ($null -eq $rec.first_seen -or $pidRec.first_seen -lt $rec.first_seen) {
                        $rec.first_seen = $pidRec.first_seen
                    }
                }
                if ($pidRec.last_seen) {
                    if ($null -eq $rec.last_seen -or $pidRec.last_seen -gt $rec.last_seen) {
                        $rec.last_seen = $pidRec.last_seen
                    }
                }
                if (-not $rec.terminal_outcome -and $pidRec.terminal_outcome) {
                    $rec.terminal_outcome = $pidRec.terminal_outcome
                    $rec.terminal_hr      = $pidRec.terminal_hr
                }
                $apps.Remove("pid:$ProductId")
            }
            return $rec
        }
        # Caller provided only a ProductId: look for an existing IME-id-keyed
        # record whose store_product_id matches, then fall back to pid: key.
        if ((-not $ImeId) -and $ProductId) {
            foreach ($existingKey in @($apps.Keys)) {
                $existing = $apps[$existingKey]
                if ($existing.store_product_id -and $existing.store_product_id -eq $ProductId) {
                    return $existing
                }
            }
            if ($apps.ContainsKey("pid:$ProductId")) {
                return $apps["pid:$ProductId"]
            }
        }
        # Upgrade case: caller provides IME id AND pid, but pid:XXX exists;
        # promote the pid record to be keyed by the IME id.
        if ($ImeId -and $ProductId -and $apps.ContainsKey("pid:$ProductId")) {
            $rec = $apps["pid:$ProductId"]
            $rec.ime_app_id = $ImeId
            if ($DisplayName -and -not $rec.ime_app_name) { $rec.ime_app_name = $DisplayName }
            $apps[$ImeId] = $rec
            $apps.Remove("pid:$ProductId")
            return $rec
        }
        $rec = [ordered]@{
            ime_app_id          = $ImeId
            ime_app_name        = $DisplayName
            store_product_id    = $ProductId
            store_pfn           = $null
            store_pfn_short     = $null
            winget_activity_ids = New-Object System.Collections.Generic.HashSet[string]
            do_job_ids          = New-Object System.Collections.Generic.HashSet[string]
            hresults_observed   = New-Object System.Collections.Generic.HashSet[string]
            operation_types     = New-Object System.Collections.Generic.HashSet[string]
            first_seen          = $null
            last_seen           = $null
            terminal_outcome    = $null
            terminal_hr         = $null
            # v1.3.1: CP-side terminal state (hop 10 - CP's view of whether
            # the install completed, from FinalStatus.json per user).
            cp_terminal_state      = $null
            cp_terminal_state_name = $null
            cp_device_key          = $null
            cp_details_uri         = $null
            timeline            = New-Object System.Collections.Generic.List[object]
        }
        $key = if ($ImeId) { $ImeId } else { "pid:$ProductId" }
        $apps[$key] = $rec
        return $rec
    }

    function Update-Timespan {
        param($Rec, [datetime]$Ts)
        # v1.3.2: original form relied on PowerShell short-circuiting -or and
        # skipping the DateTime -lt $null comparison when first_seen was null.
        # Some PS 7.x paths evaluate both sides and throw "Argument types do
        # not match". Use explicit null test to avoid the comparison entirely.
        if ($null -eq $Rec.first_seen) {
            $Rec.first_seen = $Ts
        } elseif ($Ts -lt $Rec.first_seen) {
            $Rec.first_seen = $Ts
        }
        if ($null -eq $Rec.last_seen) {
            $Rec.last_seen = $Ts
        } elseif ($Ts -gt $Rec.last_seen) {
            $Rec.last_seen = $Ts
        }
    }

    function Add-Timeline {
        param($Rec, [datetime]$Ts, [string]$Phase, [string]$Source, [string]$Detail)
        $Rec.timeline.Add([ordered]@{
            ts     = $Ts.ToString('yyyy-MM-dd HH:mm:ss.fff')
            phase  = $Phase
            source = $Source
            detail = $Detail
        })
    }

    # -------- Pass 1: AppWorkload IME_Delta (in-window only) --------
    # CMTrace format: <![LOG[msg]LOG]!><time="HH:mm:ss.mmm+000" date="MM-dd-yyyy" ...>
    $awDelta = Join-Path $script:StageRoot 'Trace\IME_Delta\AppWorkload.log'
    if (Test-Path -LiteralPath $awDelta) {
        Write-CLog "       scanning AppWorkload IME_Delta for app correlations..."
        $awLines = 0
        $awMatches = 0
        Get-Content -LiteralPath $awDelta -ErrorAction SilentlyContinue | ForEach-Object {
            $awLines++
            $line = $_
            # Parse CMTrace timestamp
            $tsMatch = [regex]::Match($line, '<time="(\d{2}:\d{2}:\d{2}\.\d+)[^"]*"\s*date="(\d{1,2})-(\d{1,2})-(\d{4})"')
            if (-not $tsMatch.Success) { return }
            $ts = $null
            try {
                $timeStr = $tsMatch.Groups[1].Value
                $m = $tsMatch.Groups[2].Value.PadLeft(2,'0')
                $d = $tsMatch.Groups[3].Value.PadLeft(2,'0')
                $y = $tsMatch.Groups[4].Value
                $ts = [datetime]::Parse("$y-$m-$d $timeStr")
            } catch { return }

            # Looking for multiple patterns - order matters (most specific first)

            # Pattern A: AgentExecutor launch - the authoritative "IME decided to invoke winget for this app" signal
            # Example: '"C:\Program Files (x86)\...\agentexecutor.exe" -executeWinGet -operationType "Detection" -repositoryType "MicrosoftStore" -packageId "9NBLGGH4VVNH" -installScope "User"'
            if ($line -match '-executeWinGet\s+-operationType\s+"([^"]+)"\s+-repositoryType\s+"([^"]+)"\s+-packageId\s+"([^"]+)"') {
                $opType   = $matches[1]
                $repoType = $matches[2]
                $pkgId    = $matches[3].ToUpper()
                $rec = Get-AppRecord -ImeId $null -ProductId $pkgId -DisplayName $null
                [void]$rec.operation_types.Add($opType)
                Update-Timespan -Rec $rec -Ts $ts
                Add-Timeline -Rec $rec -Ts $ts -Phase ("IME:executeWinGet:$opType") -Source 'AppWorkload' `
                    -Detail ("repo={0} pkgId={1}" -f $repoType, $pkgId)
                $awMatches++
                return
            }

            # Pattern B: policy receipt. The AppWorkload IME log embeds each app's
            # full policy JSON inline. A single line can carry MANY apps because
            # "Get policies = [ {app1}, {app2}, ... ]". Each app record has:
            #   "Id":"<guid>","Name":"<display name>", ...
            #   "InstallerData":"{\"PackageIdentifier\":\"<pid>\",\"SourceName\":\"msstore\"}"
            # These two fields are far apart (hundreds of chars) with unrelated
            # JSON-with-braces between them. Naive "Id.*Name.*PackageIdentifier"
            # regex fails because of the intervening braces in "InstallEx":"{...}".
            # v1.3.0 strategy: collect all (Id, Name) pairs AND all PackageIdentifier
            # occurrences with their line positions, then associate each
            # PackageIdentifier with the NEAREST PRECEDING (Id, Name) pair. This
            # correctly handles the multi-app-per-line packing.
            $idNameMatches = [regex]::Matches($line, '"Id"\s*:\s*"([a-f0-9-]{36})"\s*,\s*"Name"\s*:\s*"([^"]+)"')
            $installerMatches = [regex]::Matches($line, '"InstallerData"\s*:\s*"\{\\"PackageIdentifier\\":\\"([A-Z0-9]{10,14})\\",\\"SourceName\\":\\"msstore\\"')
            if ($idNameMatches.Count -gt 0 -and $installerMatches.Count -gt 0) {
                foreach ($inst in $installerMatches) {
                    $instPos = $inst.Index
                    # Find the last (Id, Name) pair whose start position precedes this installer's
                    $best = $null
                    foreach ($pair in $idNameMatches) {
                        if ($pair.Index -lt $instPos) {
                            if (-not $best -or $pair.Index -gt $best.Index) { $best = $pair }
                        }
                    }
                    if (-not $best) { continue }
                    $imeId = $best.Groups[1].Value.ToLower()
                    $name  = $best.Groups[2].Value
                    $pkgId = $inst.Groups[1].Value.ToUpper()
                    $rec = Get-AppRecord -ImeId $imeId -ProductId $pkgId -DisplayName $name
                    if (-not $rec.ime_app_name) { $rec.ime_app_name = $name }
                    if (-not $rec.store_product_id) { $rec.store_product_id = $pkgId }
                    if (-not $rec.ime_app_id) { $rec.ime_app_id = $imeId }
                    Update-Timespan -Rec $rec -Ts $ts
                    Add-Timeline -Rec $rec -Ts $ts -Phase 'IME:PolicyReceived' -Source 'AppWorkload' `
                        -Detail ("name={0} pkgId={1}" -f $name, $pkgId)
                    $awMatches++
                }
            }

            # Pattern C: ReportingManager app state (terminal outcomes + HRESULTs)
            # Example: App with id: 005ad0e2-... ReportingState: {"ApplicationId":"005ad...","EnforcementState":1000,"EnforcementErrorCode":0, ...}
            if ($line -match 'App with id:\s*([a-f0-9-]{36}).*?EnforcementState"\s*:\s*(\-?\d+)\s*,\s*"EnforcementErrorCode"\s*:\s*(\-?\d+|null)') {
                $imeId = $matches[1].ToLower()
                $enfState = [int]$matches[2]
                $enfErr = if ($matches[3] -eq 'null') { $null } else { $matches[3] }
                $rec = Get-AppRecord -ImeId $imeId -ProductId $null -DisplayName $null
                if ($enfErr) {
                    $hr = Format-HResult $enfErr
                    if ($hr) { [void]$rec.hresults_observed.Add($hr) }
                }
                Update-Timespan -Rec $rec -Ts $ts
                # EnforcementState codes per IME:
                #   1000 = installed, 2000 = failed, 3000 = install in progress
                #   5000 = unknown, 1003 = install pending reboot
                $stateLabel = switch ($enfState) {
                    1000 { 'installed' }
                    1003 { 'install pending reboot' }
                    2000 { 'failed' }
                    3000 { 'in progress' }
                    5000 { 'unknown' }
                    default { "code=$enfState" }
                }
                Add-Timeline -Rec $rec -Ts $ts -Phase "IME:ReportingState:$stateLabel" -Source 'AppWorkload' `
                    -Detail ("enforcementState={0} errCode={1}" -f $enfState, $enfErr)
                # Note terminal outcomes (1000/2000)
                if ($enfState -eq 1000) { $rec.terminal_outcome = 'installed'; $rec.terminal_hr = '0x00000000' }
                if ($enfState -eq 2000) {
                    $rec.terminal_outcome = 'failed'
                    if ($enfErr) { $rec.terminal_hr = Format-HResult $enfErr }
                }
                $awMatches++
            }
        }
        Write-CLog ("       AppWorkload: {0} lines, {1} correlation matches" -f $awLines, $awMatches)
    }

    # -------- Pass 2: WinGet COM logs (in-window only, NOT Historical__) --------
    # v1.3.0: Recurse - per-user logs now live under Files\General\<UserName>\
    # from the ODC-coverage winget collection; SYSTEM logs are still flat.
    $wgCount = 0
    $wgMatches = 0
    Get-ChildItem -Path $script:FilesGeneral -Filter 'WinGetCOM*.log' -File -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike 'Historical__*' } |
        ForEach-Object {
            $wgCount++
            $currentActivity = $null
            $currentProductId = $null
            Get-Content -LiteralPath $_.FullName -ErrorAction SilentlyContinue | ForEach-Object {
                $line = $_
                # WinGet native format: "YYYY-MM-DD HH:mm:ss.fff [COMPONENT] Message"
                $wgTs = $null
                $m = [regex]::Match($line, '^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+\[')
                if ($m.Success) {
                    try { $wgTs = [datetime]::Parse($m.Groups[1].Value) } catch { }
                }
                if (-not $wgTs) { return }

                # activity ID (session identity)
                $a = [regex]::Match($line, 'activity\s+\[\{([a-fA-F0-9-]+)\}\]')
                if ($a.Success) { $currentActivity = $a.Groups[1].Value.ToUpper() }

                # ProductId via Getting entitlement / Started MSStore / /packageManifests/ URL
                $p = [regex]::Match($line, '(?:ProductId:\s*|/packageManifests/)([A-Z0-9]{10,14})')
                if ($p.Success) {
                    $currentProductId = $p.Groups[1].Value.ToUpper()
                }

                if ($currentProductId -and $currentActivity) {
                    $rec = Get-AppRecord -ImeId $null -ProductId $currentProductId -DisplayName $null
                    [void]$rec.winget_activity_ids.Add($currentActivity)
                    Update-Timespan -Rec $rec -Ts $wgTs
                }

                # Store Handoff - the key pivot point
                if ($line -match 'Started MSStore package execution\.\s*ProductId:\s*([A-Z0-9]{10,14})\s+PackageFamilyName:\s*(\S+)') {
                    # v1.3.1: variable was named $pid which collides with PowerShell's
                    # read-only automatic variable $PID (process ID). Renamed to
                    # $productId.
                    $productId = $matches[1].ToUpper()
                    $pfn = $matches[2]
                    $rec = Get-AppRecord -ImeId $null -ProductId $productId -DisplayName $null
                    if (-not $rec.store_pfn) {
                        $rec.store_pfn = $pfn
                        # Short PFN = everything before the first _ (human-readable app name)
                        $rec.store_pfn_short = ($pfn -split '_')[0]
                    }
                    Update-Timespan -Rec $rec -Ts $wgTs
                    Add-Timeline -Rec $rec -Ts $wgTs -Phase 'WinGet:StoreHandoff' -Source ('WinGetCOM:' + $_.Name) `
                        -Detail ("pfn={0}" -f $pfn)
                    $wgMatches++
                }

                # Leaf command outcome
                if ($line -match 'Leaf command (succeeded|failed):\s*root:(\w+)') {
                    $outcome = $matches[1]
                    $verb    = $matches[2]
                    if ($currentProductId) {
                        $rec = Get-AppRecord -ImeId $null -ProductId $currentProductId -DisplayName $null
                        Update-Timespan -Rec $rec -Ts $wgTs
                        Add-Timeline -Rec $rec -Ts $wgTs -Phase ("WinGet:Leaf:$outcome") -Source ('WinGetCOM:' + $_.Name) `
                            -Detail ("verb=$verb")
                        $wgMatches++
                    }
                }
            }
        }
    Write-CLog ("       WinGet COM: {0} in-window file(s), {1} pivot events" -f $wgCount, $wgMatches)

    # -------- Pass 3: Company Portal FinalStatus.json (hop 10 - CP-side outcome) --------
    # v1.3.1: Adds CP-side closure to each app record. The CP app maintains
    # per-AAD-user folders under LocalState\<userGuid>\ containing:
    #   AppxLocalAppStatus.json
    #   Win32LocalAppStatus.json
    #   MsiLocalAppStatus.json
    #   FinalStatus.json        <- most useful: terminal state per app
    # FinalStatus.json is a JSON array of entries with:
    #   ApplicationKey  - IME App GUID (matches AppWorkload policy receipt)
    #   State           - CP's terminal state code (integer)
    #   DeviceKey       - Entra device identity
    #   NextActionUtc   - next poll time (Date milliseconds)
    # CP state codes (observed from Microsoft.Management.Services
    # .IntuneManagementExtension.Core):
    #   1=Unknown 2=NotInstalled 3=NeedsRebootAfterInstall 4=NeedsInstall
    #   5=NeedsRebootAfterUninstall 6=InstallInProgress 7=DownloadInProgress
    #   8=NeedsRemove 9=Available 10=Pending 11=NeedsInstallAssignment
    #   12=Installed 13=Failed 14=WaitingForUserLogon
    # This pass matches each CP entry to its IME record by ApplicationKey GUID,
    # adds a "CP:FinalStatus:<label>" timeline event, and attaches cp_terminal_state
    # to the app record.
    $cpStateLabel = @{
        1='Unknown';2='NotInstalled';3='NeedsRebootAfterInstall';4='NeedsInstall'
        5='NeedsRebootAfterUninstall';6='InstallInProgress';7='DownloadInProgress'
        8='NeedsRemove';9='Available';10='Pending';11='NeedsInstallAssignment'
        12='Installed';13='Failed';14='WaitingForUserLogon'
    }
    $cpRoot = Join-Path $script:IntuneRoot 'Files\CompanyPortalLogs'
    $cpPassCount = 0
    if (Test-Path -LiteralPath $cpRoot) {
        Get-ChildItem -LiteralPath $cpRoot -Filter 'FinalStatus.json' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                $content = Get-Content -LiteralPath $_.FullName -Raw -ErrorAction Stop
                if (-not $content) { return }
                # CP sometimes writes single object vs array; force array.
                if ($content.Trim().StartsWith('{')) { $content = '[' + $content + ']' }
                $entries = $content | ConvertFrom-Json -ErrorAction Stop
                # FileInfo.LastWriteTime is our best timestamp proxy for when CP last wrote this
                $fileTs = $_.LastWriteTime
                # Extract user folder name from the path (.../CompanyPortalLogs/<User>/LocalState/<aad>/FinalStatus.json)
                $userName = $null
                $pathParts = $_.FullName -split '[\\/]'
                $cpIdx = [Array]::IndexOf($pathParts, 'CompanyPortalLogs')
                if ($cpIdx -ge 0 -and $cpIdx + 1 -lt $pathParts.Count) {
                    $userName = $pathParts[$cpIdx + 1]
                }
                foreach ($entry in $entries) {
                    $appKey = $entry.ApplicationKey
                    if (-not $appKey) { continue }
                    $appKeyLower = $appKey.ToLower()
                    $stateCode = [int]$entry.State
                    $label = if ($cpStateLabel.ContainsKey($stateCode)) { $cpStateLabel[$stateCode] } else { "code=$stateCode" }
                    # Look up matching record by IME id
                    $rec = $null
                    if ($apps.ContainsKey($appKeyLower)) {
                        $rec = $apps[$appKeyLower]
                    } else {
                        # No match in AppWorkload - CP may have apps assigned that
                        # didn't touch AppWorkload this trace. Create a record so
                        # the app still shows up in the flow summary.
                        $rec = Get-AppRecord -ImeId $appKeyLower -ProductId $null -DisplayName $null
                    }
                    # Attach CP terminal state
                    $rec.cp_terminal_state      = $stateCode
                    $rec.cp_terminal_state_name = $label
                    $rec.cp_device_key          = $entry.DeviceKey
                    $rec.cp_details_uri         = $entry.DetailsUri
                    Update-Timespan -Rec $rec -Ts $fileTs
                    Add-Timeline -Rec $rec -Ts $fileTs -Phase "CP:FinalStatus:$label" `
                        -Source ('CP:' + $userName) `
                        -Detail ("stateCode={0} user={1}" -f $stateCode, $userName)
                    $cpPassCount++
                }
            } catch {
                # Malformed JSON or IO error - skip
            }
        }
    }
    Write-CLog ("       CP FinalStatus: {0} app-state entries applied" -f $cpPassCount)

    # -------- Emit correlation_map.json --------
    # v1.3.4: Replaced the [ordered]@{...} item construction with piece-by-
    # piece PSCustomObject + Add-Member pattern. v1.3.3 hit "Argument types
    # do not match" on every record during $appsArr += [ordered]@{...}
    # construction, and the per-record try/catch caught it but the root
    # cause was opaque. The OrderedDictionary hashtable-literal form has
    # known PS 7 issues with mixed-type value expressions inside its block
    # when $null values are present alongside [HashSet[string]] values.
    # PSCustomObject + Add-Member builds one property at a time and is
    # immune to the issue.
    #
    # Per-record diagnostic continues to isolate failures: any single
    # record that fails still gets skipped and surfaces its key + exception
    # in the WARN log, but expect the new construction path to succeed.
    $appsArr = New-Object System.Collections.Generic.List[object]
    $skippedAppBuild = 0
    $lastFailKey = $null
    $lastFailMsg = $null
    $lastFailStep = $null
    $appKeys = @($apps.Keys)
    foreach ($k in $appKeys) {
        $step = 'init'
        try {
            $r = $apps[$k]
            if ($null -eq $r) { $skippedAppBuild++; continue }

            $step = 'first_seen'
            $fsStr = $null
            if ($null -ne $r.first_seen) {
                if ($r.first_seen -is [datetime]) {
                    $fsStr = $r.first_seen.ToString('o')
                } else {
                    $fsStr = [string]$r.first_seen
                }
            }

            $step = 'last_seen'
            $lsStr = $null
            if ($null -ne $r.last_seen) {
                if ($r.last_seen -is [datetime]) {
                    $lsStr = $r.last_seen.ToString('o')
                } else {
                    $lsStr = [string]$r.last_seen
                }
            }

            $step = 'hashsets'
            # Materialize HashSets to string arrays one at a time.
            $wgIds = @()
            if ($null -ne $r.winget_activity_ids) {
                foreach ($v in $r.winget_activity_ids) { $wgIds += [string]$v }
            }
            $doIds = @()
            if ($null -ne $r.do_job_ids) {
                foreach ($v in $r.do_job_ids) { $doIds += [string]$v }
            }
            $hrs = @()
            if ($null -ne $r.hresults_observed) {
                foreach ($v in $r.hresults_observed) { $hrs += [string]$v }
            }
            $ops = @()
            if ($null -ne $r.operation_types) {
                foreach ($v in $r.operation_types) { $ops += [string]$v }
            }

            $step = 'timeline'
            # Timeline entries are already OrderedDictionary; convert each to
            # a PSCustomObject so ConvertTo-Json output stays clean.
            $tlOut = New-Object System.Collections.Generic.List[object]
            if ($null -ne $r.timeline) {
                foreach ($tlEntry in $r.timeline) {
                    if ($null -eq $tlEntry) { continue }
                    $tlObj = New-Object PSObject
                    Add-Member -InputObject $tlObj -NotePropertyName 'ts'     -NotePropertyValue ([string]$tlEntry.ts)
                    Add-Member -InputObject $tlObj -NotePropertyName 'phase'  -NotePropertyValue ([string]$tlEntry.phase)
                    Add-Member -InputObject $tlObj -NotePropertyName 'source' -NotePropertyValue ([string]$tlEntry.source)
                    Add-Member -InputObject $tlObj -NotePropertyName 'detail' -NotePropertyValue ([string]$tlEntry.detail)
                    [void]$tlOut.Add($tlObj)
                }
            }

            $step = 'build-object'
            $appObj = New-Object PSObject
            Add-Member -InputObject $appObj -NotePropertyName 'ime_app_id'             -NotePropertyValue $r.ime_app_id
            Add-Member -InputObject $appObj -NotePropertyName 'ime_app_name'           -NotePropertyValue $r.ime_app_name
            Add-Member -InputObject $appObj -NotePropertyName 'store_product_id'       -NotePropertyValue $r.store_product_id
            Add-Member -InputObject $appObj -NotePropertyName 'store_pfn'              -NotePropertyValue $r.store_pfn
            Add-Member -InputObject $appObj -NotePropertyName 'store_pfn_short'        -NotePropertyValue $r.store_pfn_short
            Add-Member -InputObject $appObj -NotePropertyName 'winget_activity_ids'    -NotePropertyValue $wgIds
            Add-Member -InputObject $appObj -NotePropertyName 'do_job_ids'             -NotePropertyValue $doIds
            Add-Member -InputObject $appObj -NotePropertyName 'hresults_observed'      -NotePropertyValue $hrs
            Add-Member -InputObject $appObj -NotePropertyName 'operation_types'        -NotePropertyValue $ops
            Add-Member -InputObject $appObj -NotePropertyName 'first_seen'             -NotePropertyValue $fsStr
            Add-Member -InputObject $appObj -NotePropertyName 'last_seen'              -NotePropertyValue $lsStr
            Add-Member -InputObject $appObj -NotePropertyName 'terminal_outcome'       -NotePropertyValue $r.terminal_outcome
            Add-Member -InputObject $appObj -NotePropertyName 'terminal_hr'            -NotePropertyValue $r.terminal_hr
            Add-Member -InputObject $appObj -NotePropertyName 'cp_terminal_state'      -NotePropertyValue $r.cp_terminal_state
            Add-Member -InputObject $appObj -NotePropertyName 'cp_terminal_state_name' -NotePropertyValue $r.cp_terminal_state_name
            Add-Member -InputObject $appObj -NotePropertyName 'cp_device_key'          -NotePropertyValue $r.cp_device_key
            Add-Member -InputObject $appObj -NotePropertyName 'cp_details_uri'         -NotePropertyValue $r.cp_details_uri
            Add-Member -InputObject $appObj -NotePropertyName 'timeline'               -NotePropertyValue $tlOut.ToArray()
            [void]$appsArr.Add($appObj)
        } catch {
            $skippedAppBuild++
            $lastFailKey = $k
            $lastFailMsg = $_.Exception.Message
            $lastFailStep = $step
        }
    }
    if ($skippedAppBuild -gt 0) {
        Write-CLog ("       WARN: {0} app record(s) skipped during emit build; lastFailKey={1}, step={2}, reason={3}" -f `
            $skippedAppBuild, $lastFailKey, $lastFailStep, $lastFailMsg) -Level ERROR
    }
    # Convert to array for JSON serialization
    $appsArr = $appsArr.ToArray()
    $correlation = [ordered]@{
        generator    = "Trace-IntuneAppDeploy v$APP_VERSION"
        computer     = $env:COMPUTERNAME
        trace_start  = $script:TraceStartedAt.ToString('o')
        trace_end    = $script:TraceEndedAt.ToString('o')
        app_count    = $appsArr.Count
        apps         = $appsArr
    }
    # v1.3.3: isolate the JSON serialization too, so if ConvertTo-Json itself
    # throws (e.g. on circular references or unexpected object types in the
    # timeline array), we still know what happened.
    try {
        $correlation | ConvertTo-Json -Depth 12 | Out-File -FilePath $correlationPath -Encoding UTF8
        Write-CLog ("       correlation_map.json: {0} app(s) tracked" -f $appsArr.Count)
    } catch {
        Write-CLog ("       correlation_map.json emit FAILED: {0}" -f $_.Exception.Message) -Level ERROR
        # Try a minimal fallback - just the counts, no nested arrays
        try {
            $fallback = [ordered]@{
                generator = "Trace-IntuneAppDeploy v$APP_VERSION"
                computer  = $env:COMPUTERNAME
                app_count = $appsArr.Count
                error     = $_.Exception.Message
            }
            $fallback | ConvertTo-Json | Out-File -FilePath $correlationPath -Encoding UTF8
            Write-CLog "       wrote minimal-fallback correlation_map.json"
        } catch {
            Write-CLog ("       fallback emit also failed: {0}" -f $_.Exception.Message) -Level ERROR
        }
    }

    # -------- Emit _FlowSummary.txt --------
    # v1.3.2: Wrap in inner try/catch. If the human-readable summary rendering
    # fails for any reason (sort, format, null deref, whatever), we still
    # have correlation_map.json on disk from the block above. Previously a
    # single failure here dumped everything - CP FinalStatus work included.
    try {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("Install Flow Summary - Trace-IntuneAppDeploy v$APP_VERSION")
    [void]$sb.AppendLine(("=" * 72))
    [void]$sb.AppendLine(("Computer   : {0}" -f $env:COMPUTERNAME))
    [void]$sb.AppendLine(("Trace start: {0}" -f $script:TraceStartedAt.ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine(("Trace end  : {0}" -f $script:TraceEndedAt.ToString('yyyy-MM-dd HH:mm:ss')))
    [void]$sb.AppendLine(("Duration   : {0} sec" -f [int]($script:TraceEndedAt - $script:TraceStartedAt).TotalSeconds))
    [void]$sb.AppendLine()
    if ($appsArr.Count -eq 0) {
        [void]$sb.AppendLine("No app-deployment correlation events detected in trace window.")
        [void]$sb.AppendLine("Check: IME_Delta\AppWorkload.log for policy receipt and")
        [void]$sb.AppendLine("       Historical__* winget logs for pre-trace activity.")
    } else {
        [void]$sb.AppendLine(("Apps observed ({0}):" -f $appsArr.Count))
        [void]$sb.AppendLine()
        # v1.3.2: Sort-Object -Property { $_.first_seen } crashes with
        # "Argument types do not match" when first_seen is a mix of ISO
        # strings and $null across records. Coerce missing timestamps to
        # a sentinel that sorts last so ordered apps still come first.
        $sorted = $appsArr | Sort-Object -Property @{
            Expression = { if ($_.first_seen) { $_.first_seen } else { 'ZZZZZZZZZZZZZ' } }
        }
        foreach ($a in $sorted) {
            $dispName = if ($a.ime_app_name) { $a.ime_app_name } `
                        elseif ($a.store_pfn_short) { $a.store_pfn_short } `
                        else { ($a.store_product_id, '(unknown)' -ne $null)[0] }
            [void]$sb.AppendLine(("-" * 72))
            [void]$sb.AppendLine(("App: {0}" -f $dispName))
            if ($a.ime_app_id)          { [void]$sb.AppendLine(("  IME App Id       : {0}" -f $a.ime_app_id)) }
            if ($a.store_product_id)    { [void]$sb.AppendLine(("  Store ProductId  : {0}" -f $a.store_product_id)) }
            if ($a.store_pfn)           { [void]$sb.AppendLine(("  Store PFN        : {0}" -f $a.store_pfn)) }
            if ($a.operation_types.Count -gt 0) {
                [void]$sb.AppendLine(("  Operation types  : {0}" -f ($a.operation_types -join ', ')))
            }
            if ($a.winget_activity_ids.Count -gt 0) {
                [void]$sb.AppendLine(("  WinGet Activities: {0}" -f ($a.winget_activity_ids -join ', ')))
            }
            if ($a.hresults_observed.Count -gt 0) {
                [void]$sb.AppendLine(("  HRESULTs observed: {0}" -f ($a.hresults_observed -join ', ')))
            }
            if ($a.terminal_outcome) {
                [void]$sb.AppendLine(("  IME Enforcement  : {0} (hr={1})" -f $a.terminal_outcome, $a.terminal_hr))
            } else {
                [void]$sb.AppendLine("  IME Enforcement  : (no IME terminal state observed in trace window)")
            }
            if ($a.cp_terminal_state_name) {
                [void]$sb.AppendLine(("  CP Terminal State: {0} (code={1})" -f $a.cp_terminal_state_name, $a.cp_terminal_state))
                if ($a.cp_device_key) {
                    [void]$sb.AppendLine(("  CP Device Key    : {0}" -f $a.cp_device_key))
                }
            } else {
                [void]$sb.AppendLine("  CP Terminal State: (no CP FinalStatus entry for this app)")
            }
            [void]$sb.AppendLine()
            [void]$sb.AppendLine("  Timeline:")
            foreach ($evt in ($a.timeline | Sort-Object -Property ts)) {
                [void]$sb.AppendLine(("    {0}  {1,-32}  {2}" -f $evt.ts, $evt.phase, $evt.detail))
            }
            [void]$sb.AppendLine()
        }
    }
    [void]$sb.AppendLine(("=" * 72))
    [void]$sb.AppendLine("End of flow summary. See _Summary.txt for trace metadata, Intune.xml")
    [void]$sb.AppendLine("for the file manifest, and correlation_map.json for the machine-")
    [void]$sb.AppendLine("readable per-app record consumed by the store analyzer.")
    $sb.ToString() | Out-File -FilePath $flowSummaryPath -Encoding UTF8
    Write-CLog ("       _FlowSummary.txt written ({0} app records)" -f $appsArr.Count)
    } catch {
        Write-CLog ("       _FlowSummary.txt rendering failed: {0}" -f $_.Exception.Message) -Level ERROR
        Write-CLog ("       correlation_map.json was written before the failure; see outputs/")
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
