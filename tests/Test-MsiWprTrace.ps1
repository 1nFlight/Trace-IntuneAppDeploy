#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$collectorPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Trace-IntuneAppDeploy.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $collectorPath, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors) { throw "Collector parse failed: $($parseErrors[0].Message)" }

foreach ($functionName in @('Start-MsiWprTrace', 'Stop-MsiWprTrace', 'Ensure-Dir', 'Invoke-Safe')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $functionName
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:wprCalls = [System.Collections.Generic.List[object]]::new()
$script:collectorMessages = [System.Collections.Generic.List[object]]::new()
$script:wprInstances = @{ ExistingWpr = $true }
$script:missingWpr = $false
$script:failWprStart = $false
$script:failWprStop = $false
$script:failWprCancel = $false
$script:wprSaveMode = 'Valid'

function Write-CLog {
    param([string]$Message, [string]$Level = 'INFO')
    $script:collectorMessages.Add([pscustomobject]@{ Message = $Message; Level = $Level })
    Write-Verbose "[$Level] $Message"
}

function Get-Command {
    param([string]$Name, [string]$CommandType, [string]$ErrorAction)
    if ($Name -ne 'wpr.exe' -or $CommandType -ne 'Application') { throw 'Unexpected command lookup.' }
    if (-not $script:missingWpr) { [pscustomobject]@{ Source = 'wpr.exe' } }
}

function wpr.exe {
    $arguments = @($args)
    $instanceIndex = [array]::IndexOf($arguments, '-instancename')
    if ($instanceIndex -ne ($arguments.Count - 2)) {
        throw 'Every WPR command must end with -instancename and its owned instance.'
    }
    $instanceName = $arguments[-1]
    if ($instanceName -notlike 'IntuneMsiWpr_*') { throw 'An unrelated WPR recording was targeted.' }
    $script:wprCalls.Add([pscustomobject]@{ Arguments = $arguments; InstanceName = $instanceName })
    $global:LASTEXITCODE = 0
    switch ($arguments[0]) {
        '-start' {
            $script:wprInstances[$instanceName] = $true
            if ($script:failWprStart) { $global:LASTEXITCODE = 5 }
        }
        '-stop' {
            if (-not $script:wprInstances.ContainsKey($instanceName)) { throw 'Stopping an unowned instance.' }
            if ($script:failWprStop) {
                $global:LASTEXITCODE = 5
            } else {
                $script:wprInstances.Remove($instanceName)
                switch ($script:wprSaveMode) {
                    'Valid' { 'SIMULATED_ETL' | Set-Content -LiteralPath $arguments[1] -Encoding ASCII }
                    'Empty' { [IO.File]::WriteAllBytes($arguments[1], [byte[]]@()) }
                    'Missing' { }
                    default { throw 'Unknown save mode.' }
                }
            }
        }
        '-cancel' {
            if ($script:failWprCancel) {
                $global:LASTEXITCODE = 5
            } else {
                $script:wprInstances.Remove($instanceName)
            }
        }
        default { throw "Unexpected WPR command: $($arguments[0])" }
    }
    'Simulated WPR output'
}

function Assert-TraceError {
    param([scriptblock]$Action, [string]$Pattern)
    $observedError = $null
    try { & $Action | Out-Null } catch { $observedError = $_.Exception.Message }
    if ($observedError -notlike $Pattern) {
        throw "Expected '$Pattern', observed '$observedError'."
    }
}

function Get-NativeMdmLogSources { return @() }
function Copy-NativeMdmAppLogs {
    param($Sources, [string]$OutDir, [datetime]$StartUtc, [datetime]$EndUtc)
    return 0
}
function Get-CmdOutPath {
    param([string]$Dir, [string]$OutputFileName)
    return (Join-Path $testRoot 'missing-app-diff.txt')
}

$testRoot = Join-Path $env:TEMP ('MsiWprTrace-Test-' + [guid]::NewGuid().ToString('N') + " ' " + [char]0xe9)
try {
    $parameter = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'CaptureMsiWpr' }
    if (-not $parameter -or $parameter.DefaultValue -or $parameter.Attributes.TypeName.FullName -notcontains 'switch') {
        throw 'CaptureMsiWpr must be an opt-in switch.'
    }

    $traceSession = Start-MsiWprTrace -OutDir (Join-Path $testRoot '[MSI] Successful trace')
    $startArgs = $script:wprCalls[0].Arguments
    if (($startArgs -join '|') -ne ("-start|GeneralProfile|-start|FileIO|-start|Registry|-filemode|-instancename|{0}" -f $traceSession.InstanceName)) {
        throw 'Incorrect WPR profiles, logging mode or instance arguments.'
    }
    if (-not $traceSession.Running -or $traceSession.Captured) { throw 'Incorrect initial WPR state.' }
    $secondSession = Start-MsiWprTrace -OutDir (Join-Path $testRoot 'Second trace')
    if ($traceSession.InstanceName -eq $secondSession.InstanceName) { throw 'Instance names are not unique.' }
    Stop-MsiWprTrace -TraceSession $traceSession
    $stopArgs = $script:wprCalls[-1].Arguments
    if ($stopArgs[0] -ne '-stop' -or $stopArgs[1] -ne $traceSession.EtlPath -or
        $stopArgs -notcontains '-compress' -or $stopArgs -notcontains '-skipPdbGen') {
        throw 'WPR save arguments are incorrect.'
    }
    if ($traceSession.Running -or -not $traceSession.Captured -or
        -not $script:wprInstances.ContainsKey($secondSession.InstanceName)) {
        throw 'Stopping one recording affected another recording or failed to save.'
    }
    $callCount = $script:wprCalls.Count
    Stop-MsiWprTrace -TraceSession $traceSession
    if ($script:wprCalls.Count -ne $callCount) { throw 'Stop is not idempotent.' }
    Stop-MsiWprTrace -TraceSession $secondSession -Discard
    if ($secondSession.Running -or $secondSession.Captured -or
        (Test-Path -LiteralPath $secondSession.EtlPath)) { throw 'Discard saved a recording.' }
    $callCount = $script:wprCalls.Count
    Stop-MsiWprTrace -TraceSession $secondSession -Discard
    if ($script:wprCalls.Count -ne $callCount) { throw 'Discard is not idempotent.' }
    Write-Output 'PASS: profiles, file mode, unique named instances, Unicode/literal paths, save/discard, and idempotent cleanup.'

    $script:missingWpr = $true
    Assert-TraceError { Start-MsiWprTrace -OutDir $testRoot } '*requires wpr.exe*'
    if ($script:wprCalls.Count -ne $callCount) { throw 'Missing WPR still issued trace commands.' }
    $script:missingWpr = $false
    $script:failWprStart = $true
    Assert-TraceError { Start-MsiWprTrace -OutDir $testRoot } 'MSI WPR start failed:*'
    if ($script:wprCalls[-1].Arguments[0] -ne '-cancel' -or
        $script:wprCalls[-1].InstanceName -ne $script:wprCalls[-2].InstanceName -or
        $script:wprInstances.Count -ne 1) { throw 'Failed-start cleanup did not target only its partial recording.' }
    $script:failWprCancel = $true
    Assert-TraceError { Start-MsiWprTrace -OutDir $testRoot } 'MSI WPR start failed:*'
    $failedInstance = $script:wprCalls[-1].InstanceName
    $cleanupWarnings = @($script:collectorMessages | Where-Object {
        $_.Level -eq 'WARN' -and $_.Message -like "*failed-start cleanup*$failedInstance*"
    })
    if ($cleanupWarnings.Count -ne 1) { throw 'Failed-start cleanup failure was not logged with its recovery command.' }
    $script:failWprStart = $false
    $script:failWprCancel = $false
    $null = wpr.exe -cancel -instancename $failedInstance
    Write-Output 'PASS: missing WPR, partial startup failure, isolated cancellation, and explicit cleanup failure.'

    $traceSession = Start-MsiWprTrace -OutDir (Join-Path $testRoot 'Retry trace')
    $script:failWprStop = $true
    Assert-TraceError { Stop-MsiWprTrace -TraceSession $traceSession } "MSI WPR stop failed:*Recover only this instance*$($traceSession.InstanceName)*"
    if (-not $traceSession.Running -or $traceSession.Captured) { throw 'Stop failure falsely reported completion.' }
    $script:failWprStop = $false
    Stop-MsiWprTrace -TraceSession $traceSession
    if ($traceSession.Running -or -not $traceSession.Captured) { throw 'Stop failure could not be retried.' }
    $traceSession = Start-MsiWprTrace -OutDir (Join-Path $testRoot 'Cancel retry')
    $script:failWprCancel = $true
    Assert-TraceError { Stop-MsiWprTrace -TraceSession $traceSession -Discard } 'MSI WPR cancel failed:*'
    if (-not $traceSession.Running) { throw 'Cancel failure falsely reported completion.' }
    $script:failWprCancel = $false
    Stop-MsiWprTrace -TraceSession $traceSession -Discard
    foreach ($saveMode in @('Missing', 'Empty')) {
        $script:wprSaveMode = $saveMode
        $traceSession = Start-MsiWprTrace -OutDir (Join-Path $testRoot $saveMode)
        Assert-TraceError { Stop-MsiWprTrace -TraceSession $traceSession } 'MSI WPR stopped but did not save a nonempty ETL:*'
        if ($traceSession.Running -or $traceSession.Captured) { throw 'An invalid ETL was reported as captured.' }
    }
    $script:wprSaveMode = 'Valid'
    Write-Output 'PASS: retryable stop/cancel failures, recovery commands, and rejection of missing/empty ETLs.'

    $startupCommands = @($ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and
        $node.CommandElements[1].Value -eq 'start MSI WPR trace'
    }, $true))
    if ($startupCommands.Count -ne 1) { throw 'Expected one MSI WPR startup block.' }
    $startupCondition = $startupCommands[0].Parent
    while ($startupCondition -and $startupCondition -isnot [System.Management.Automation.Language.IfStatementAst]) {
        $startupCondition = $startupCondition.Parent
    }
    if (-not $startupCondition -or $startupCondition.Clauses[0].Item1.Extent.Text -ne '$CaptureMsiWpr') {
        throw 'MSI WPR startup is not guarded solely by its opt-in flag.'
    }
    $traceTry = $startupCondition.Parent
    while ($traceTry -and $traceTry -isnot [System.Management.Automation.Language.TryStatementAst]) {
        $traceTry = $traceTry.Parent
    }
    if (-not $traceTry.Finally) { throw 'WPR startup is not protected by finally.' }
    $startupBlock = [scriptblock]::Create($startupCondition.Extent.Text)
    $cleanupBlock = [scriptblock]::Create('& ' + $traceTry.Finally.Extent.Text)
    $NoNetworkTrace = $true
    $NoNativeMdmTrace = $true
    $NoDeliveryOptimizationTrace = $true
    $script:NativeMdmTrace = $null
    $script:DOTraceProcess = $null
    $script:DOToolTempDir = $null
    $script:IntuneRoot = $testRoot
    $script:TraceStartedAt = (Get-Date).AddMinutes(-1)
    $script:MsiWprTrace = $null
    $trcDir = Join-Path $testRoot 'Wiring'
    $CaptureMsiWpr = $false
    $callCount = $script:wprCalls.Count
    $null = & $startupBlock
    if ($script:MsiWprTrace -or $script:wprCalls.Count -ne $callCount) { throw 'WPR ran without opt-in.' }

    $CaptureMsiWpr = $true
    foreach ($stopReason in @('Enter', 'Timeout', 'Abort', 'Interruption')) {
        $trcDir = Join-Path $testRoot $stopReason
        $userAborted = $stopReason -eq 'Abort'
        $userInterrupted = $stopReason -eq 'Enter'
        try {
            try {
                $null = & $startupBlock
                if (-not $script:MsiWprTrace.Running) { throw 'Other opt-out switches disabled MSI WPR.' }
                if ($stopReason -eq 'Interruption') { throw 'Simulated interruption' }
            } finally {
                $null = & $cleanupBlock
            }
        } catch {
            if ($stopReason -ne 'Interruption' -or $_.Exception.Message -ne 'Simulated interruption') { throw }
        }
        if ($script:MsiWprTrace.Running -or $script:MsiWprTrace.Captured -eq $userAborted) {
            throw "Incorrect finally cleanup for $stopReason."
        }
        $expectedCommand = if ($userAborted) { '-cancel' } else { '-stop' }
        if ($script:wprCalls[-1].Arguments[0] -ne $expectedCommand) { throw "Wrong cleanup command for $stopReason." }
    }
    $script:MsiWprTrace = $null
    $script:failWprStart = $true
    $null = & $startupBlock
    $script:failWprStart = $false
    if ($script:MsiWprTrace -or -not ($script:collectorMessages | Where-Object {
        $_.Level -eq 'ERROR' -and $_.Message -like '*start MSI WPR trace*MSI WPR start failed*'
    })) { throw 'Collector wiring hid WPR startup failure.' }
    Write-Output 'PASS: opt-in, independence from other capture switches, Enter/timeout/abort/interruption cleanup, and startup error reporting.'

    $script:StageRoot = Join-Path $testRoot 'Package'
    $script:Summary = Join-Path $script:StageRoot '_Summary.txt'
    $script:ZipPath = Join-Path $testRoot 'MsiWpr.zip'
    $script:StartTime = (Get-Date).AddMinutes(-2)
    $script:Computer = 'TRACEHOST'
    $script:DOTraceCaptured = $false
    $script:NativeMdmLogCount = 0
    $APP_VERSION = 'test'
    $APP_BUILD = 'test'
    $MaxMinutes = 1
    $cmdDir = $testRoot
    $userInterrupted = $true
    $script:MsiWprTrace = Start-MsiWprTrace -OutDir (Join-Path $script:StageRoot 'Trace')
    Stop-MsiWprTrace -TraceSession $script:MsiWprTrace

    $summaryCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and
        $node.CommandElements[1].Value -eq 'write _Summary.txt'
    }, $true) | Select-Object -First 1
    if (-not $summaryCommand) { throw 'Summary block not found.' }
    $summaryBlock = [scriptblock]::Create($summaryCommand.Extent.Text)
    foreach ($state in @('Captured', 'Disabled', 'Unavailable', 'Running', 'InvalidEtl')) {
        $savedTrace = $script:MsiWprTrace
        $CaptureMsiWpr = $state -ne 'Disabled'
        if ($state -eq 'Unavailable') {
            $script:MsiWprTrace = $null
        } else {
            $script:MsiWprTrace.Running = $state -eq 'Running'
            $script:MsiWprTrace.Captured = $state -eq 'Captured'
        }
        if (-not (& $summaryBlock)) { throw "Summary failed for ${state}: $($script:collectorMessages[-1].Message)" }
        $summaryText = Get-Content -LiteralPath $script:Summary -Raw
        $expectedStatus = switch ($state) {
            'Captured' { 'captured' }
            'Disabled' { 'disabled' }
            'Unavailable' { 'unavailable; see _Collector.log' }
            'Running' { 'stop failed; recording may still be active' }
            'InvalidEtl' { 'save failed; ETL unavailable or incomplete' }
        }
        if (-not $summaryText.Contains("MSI WPR trace     : $expectedStatus")) { throw "Incorrect summary status for $state." }
        if ($state -eq 'Captured' -and (-not $summaryText.Contains('GeneralProfile, FileIO, Registry') -or
            -not $summaryText.Contains($script:MsiWprTrace.InstanceName) -or
            -not $summaryText.Contains($script:MsiWprTrace.EtlPath) -or
            -not $summaryText.Contains('system-wide') -or -not $summaryText.Contains('WPR etl size'))) {
            throw 'Summary is missing WPR metadata.'
        }
        $script:MsiWprTrace = $savedTrace
    }
    $script:MsiWprTrace.Running = $false
    $script:MsiWprTrace.Captured = $true
    $CaptureMsiWpr = $true
    if (-not (& $summaryBlock)) { throw 'Final summary failed.' }
    $zipCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and
        $node.CommandElements[1].Value -eq 'compress to ZIP'
    }, $true) | Select-Object -First 1
    if (-not $zipCommand -or -not (& ([scriptblock]::Create($zipCommand.Extent.Text)))) {
        throw 'ZIP packaging failed.'
    }
    $archive = [IO.Compression.ZipFile]::OpenRead($script:ZipPath)
    try {
        $entryNames = @($archive.Entries | ForEach-Object { $_.FullName -replace '\\', '/' })
        if ($entryNames -notcontains 'Trace/MsiWpr.etl' -or $entryNames -notcontains '_Summary.txt') {
            throw 'WPR ETL or summary was not included in the ZIP.'
        }
    } finally {
        $archive.Dispose()
    }
    if ($script:wprInstances.Count -ne 1 -or -not $script:wprInstances.ExistingWpr) {
        throw 'Tests left an owned instance running or affected the pre-existing recording.'
    }
    Write-Output 'PASS: accurate capture/failure/disabled summary status, WPR metadata, ZIP inclusion, and unrelated-recording protection.'
} finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
