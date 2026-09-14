#Requires -Version 5.1

[CmdletBinding()]
param([switch]$CheckGallery)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Path $PSScriptRoot -Parent
$collectorPath = Join-Path $repoRoot 'Trace-IntuneAppDeploy.ps1'
$testRoot = Join-Path $env:TEMP ('TraceIntuneAppDeploy-Test-' + [guid]::NewGuid().ToString('N') + " ' " + [char]0xe9)
$fakeScriptPath = Join-Path $testRoot 'DeliveryOptimizationTroubleshooter.ps1'
$destinationPath = Join-Path $testRoot 'captured\Get-DeliveryOptimizationLog.txt'
$bundlePathFile = Join-Path $testRoot 'bundle-path.txt'
$preExistingBundle = Join-Path $env:TEMP ("dosvc-diag-$env:COMPUTERNAME-existing-$([guid]::NewGuid().ToString('N')).zip")
$traceProcess = $null
$bundlePath = $null
$script:doCleanupCalls = 0
$script:preExistingDOSettings = $null

function Get-ItemProperty {
    [CmdletBinding()]
    param([string]$LiteralPath)
    return $script:preExistingDOSettings
}

function Disable-DeliveryOptimizationVerboseLogs {
    [CmdletBinding()]
    param([switch]$Force)
    $script:doCleanupCalls++
}

function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-CLog {
    param(
        [Parameter(Mandatory)][string]$Message,
        [string]$Level = 'INFO'
    )
    Write-Verbose "[$Level] $Message"
}

try {
    Ensure-Dir $testRoot
    'PRE_EXISTING_BUNDLE' | Set-Content -LiteralPath $preExistingBundle

    $tokens = $null
    $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $collectorPath,
        [ref]$tokens,
        [ref]$parseErrors
    )
    if ($parseErrors) {
        throw "Collector parse failed: $($parseErrors[0].Message)"
    }

    foreach ($functionName in @(
        'Test-DeliveryOptimizationTroubleshooterTrust',
        'Resolve-DeliveryOptimizationTroubleshooter',
        'Start-DeliveryOptimizationTroubleshooterTrace',
        'Convert-DeliveryOptimizationReproductionTrace',
        'Complete-DeliveryOptimizationTroubleshooterTrace'
    )) {
        $definition = $ast.FindAll({
            param($node)
            $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq $functionName
        }, $true) | Select-Object -First 1
        if (-not $definition) { throw "Function not found: $functionName" }
        . ([scriptblock]::Create($definition.Extent.Text))
    }

    $fakeScript = @'
[CmdletBinding()]
param(
    [switch]$GenerateSupportBundle,
    [switch]$ReproduceIssueWithVerboseLogs
)

if (-not $GenerateSupportBundle -or -not $ReproduceIssueWithVerboseLogs) {
    throw 'Both official reproduction switches are required.'
}
$PID | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'child-pid.txt')
$scenarioPath = Join-Path $PSScriptRoot 'scenario.txt'
$scenario = if (Test-Path -LiteralPath $scenarioPath) { (Get-Content -LiteralPath $scenarioPath -Raw).Trim() } else { 'Success' }
if ($scenario -eq 'EarlyExit') {
    [Console]::Error.WriteLine('Simulated startup failure.')
    exit 7
}
Write-Host '[Step 11/12] Enabling verbose logging for issue reproduction...'
if ($scenario -eq 'StartupTimeout') {
    $null = [Console]::ReadLine()
    exit 8
}
Write-Host 'Please reproduce the issue now'
Read-Host | Out-Null
if ($scenario -eq 'StopTimeout') {
    $waitHandle = [Threading.ManualResetEvent]::new($false)
    $null = $waitHandle.WaitOne()
}
if ($scenario -eq 'ChildFailure') {
    [Console]::Error.WriteLine('Simulated finalization failure.')
    exit 7
}
if ($scenario -eq 'LargeOutput') {
    foreach ($iteration in 1..128) {
        [Console]::Out.WriteLine(('O' * 1024))
        [Console]::Error.WriteLine(('E' * 1024))
    }
}

$contentRoot = Join-Path $env:TEMP ('fake-do-content-' + [guid]::NewGuid().ToString('N'))
$bundlePath = Join-Path $env:TEMP ("dosvc-diag-$env:COMPUTERNAME-test-$([guid]::NewGuid().ToString('N')).zip")
try {
    New-Item -ItemType Directory -Path $contentRoot -Force | Out-Null
    $eventTime = (Get-Content -LiteralPath (Join-Path $PSScriptRoot 'event-time.txt') -Raw).Trim()
    @(
        '2000-01-01T00:00:00.0000000 4D2 162E Info {Download::Complete} HISTORICAL_MARKER'
        ('{0} 4D2 162E Info {{Download::Complete}} TRACE_ONLY_MARKER accent-{1}' -f $eventTime, [char]0xe9)
        'second line (hr:80070005)'
        '2099-01-01T00:00:00.0000000 4D2 162E Info {Download::Complete} POST_WINDOW_MARKER'
    ) | Set-Content -LiteralPath (Join-Path $contentRoot 'logs-dosvc-repro.txt')
    if ($scenario -eq 'MissingTrace') {
        Remove-Item -LiteralPath (Join-Path $contentRoot 'logs-dosvc-repro.txt') -Force
    } elseif ($scenario -eq 'EmptyTrace') {
        '' | Set-Content -LiteralPath (Join-Path $contentRoot 'logs-dosvc-repro.txt')
    } elseif ($scenario -eq 'UnsupportedTrace') {
        'Unsupported trace layout' | Set-Content -LiteralPath (Join-Path $contentRoot 'logs-dosvc-repro.txt')
    }
    'DO_NOT_RETAIN_EXISTING_LOGS' | Set-Content -LiteralPath (Join-Path $contentRoot 'logs-dosvc-existing.txt')
    'DO_NOT_RETAIN_CONFIG' | Set-Content -LiteralPath (Join-Path $contentRoot 'config-dosvc.txt')
    Compress-Archive -Path (Join-Path $contentRoot '*') -DestinationPath $bundlePath -Force
    $bundlePath | Set-Content -LiteralPath (Join-Path $PSScriptRoot 'bundle-path.txt')
    Write-Host 'Verbose logging disabled successfully.'
    Write-Host $bundlePath
} finally {
    Remove-Item -LiteralPath $contentRoot -Recurse -Force -ErrorAction SilentlyContinue
}
'@
    $fakeScript | Set-Content -LiteralPath $fakeScriptPath -Encoding UTF8

    $traceProcess = Start-DeliveryOptimizationTroubleshooterTrace `
        -ScriptPath $fakeScriptPath `
        -Deadline (Get-Date).AddSeconds(60) `
        -WorkingDirectory (Join-Path $testRoot 'Private DO output')
    if (-not $traceProcess -or $traceProcess.Process.HasExited) {
        throw 'The fake troubleshooter was not waiting for the stop signal.'
    }
    (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath (Join-Path $testRoot 'event-time.txt')

    $completed = Complete-DeliveryOptimizationTroubleshooterTrace `
        -TraceProcess $traceProcess `
        -DestinationPath $destinationPath
    if (-not $completed) { throw 'Trace completion returned false.' }
    $traceProcess = $null

    if (-not (Test-Path -LiteralPath $destinationPath)) {
        throw 'The reproduction trace was not extracted.'
    }
    $capturedText = Get-Content -LiteralPath $destinationPath -Raw
    if ($capturedText -notmatch 'TRACE_ONLY_MARKER') {
        throw 'The extracted trace does not contain the expected marker.'
    }
    if ($capturedText -match 'HISTORICAL_MARKER|POST_WINDOW_MARKER|DO_NOT_RETAIN') {
        throw 'Content outside the reproduction window was retained.'
    }
    foreach ($expectedField in @('ProcessId   : 1234', 'ThreadId    : 5678', 'ErrorCode   : -2147024891', 'second line (hr:80070005)', ('accent-' + [char]0xe9))) {
        if (-not $capturedText.Contains($expectedField)) { throw "Expected DO field missing: $expectedField" }
    }
    if (@(Get-ChildItem -LiteralPath (Split-Path $destinationPath -Parent) -File).Count -ne 1) {
        throw 'More than one DO trace artifact was retained.'
    }

    $bundlePath = Get-Content -LiteralPath $bundlePathFile -Raw
    $bundlePath = $bundlePath.Trim()
    if (Test-Path -LiteralPath $bundlePath) {
        throw 'The temporary DO support bundle was not deleted.'
    }
    if (-not (Test-Path -LiteralPath $preExistingBundle)) {
        throw 'A pre-existing DO support bundle was deleted.'
    }
    if ($script:doCleanupCalls -ne 0) {
        throw 'A successful troubleshooter triggered redundant parent cleanup.'
    }

    Write-Output 'PASS: one structured DO trace, hexadecimal IDs, HRESULT, multiline text, window filtering, and private-bundle cleanup.'

    foreach ($testCase in @(
        @{ Name = 'EarlyExit'; Error = 'did not enter reproduction mode'; CleanupCalls = 0 }
        @{ Name = 'StartupTimeout'; Error = 'did not enter reproduction mode'; CleanupCalls = 1 }
        @{ Name = 'ChildFailure'; Error = 'exited with code 7'; CleanupCalls = 1 }
        @{ Name = 'StopTimeout'; Error = 'stop timeout'; CleanupCalls = 1 }
        @{ Name = 'MissingTrace'; Error = 'does not contain logs-dosvc-repro.txt'; CleanupCalls = 0 }
        @{ Name = 'EmptyTrace'; Error = 'no events in the reproduction window'; CleanupCalls = 0 }
        @{ Name = 'UnsupportedTrace'; Error = 'expected LogOutput format'; CleanupCalls = 0 }
        @{ Name = 'ExistingSettings'; Error = 'tracing is already customized'; CleanupCalls = 0 }
        @{ Name = 'LargeOutput'; Error = $null; CleanupCalls = 0 }
    )) {
        $script:doCleanupCalls = 0
        $script:preExistingDOSettings = if ($testCase.Name -eq 'ExistingSettings') { [PSCustomObject]@{ TraceLevel_Override = 5 } } else { $null }
        $traceProcess = $null
        $caseDirectory = Join-Path $testRoot $testCase.Name
        $caseDestination = Join-Path $testRoot ("captured-$($testCase.Name).txt")
        $observedError = $null
        $testCase.Name | Set-Content -LiteralPath (Join-Path $testRoot 'scenario.txt')
        Remove-Item -LiteralPath (Join-Path $testRoot 'child-pid.txt') -Force -ErrorAction SilentlyContinue
        try {
            $startupSeconds = if ($testCase.Name -eq 'StartupTimeout') { 3 } else { 60 }
            $traceProcess = Start-DeliveryOptimizationTroubleshooterTrace `
                -ScriptPath $fakeScriptPath -Deadline (Get-Date).AddSeconds($startupSeconds) -WorkingDirectory $caseDirectory
            (Get-Date).ToUniversalTime().ToString('o') | Set-Content -LiteralPath (Join-Path $testRoot 'event-time.txt')
            $stopMilliseconds = if ($testCase.Name -eq 'StopTimeout') { 500 } else { 10000 }
            $null = Complete-DeliveryOptimizationTroubleshooterTrace -TraceProcess $traceProcess `
                -DestinationPath $caseDestination -CompletionTimeoutMilliseconds $stopMilliseconds
        } catch {
            $observedError = $_.Exception.Message
        }
        $traceProcess = $null
        if ($testCase.Error) {
            if (-not $observedError -or $observedError -notmatch [regex]::Escape($testCase.Error)) {
                throw "$($testCase.Name): expected '$($testCase.Error)', received '$observedError'."
            }
            if (Test-Path -LiteralPath $caseDestination) { throw "$($testCase.Name): partial trace was retained." }
        } elseif ($observedError -or -not (Test-Path -LiteralPath $caseDestination)) {
            throw "$($testCase.Name): trace completion failed: $observedError"
        }
        if ($script:doCleanupCalls -ne $testCase.CleanupCalls) { throw "$($testCase.Name): unexpected verbose-log cleanup count." }
        if (Test-Path -LiteralPath $caseDirectory) { throw "$($testCase.Name): private bundle directory was not removed." }
        $pidPath = Join-Path $testRoot 'child-pid.txt'
        if (Test-Path -LiteralPath $pidPath) {
            $childProcessId = [int](Get-Content -LiteralPath $pidPath -Raw)
            if (Get-Process -Id $childProcessId -ErrorAction SilentlyContinue) { throw "$($testCase.Name): child process is still running." }
        }
        if (-not (Test-Path -LiteralPath $preExistingBundle)) { throw "$($testCase.Name): unrelated bundle was removed." }
        Write-Output "PASS: $($testCase.Name)"
    }

    $logCommand = Get-Command Get-DeliveryOptimizationLog -ErrorAction SilentlyContinue
    if ($logCommand -and $logCommand.ImplementingType) {
        $outputType = $logCommand.ImplementingType.Assembly.GetType('Microsoft.Windows.DeliveryOptimization.AdminCommands.LogOutput')
        $syntheticEntry = [Runtime.Serialization.FormatterServices]::GetUninitializedObject($outputType)
        $values = @{
            TimeCreated = [datetime]::SpecifyKind([datetime]'2026-09-14T12:34:56.789', [DateTimeKind]::Unspecified)
            ProcessId   = [uint32]1234
            ThreadId    = [uint32]5678
            Level       = [uint32]5
            LevelName   = 'Verbose'
            Message     = 'Synthetic formatter parity'
            Function    = 'Download::Complete'
            LineNumber  = [uint32]42
            ErrorCode   = [int]-2147024891
        }
        foreach ($field in $outputType.GetFields([Reflection.BindingFlags]'NonPublic,Instance')) {
            $name = $field.Name -replace '^<([^>]+)>.*$', '$1'
            if ($values.ContainsKey($name)) { $field.SetValue($syntheticEntry, $values[$name]) }
        }
        $reader = [System.IO.StringReader]::new($syntheticEntry.ToString())
        $writer = [System.IO.StringWriter]::new()
        try {
            $entryCount = Convert-DeliveryOptimizationReproductionTrace -Reader $reader -Writer $writer `
                -StartUtc ([datetime]'2026-09-14T12:34:56Z').ToUniversalTime() `
                -EndUtc ([datetime]'2026-09-14T12:34:57Z').ToUniversalTime()
            if ($entryCount -ne 1 -or -not $writer.ToString().Contains('TimeCreated : 2026-09-14T12:34:56.789Z')) {
                throw 'The installed DO formatter is not compatible with the converter.'
            }
        } finally {
            $reader.Dispose()
            $writer.Dispose()
        }
        Write-Output 'PASS: installed DO LogOutput formatter parity using synthetic data only.'
    } else {
        Write-Output 'SKIP: installed DO formatter not available; fixture tests passed.'
    }

    if ($CheckGallery) {
        $toolPath = Resolve-DeliveryOptimizationTroubleshooter -DownloadDirectory (Join-Path $testRoot 'Gallery')
        if (-not $toolPath -or -not (Test-DeliveryOptimizationTroubleshooterTrust -Path $toolPath)) {
            throw 'Official Gallery acquisition or verification failed.'
        }
        if (Test-DeliveryOptimizationTroubleshooterTrust -Path $fakeScriptPath) {
            throw 'An unsigned, unpinned troubleshooter was accepted.'
        }
        Write-Output 'PASS: official troubleshooter acquisition and trust checks; downloaded code was not executed.'
    }
} finally {
    $pidPath = Join-Path $testRoot 'child-pid.txt'
    if (Test-Path -LiteralPath $pidPath) {
        $childProcessId = [int](Get-Content -LiteralPath $pidPath -Raw)
        Stop-Process -Id $childProcessId -Force -ErrorAction SilentlyContinue
    }
    if ($bundlePath -and (Test-Path -LiteralPath $bundlePath)) {
        Remove-Item -LiteralPath $bundlePath -Force -ErrorAction SilentlyContinue
    }
    Remove-Item -LiteralPath $preExistingBundle -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}