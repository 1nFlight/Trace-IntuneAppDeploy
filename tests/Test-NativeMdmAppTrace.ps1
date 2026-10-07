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

foreach ($functionName in @(
    'Export-NativeMdmAppRegistry'
    'Get-NativeMdmLogSources'
    'Copy-NativeMdmAppLogs'
    'Start-NativeMdmAppTrace'
    'Stop-NativeMdmAppTrace'
    'Ensure-Dir'
)) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq $functionName
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $functionName" }
    . ([scriptblock]::Create($definition.Extent.Text))
}

$script:registryExports = [System.Collections.Generic.List[object]]::new()
function Export-RegKey {
    param([string]$Key, [string]$OutDir)
    $script:registryExports.Add([pscustomobject]@{ Key = $Key; OutDir = $OutDir })
}

function Invoke-Safe {
    param([string]$Label, [scriptblock]$Action)
    & $Action
}

$baseDir = 'Baseline'
$regDir = 'RegistryKeys'
foreach ($label in @(
    'baseline: registry (IME + native MDM apps)'
    'registry (end-state IME + app mgmt)'
)) {
    $commands = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.PipelineAst] -and
        $_.PipelineElements[0] -is [System.Management.Automation.Language.CommandAst] -and
        $_.PipelineElements[0].GetCommandName() -eq 'Invoke-Safe' -and
        $_.PipelineElements[0].CommandElements[1].Value -eq $label
    })
    if ($commands.Count -ne 1) { throw "Expected unconditional collection block: $label" }
    & ([scriptblock]::Create($commands[0].Extent.Text))
}

foreach ($key in @(
    'HKLM\SOFTWARE\Microsoft\EnterpriseDesktopAppManagement'
    'HKLM\SOFTWARE\Microsoft\OfficeCSP'
    'HKLM\SOFTWARE\Microsoft\Office\ClickToRun'
    'HKLM\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun'
)) {
    $baselineExports = @($script:registryExports | Where-Object { $_.Key -eq $key -and $_.OutDir -eq $baseDir })
    $odcExports = @($script:registryExports | Where-Object { $_.Key -eq $key -and $_.OutDir -eq $regDir })
    if ($baselineExports.Count -ne 1 -or $odcExports.Count -ne 2) {
        throw "Missing baseline or end-state native MDM registry export: $key"
    }
}

Write-Output 'PASS: native MSI and Office registry snapshots run at baseline and end-state without IME.'

function Write-CLog {
    param([string]$Message, [string]$Level)
    Write-Verbose "[$Level] $Message"
}

function Resolve-EtwProvider {
    param([string]$Name)
    if ($script:missingManifestProviders) { return $null }
    switch ($Name) {
        'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider' { return '{00000000-0000-0000-0000-000000000001}' }
        'Microsoft-Windows-Bits-Client' { return '{00000000-0000-0000-0000-000000000002}' }
        default { throw "Runtime-only provider must not depend on registration: $Name" }
    }
}

$script:logmanCalls = [System.Collections.Generic.List[object]]::new()
$script:failNativeStart = $false
$script:failNativeStop = $false
$script:missingManifestProviders = $false
function logman.exe {
    $script:logmanCalls.Add([pscustomobject]@{ Arguments = @($args) })
    $global:LASTEXITCODE = if (($script:failNativeStart -and $args[0] -eq 'create') -or
        ($script:failNativeStop -and $args[0] -eq 'stop')) { 5 } else { 0 }
    'Simulated logman result'
}

$testRoot = Join-Path $env:TEMP ('NativeMdmTrace-Test-' + [guid]::NewGuid().ToString('N') + " ' " + [char]0xe9)
try {
    $traceSession = Start-NativeMdmAppTrace -OutDir $testRoot
    $providerLines = @(Get-Content -LiteralPath (Join-Path $testRoot 'NativeMdmProviders.txt'))
    if ($providerLines.Count -ne 4 -or $traceSession.ProviderCount -ne 4) { throw 'Expected four native MDM trace providers.' }
    foreach ($providerGuid in @(
        '{ef614386-f019-4323-85a1-d6ebaf9cde12}'
        '{f01756f1-23c4-5663-6e27-5cb7e7942ad2}'
    )) {
        if ($providerLines -notcontains "$providerGuid 0xffffffffffffffff 5") { throw "Missing runtime-only provider: $providerGuid" }
    }
    $startArgs = $script:logmanCalls[0].Arguments
    foreach ($expectedArgument in @(
        @{ Name = '-o'; Value = (Join-Path $testRoot 'NativeMdm.etl') }
        @{ Name = '-f'; Value = 'bincirc' }
        @{ Name = '-max'; Value = '128' }
        @{ Name = '-pf'; Value = (Join-Path $testRoot 'NativeMdmProviders.txt') }
    )) {
        $argumentIndex = [array]::IndexOf($startArgs, $expectedArgument.Name)
        if ($argumentIndex -lt 0 -or $startArgs[$argumentIndex + 1] -ne $expectedArgument.Value) {
            throw "Incorrect logman argument: $($expectedArgument.Name)"
        }
    }
    if ($startArgs -notcontains '-ets') { throw 'Trace must not create a persistent collector.' }
    Stop-NativeMdmAppTrace -TraceSession $traceSession
    Stop-NativeMdmAppTrace -TraceSession $traceSession
    if ($traceSession.Running -or $script:logmanCalls.Count -ne 2 -or
        $script:logmanCalls[1].Arguments[1] -ne $traceSession.SessionName) { throw 'Trace cleanup is not owned and idempotent.' }
    Write-Output 'PASS: explicit runtime-provider GUIDs, bounded ETL, paths with spaces, and owned idempotent cleanup.'

    $script:failNativeStart = $true
    $observedError = $null
    try { $null = Start-NativeMdmAppTrace -OutDir $testRoot } catch { $observedError = $_.Exception.Message }
    if ($observedError -notlike 'Native MDM ETW start failed:*') { throw 'Trace startup failure was hidden.' }
    $script:failNativeStart = $false

    $script:missingManifestProviders = $true
    $traceSession = Start-NativeMdmAppTrace -OutDir $testRoot
    if ($traceSession.ProviderCount -ne 2) { throw 'Missing manifest providers removed the explicit CSP providers.' }
    $script:failNativeStop = $true
    $observedError = $null
    try { Stop-NativeMdmAppTrace -TraceSession $traceSession } catch { $observedError = $_.Exception.Message }
    if (-not $traceSession.Running -or $observedError -notlike 'Native MDM ETW stop failed:*') { throw 'Trace stop failure was hidden.' }
    $script:failNativeStop = $false
    Stop-NativeMdmAppTrace -TraceSession $traceSession
    Write-Output 'PASS: startup failure, missing optional providers, and retryable stop failure.'

    $startupCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and
        $node.CommandElements[1].Value -eq 'start native MSI / Office MDM trace'
    }, $true) | Select-Object -First 1
    $startupCondition = $startupCommand.Parent
    while ($startupCondition -and $startupCondition -isnot [System.Management.Automation.Language.IfStatementAst]) {
        $startupCondition = $startupCondition.Parent
    }
    $traceTry = $startupCondition.Parent
    while ($traceTry -and $traceTry -isnot [System.Management.Automation.Language.TryStatementAst]) {
        $traceTry = $traceTry.Parent
    }
    if (-not $startupCondition -or -not $traceTry.Finally) { throw 'Native trace is not guarded by cleanup.' }
    $trcDir = $testRoot
    $NoNetworkTrace = $true
    $NoNativeMdmTrace = $false
    $script:DOTraceProcess = $null
    $script:DOToolTempDir = $null
    & ([scriptblock]::Create($startupCondition.Extent.Text))
    if (-not $script:NativeMdmTrace.Running) { throw 'NoNetworkTrace disabled the native MDM trace.' }
    $script:IntuneRoot = $testRoot
    $script:TraceStartedAt = (Get-Date).AddMinutes(-1)
    & {
        function Get-NativeMdmLogSources { return @() }
        & ([scriptblock]::Create('& ' + $traceTry.Finally.Extent.Text))
    }
    if ($script:NativeMdmTrace.Running) { throw 'Finally did not stop the native MDM trace.' }
    $callCount = $script:logmanCalls.Count
    $NoNativeMdmTrace = $true
    & ([scriptblock]::Create($startupCondition.Extent.Text))
    if ($script:logmanCalls.Count -ne $callCount) { throw 'Native MDM opt-out was ignored.' }
    Write-Output 'PASS: owning start/finally blocks, NoNetworkTrace independence, and native ETW opt-out.'

    function Get-CimInstance {
        param([string]$ClassName, [string]$ErrorAction)
        if ($ClassName -ne 'Win32_UserProfile') { throw 'Unexpected inventory class.' }
        [pscustomobject]@{ LocalPath = (Join-Path $testRoot 'NondefaultProfile') }
    }
    $logSources = @(Get-NativeMdmLogSources -ComputerName 'TRACEHOST')
    foreach ($expectedPath in @(
        (Join-Path $testRoot 'NondefaultProfile\AppData\Local\mdm')
        (Join-Path $testRoot 'NondefaultProfile\AppData\Local\Temp')
        (Join-Path $env:SystemRoot 'System32\config\systemprofile\AppData\Local\mdm')
        (Join-Path $env:SystemRoot 'SysWOW64\config\systemprofile\AppData\Local\mdm')
        (Join-Path $env:SystemRoot 'Temp')
    )) {
        if ($logSources.Path -notcontains $expectedPath) { throw "Missing native log source: $expectedPath" }
    }

    $startUtc = [datetime]::UtcNow.AddMinutes(-5)
    $endUtc = $startUtc.AddMinutes(1)
    $logRoot = Join-Path $testRoot 'Logs'
    foreach ($fixture in @(
        @{ Path = 'System\job.log'; Age = 'Window' }
        @{ Path = 'User\job.log'; Age = 'Window' }
        @{ Path = 'Office\TRACEHOST-install.log'; Age = 'Window' }
        @{ Path = 'Office\officeclicktorun.log'; Age = 'Window' }
        @{ Path = 'Office\TRACEHOST-active.log'; Age = 'Active' }
        @{ Path = 'System\old.log'; Age = 'Old' }
        @{ Path = 'System\later.log'; Age = 'Later' }
        @{ Path = 'System\payload.msi'; Age = 'Window' }
        @{ Path = 'System\nested\other.log'; Age = 'Window' }
        @{ Path = 'Office\unrelated.log'; Age = 'Window' }
        @{ Path = 'Office\TRACEHOST-payload.exe'; Age = 'Window' }
    )) {
        $fixturePath = Join-Path $logRoot $fixture.Path
        Ensure-Dir (Split-Path -Path $fixturePath -Parent)
        ($fixture.Path + ' accent-' + [char]0xe9) | Set-Content -LiteralPath $fixturePath -Encoding Unicode
        $createdUtc = $startUtc.AddSeconds(1)
        $modifiedUtc = $endUtc.AddSeconds(-1)
        switch ($fixture.Age) {
            'Old' { $createdUtc = $startUtc.AddDays(-1); $modifiedUtc = $startUtc.AddMinutes(-1) }
            'Later' { $createdUtc = $endUtc.AddSeconds(1); $modifiedUtc = $endUtc.AddSeconds(2) }
            'Active' { $modifiedUtc = $endUtc.AddMinutes(1) }
        }
        [IO.File]::SetCreationTimeUtc($fixturePath, $createdUtc)
        [IO.File]::SetLastWriteTimeUtc($fixturePath, $modifiedUtc)
    }
    $sources = @(
        [pscustomobject]@{ Kind = 'MSI'; Path = (Join-Path $logRoot 'System'); Filters = @('*.log', 'job*.log') }
        [pscustomobject]@{ Kind = 'MSI'; Path = (Join-Path $logRoot 'User'); Filters = @('*.log') }
        [pscustomobject]@{ Kind = 'Office'; Path = (Join-Path $logRoot 'Office'); Filters = @('TRACEHOST*.log', 'officeclicktorun*.log') }
        [pscustomobject]@{ Kind = 'MSI'; Path = (Join-Path $logRoot 'Missing'); Filters = @('*.log') }
    )
    $logDestination = Join-Path $testRoot 'CollectedLogs'
    $copiedCount = Copy-NativeMdmAppLogs -Sources $sources -OutDir $logDestination -StartUtc $startUtc -EndUtc $endUtc
    if ($copiedCount -ne 5) { throw "Expected five relevant logs, collected $copiedCount." }
    $collectedFiles = @(Get-ChildItem -LiteralPath $logDestination -Recurse -File)
    if ($collectedFiles.Count -ne 6) { throw 'Unexpected files copied with native deployment logs.' }
    foreach ($record in (Import-Csv -LiteralPath (Join-Path $logDestination 'CollectedFiles.csv'))) {
        $sourceHash = (Get-FileHash -LiteralPath $record.SourcePath -Algorithm SHA256).Hash
        $copyHash = (Get-FileHash -LiteralPath (Join-Path $logDestination $record.CollectedPath) -Algorithm SHA256).Hash
        if ($sourceHash -ne $copyHash) { throw 'Native deployment log encoding or content changed.' }
    }
    if ((Copy-NativeMdmAppLogs -Sources @() -OutDir $logDestination -StartUtc $startUtc -EndUtc $endUtc) -ne 0) {
        throw 'An empty collection should report zero logs.'
    }
    Write-Output 'PASS: SYSTEM/user sources, window selection, active logs, duplicate filenames, byte preservation, and payload/history exclusions.'
} finally {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
}