#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$collectorPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Trace-IntuneAppDeploy.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collectorPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw "Collector parse failed: $($parseErrors[0].Message)" }
foreach ($name in @('Resolve-TraceOutputRoot', 'Invoke-Safe')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
function Write-CLog {
    param([string]$Message, [string]$Level)
    Write-Verbose "[$Level] $Message"
}
function Assert-OutputError {
    param([scriptblock]$Action, [string]$Pattern)
    $observed = $null
    try { $null = & $Action } catch { $observed = $_.Exception.Message }
    if ($observed -notlike $Pattern) { throw "Expected '$Pattern', got '$observed'." }
}

$testRoot = Join-Path $env:TEMP ('OutputRoot-Test-' + [guid]::NewGuid().ToString('N') + " ' " + [char]0xe9)
$originalTemp = $env:TEMP
$null = [IO.Directory]::CreateDirectory($testRoot)
try {
    $desktop = Join-Path $testRoot 'Existing Desktop'
    $null = [IO.Directory]::CreateDirectory($desktop)
    if ((Resolve-TraceOutputRoot -Path $desktop) -ne $desktop) { throw 'Available Desktop default changed.' }
    $env:TEMP = Join-Path $testRoot 'System Temp'
    $fallback = Resolve-TraceOutputRoot -Path '' -WarningVariable fallbackWarnings -WarningAction SilentlyContinue
    if ($fallback -ne (Join-Path $env:TEMP 'IntuneAppDeployTraces') -or
        -not (Test-Path -LiteralPath $fallback -PathType Container) -or $fallbackWarnings.Count -ne 1) {
        throw 'Empty Desktop did not resolve to an explicitly announced temp fallback.'
    }
    foreach ($badPath in @('', ' ', "`t`r`n")) {
        Assert-OutputError { Resolve-TraceOutputRoot -Path $badPath -Explicit } '*must be a nonempty filesystem directory*'
    }
    $env:TEMP = ''
    Assert-OutputError { Resolve-TraceOutputRoot -Path '' } '*Desktop and TEMP are unavailable*'
    $env:TEMP = $originalTemp
    Write-Output 'PASS: available Desktop, missing Desktop fallback/warning, explicit blank rejection and missing TEMP.'

    $explicit = Join-Path $testRoot 'Explicit [MSI]\Nested output'
    if ((Resolve-TraceOutputRoot -Path $explicit -Explicit) -ne $explicit -or
        -not (Test-Path -LiteralPath $explicit -PathType Container)) { throw 'Explicit literal output path was not created.' }
    Push-Location -LiteralPath $testRoot
    try {
        $relative = Resolve-TraceOutputRoot -Path '.\Relative output' -Explicit
        if ($relative -ne (Join-Path $testRoot 'Relative output')) { throw 'Relative output was not normalized against the PowerShell location.' }
    } finally { Pop-Location }
    $null = New-PSDrive -Name OutputRootFixture -PSProvider FileSystem -Root $testRoot
    try {
        if ((Resolve-TraceOutputRoot -Path 'OutputRootFixture:\Drive output' -Explicit) -ne (Join-Path $testRoot 'Drive output')) {
            throw 'Filesystem PSDrive did not resolve to a native path.'
        }
    } finally { Remove-PSDrive -Name OutputRootFixture }
    Assert-OutputError { Resolve-TraceOutputRoot -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' -Explicit } '*FileSystem provider*'
    Assert-OutputError { Resolve-TraceOutputRoot -Path ($testRoot + '\' + [char]0) -Explicit } 'Cannot use OutputRoot*'
    $existingFile = Join-Path $testRoot 'not-a-directory.txt'
    'fixture' | Set-Content -LiteralPath $existingFile
    Assert-OutputError { Resolve-TraceOutputRoot -Path $existingFile -Explicit } '*existing file, not a directory*'
    Assert-OutputError { Resolve-TraceOutputRoot -Path (Join-Path $existingFile 'child') -Explicit } 'Cannot use OutputRoot*'

    $denied = Join-Path $testRoot 'Denied output'
    $null = [IO.Directory]::CreateDirectory($denied)
    $originalAcl = Get-Acl -LiteralPath $denied
    $restrictedAcl = Get-Acl -LiteralPath $denied
    $denyRule = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent().User,
        [Security.AccessControl.FileSystemRights]::WriteData,
        [Security.AccessControl.AccessControlType]::Deny
    )
    $restrictedAcl.AddAccessRule($denyRule)
    try {
        Set-Acl -LiteralPath $denied -AclObject $restrictedAcl
        Assert-OutputError { Resolve-TraceOutputRoot -Path $denied -Explicit } 'Cannot use OutputRoot*'
    } finally { Set-Acl -LiteralPath $denied -AclObject $originalAcl }
    if (@(Get-ChildItem -LiteralPath $testRoot -Recurse -Force -Filter '.AppDeployTrace_write_test_*.tmp').Count) {
        throw 'Output validation left temporary probe files.'
    }
    Write-Output 'PASS: explicit/relative/PSDrive/literal paths, invalid provider/path, existing file, creation/write failures and probe cleanup.'

    $resolveAssignment = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$OutputRoot'
    })
    $zipAssignment = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and
        $_.Left.Extent.Text -eq '$script:ZipPath' -and $_.Right.Extent.Text -like 'Join-Path $OutputRoot*'
    })
    if ($resolveAssignment.Count -ne 1 -or $zipAssignment.Count -ne 1 -or
        $resolveAssignment[0].Extent.StartOffset -ge $zipAssignment[0].Extent.StartOffset) {
        throw 'ZIP path is still constructed before output-root validation.'
    }
    $traceStart = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and
        $node.CommandElements[1].Value -eq 'start ETW network trace (netsh InternetClient_dbg + deployment providers)'
    }, $true) | Select-Object -First 1
    if (-not $traceStart -or $zipAssignment[0].Extent.StartOffset -ge $traceStart.Extent.StartOffset) {
        throw 'Output validation does not precede tracing.'
    }
    $preflight = [scriptblock]::Create(
        "[CmdletBinding()]`nparam([string]`$OutputRoot = `$script:defaultOutput)`n" +
        $resolveAssignment[0].Extent.Text + "`n" + $zipAssignment[0].Extent.Text + "`n`$script:ZipPath"
    )
    $script:ZipName = 'Fixture_AppDeployTrace.zip'
    $script:defaultOutput = ''
    $env:TEMP = Join-Path $testRoot 'Preflight temp'
    $defaultZip = & $preflight -WarningAction SilentlyContinue
    if ($defaultZip -ne (Join-Path $env:TEMP ('IntuneAppDeployTraces\' + $script:ZipName))) {
        throw 'Default main-script preflight still produces a blank ZIP path.'
    }
    $explicitZip = & $preflight -OutputRoot $desktop
    if ($explicitZip -ne (Join-Path $desktop $script:ZipName)) { throw 'Explicit main-script preflight did not build the ZIP target.' }
    Assert-OutputError { & $preflight -OutputRoot '' } '*must be a nonempty filesystem directory*'
    $env:TEMP = $originalTemp
    Write-Output 'PASS: actual preflight wiring, default/explicit parameter distinction and nonempty ZIP target before tracing.'

    $compression = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and $node.CommandElements[1].Value -eq 'compress to ZIP'
    }, $true) | Select-Object -First 1
    $assignment = $compression.Parent
    while ($assignment -and $assignment -isnot [System.Management.Automation.Language.AssignmentStatementAst]) {
        $assignment = $assignment.Parent
    }
    if (-not $assignment -or $assignment.Left.Extent.Text -ne '$zipCreated') { throw 'ZIP completion is not tracked.' }
    $completion = @($ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.IfStatementAst] -and
        $_.Clauses[0].Item1.Extent.Text -like '$zipCreated -and*'
    })
    if ($completion.Count -ne 1) { throw 'Stage deletion is not conditional on successful ZIP creation.' }
    $script:StageRoot = Join-Path $testRoot 'Preserved stage'
    $null = [IO.Directory]::CreateDirectory($script:StageRoot)
    'diagnostics' | Set-Content -LiteralPath (Join-Path $script:StageRoot 'Evidence.log')
    $script:ZipPath = Join-Path $testRoot 'Partial.zip'
    'incomplete archive' | Set-Content -LiteralPath $script:ZipPath
    $lockedEvidence = [IO.FileStream]::new(
        (Join-Path $script:StageRoot 'Evidence.log'),
        [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None
    )
    try {
        . ([scriptblock]::Create($assignment.Extent.Text))
        if ($zipCreated -or -not (Test-Path -LiteralPath $script:ZipPath -PathType Leaf)) {
            throw 'Synthetic compression failure did not produce the expected failed, partial-ZIP state.'
        }
    } finally { $lockedEvidence.Dispose() }
    $null = & ([scriptblock]::Create($completion[0].Extent.Text))
    if (-not (Test-Path -LiteralPath (Join-Path $script:StageRoot 'Evidence.log'))) {
        throw 'Failed compression discarded the only complete diagnostics.'
    }
    Write-Output 'PASS: a failed compression with a partial ZIP preserves staging instead of reporting success.'
} finally {
    $env:TEMP = $originalTemp
    Remove-Item -LiteralPath $testRoot -Recurse -Force
}
