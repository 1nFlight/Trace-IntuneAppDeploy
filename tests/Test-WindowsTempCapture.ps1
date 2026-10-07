#Requires -Version 5.1

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$collectorPath = Join-Path (Split-Path -Path $PSScriptRoot -Parent) 'Trace-IntuneAppDeploy.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($collectorPath, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors) { throw "Collector parse failed: $($parseErrors[0].Message)" }
foreach ($name in @('Get-WindowsTempInventory', 'Copy-NewWindowsTempFiles', 'Invoke-Safe')) {
    $definition = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $true) | Select-Object -First 1
    if (-not $definition) { throw "Function not found: $name" }
    . ([scriptblock]::Create($definition.Extent.Text))
}
$script:messages = [System.Collections.Generic.List[object]]::new()
function Write-CLog {
    param([string]$Message, [string]$Level)
    $script:messages.Add([pscustomobject]@{ Message = $Message; Level = $Level })
}
function New-TempFixture {
    param([string]$RelativePath, [datetime]$CreatedUtc)
    $path = Join-Path $sourceRoot $RelativePath
    $null = [IO.Directory]::CreateDirectory((Split-Path -Path $path -Parent))
    ('Fixture: ' + $RelativePath + ' ' + [char]0xe9) | Set-Content -LiteralPath $path -Encoding Unicode
    [IO.File]::SetCreationTimeUtc($path, $CreatedUtc)
    [IO.File]::SetLastWriteTimeUtc($path, $CreatedUtc)
    return $path
}
function Get-ChildItem {
    param([string]$LiteralPath, [switch]$Force, [string]$ErrorAction)
    if ($script:blockedDirectory -and $LiteralPath -eq $script:blockedDirectory) { throw 'Simulated directory access denied.' }
    Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force -ErrorAction Stop
}

$testRoot = Join-Path $env:TEMP ('WindowsTemp-Test-' + [guid]::NewGuid().ToString('N') + " ' " + [char]0xe9)
$sourceRoot = Join-Path $testRoot 'Windows\Temp'
$stageRoot = Join-Path $sourceRoot 'Collector Stage'
$doRoot = Join-Path $sourceRoot 'Collector DO bundle'
$outDir = Join-Path $stageRoot 'Intune\Files\WindowsTemp'
$startUtc = [datetime]::UtcNow.AddMinutes(-2)
$endUtc = $startUtc.AddMinutes(1)
$locked = $null
$junction = Join-Path $sourceRoot 'Do not follow'
$originalSystemRoot = $env:SystemRoot
try {
    $null = [IO.Directory]::CreateDirectory($sourceRoot)
    $old = New-TempFixture 'old.log' $startUtc.AddDays(-1)
    $preexistingRecent = New-TempFixture 'existing-with-window-timestamp.log' $startUtc.AddSeconds(1)
    $replacement = New-TempFixture 'replaced.log' $startUtc.AddDays(-1)
    $script:blockedDirectory = Join-Path $sourceRoot 'Unreadable at baseline'
    $null = New-TempFixture 'Unreadable at baseline\old.log' $startUtc.AddDays(-1)
    $baseline = Get-WindowsTempInventory -SourceRoot $sourceRoot -ExcludedPaths @($stageRoot, $doRoot)
    if ($baseline.Files.Count -ne 3 -or $baseline.UnreadableDirectories.Count -ne 1) {
        throw 'Baseline was incomplete without reporting the unreadable subtree.'
    }
    $script:blockedDirectory = $null
    'updated during capture' | Add-Content -LiteralPath $old
    [IO.File]::SetLastWriteTimeUtc($old, $startUtc.AddSeconds(20))
    [IO.File]::Delete($replacement)
    $null = New-TempFixture 'replaced.log' $startUtc.AddSeconds(2)
    $expected = @(
        'MSI-install.log'
        'Nested [MSI]\same-name.log'
        'Other folder\same-name.log'
        'payload.tmp'
        'Nested [MSI]\CollectedFiles.csv'
        'Collector Stage-sibling\install.log'
        'replaced.log'
    )
    foreach ($relative in $expected | Where-Object { $_ -ne 'replaced.log' }) {
        $null = New-TempFixture $relative $startUtc.AddSeconds(10)
    }
    foreach ($relative in @('Collector Stage\new-collector.log', 'Collector DO bundle\new-do.log', 'Unreadable at baseline\new.log')) {
        $null = New-TempFixture $relative $startUtc.AddSeconds(10)
    }
    $null = New-TempFixture 'before-start.log' $startUtc.AddSeconds(-1)
    $null = New-TempFixture 'after-stop.log' $endUtc.AddSeconds(1)
    $script:blockedDirectory = Join-Path $sourceRoot 'Unreadable at stop'
    $null = New-TempFixture 'Unreadable at stop\new.log' $startUtc.AddSeconds(10)
    $lockedPath = New-TempFixture 'locked.log' $startUtc.AddSeconds(10)
    $locked = [IO.FileStream]::new($lockedPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    $outside = Join-Path $testRoot 'Junction target'
    $null = [IO.Directory]::CreateDirectory($outside)
    $outsideFile = Join-Path $outside 'outside.log'
    'do not copy' | Set-Content -LiteralPath $outsideFile
    [IO.File]::SetCreationTimeUtc($outsideFile, $startUtc.AddSeconds(10))
    $null = New-Item -ItemType Junction -Path $junction -Target $outside

    $result = Copy-NewWindowsTempFiles -Baseline $baseline -OutDir $outDir -StartUtc $startUtc -EndUtc $endUtc
    if ($result.CopiedCount -ne $expected.Count -or $result.FailedCount -ne 1 -or $result.UnreadableDirectoryCount -ne 2) {
        throw "Unexpected collection counts: $($result | ConvertTo-Json -Compress)"
    }
    $rows = @(Import-Csv -LiteralPath (Join-Path $outDir 'CollectedFiles.csv'))
    if ($rows.Count -ne ($expected.Count + 1)) { throw 'CSV did not record every selected file and copy failure.' }
    $totalBytes = [long]0
    foreach ($relative in $expected) {
        $source = Join-Path $sourceRoot $relative
        $copy = Join-Path $outDir ('Files\' + $relative)
        if (-not (Test-Path -LiteralPath $copy -PathType Leaf) -or
            (Get-FileHash -LiteralPath $source).Hash -ne (Get-FileHash -LiteralPath $copy).Hash) {
            throw "Missing or altered copied file: $relative"
        }
        $row = @($rows | Where-Object { $_.SourcePath -eq $source })
        if ($row.Count -ne 1 -or $row[0].Status -ne 'Copied' -or $row[0].CollectedPath -ne ('Files\' + $relative)) {
            throw "Incorrect source/copy mapping: $relative"
        }
        $totalBytes += (Get-Item -LiteralPath $copy).Length
    }
    $failedRow = @($rows | Where-Object { $_.SourcePath -eq $lockedPath })
    if ($failedRow.Count -ne 1 -or $failedRow[0].Status -ne 'Failed' -or -not $failedRow[0].Error -or
        (Test-Path -LiteralPath (Join-Path $outDir 'Files\locked.log')) -or $result.CollectedBytes -ne $totalBytes) {
        throw 'Locked-file failure was hidden, retained as a partial copy, or counted as success.'
    }
    $copiedFiles = @(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath (Join-Path $outDir 'Files') -Recurse -File)
    if ($copiedFiles.Count -ne $expected.Count -or -not (Test-Path -LiteralPath $outsideFile)) {
        throw 'Collection included history/staging/reparse targets or altered originals.'
    }
    if (@($script:messages | Where-Object { $_.Level -eq 'WARN' -and $_.Message -like '*locked.log*' }).Count -ne 1) {
        throw 'Locked-file failure was not explicitly logged.'
    }
    $locked.Dispose()
    $locked = $null
    [IO.Directory]::Delete($junction)
    $script:blockedDirectory = $null
    Write-Output 'PASS: recursive new files, all extensions, existing-file exclusion, timestamp bounds, replacements, literal paths and byte preservation.'
    Write-Output 'PASS: staging/DO/sibling boundaries, reparse points, unreadable baseline/stop subtrees and indexed/logged locked-file failure.'

    $baselineCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and $node.CommandElements[1].Value -eq 'baseline: Windows Temp files'
    }, $true) | Select-Object -First 1
    $startAssignment = $ast.EndBlock.Statements | Where-Object {
        $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and $_.Left.Extent.Text -eq '$script:TraceStartedAt'
    } | Select-Object -First 1
    $copyCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and $node.CommandElements[1].Value -eq 'new Windows Temp files'
    }, $true) | Select-Object -First 1
    if (-not $baselineCommand -or -not $copyCommand -or $baselineCommand.Extent.StartOffset -ge $startAssignment.Extent.StartOffset) {
        throw 'Temp baseline is not wired before the reproduction window.'
    }
    $copyParent = $copyCommand.Parent
    $abortGuard = $null
    $baselineGuard = $null
    while ($copyParent -and $copyParent -isnot [System.Management.Automation.Language.TryStatementAst]) {
        if ($copyParent -is [System.Management.Automation.Language.IfStatementAst] -and
            $copyParent.Clauses[0].Item1.Extent.Text -eq '-not $userAborted') { $abortGuard = $copyParent }
        if ($copyParent -is [System.Management.Automation.Language.IfStatementAst] -and
            $copyParent.Clauses[0].Item1.Extent.Text -eq '$script:WindowsTempBaseline') { $baselineGuard = $copyParent }
        $copyParent = $copyParent.Parent
    }
    if (-not $abortGuard -or -not $copyParent.Finally -or
        $copyCommand.Extent.StartOffset -lt $copyParent.Finally.Extent.StartOffset) {
        throw 'Temp copy is not protected by finally and the operator-abort guard.'
    }
    & {
        function Copy-NewWindowsTempFiles { throw 'Q must not copy temp files.' }
        $userAborted = $true
        $null = & ([scriptblock]::Create($abortGuard.Extent.Text))
    }
    $env:SystemRoot = Join-Path $testRoot 'Windows'
    $script:StageRoot = $stageRoot
    $script:DOToolTempDir = $doRoot
    $script:ZipPath = New-TempFixture 'Collector target.zip' $startUtc.AddSeconds(10)
    $NoNetworkTrace = $true
    $NoNativeMdmTrace = $true
    $NoDeliveryOptimizationTrace = $true
    $CaptureMsiWpr = $false
    if (-not (& ([scriptblock]::Create($baselineCommand.Extent.Text)))) { throw 'Actual temp baseline wiring failed.' }
    if ($script:WindowsTempBaseline.SourceRoot -ne $sourceRoot -or
        $script:WindowsTempBaseline.Files.ContainsKey($script:ZipPath) -or
        @($script:WindowsTempBaseline.Files.Keys | Where-Object {
            $_.StartsWith($stageRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
            $_.StartsWith($doRoot + '\', [StringComparison]::OrdinalIgnoreCase)
        }).Count) { throw 'Actual baseline source or collector exclusions are incorrect.' }
    $env:SystemRoot = $originalSystemRoot
    & {
        function Copy-NewWindowsTempFiles { throw 'Missing baseline must not copy any temp files.' }
        $script:WindowsTempBaseline = $null
        $null = & ([scriptblock]::Create($baselineGuard.Extent.Text))
    }
    if (-not @($script:messages | Where-Object {
        $_.Level -eq 'WARN' -and $_.Message -like '*no baseline inventory*'
    }).Count) { throw 'Missing baseline was not explicitly reported.' }
    Write-Output 'PASS: baseline-before-start, cleanup/finally wiring, capture-switch independence and Q exclusion.'
    Write-Output 'PASS: actual Windows Temp source/exclusion wiring and no whole-folder fallback when baseline is unavailable.'

    $emptyRoot = Join-Path $testRoot 'Empty source'
    $null = [IO.Directory]::CreateDirectory($emptyRoot)
    $emptyBaseline = Get-WindowsTempInventory -SourceRoot $emptyRoot
    $emptyResult = Copy-NewWindowsTempFiles -Baseline $emptyBaseline -OutDir (Join-Path $testRoot 'Empty output') -StartUtc $startUtc -EndUtc $endUtc
    if ($emptyResult.CopiedCount -ne 0 -or $emptyResult.FailedCount -ne 0) { throw 'Empty source did not report zero files.' }
    $invalidWindow = $false
    try { $null = Copy-NewWindowsTempFiles -Baseline $emptyBaseline -OutDir $outDir -StartUtc $endUtc -EndUtc $startUtc }
    catch { $invalidWindow = $_.Exception.Message -like '*end must not precede*' }
    if (-not $invalidWindow) { throw 'Invalid capture window was accepted.' }
    Write-Output 'PASS: empty source and explicit invalid-window failure.'

    function Get-CmdOutPath { return (Join-Path $testRoot 'Missing app diff.txt') }
    $script:StageRoot = $stageRoot
    $script:Summary = Join-Path $stageRoot '_Summary.txt'
    $script:WindowsTempCollection = $result
    $script:StartTime = $startUtc.ToLocalTime()
    $script:TraceStartedAt = $startUtc.ToLocalTime()
    $script:TraceEndedAt = $endUtc.ToLocalTime()
    $script:Computer = 'TRACEHOST'
    $script:ZipPath = Join-Path $testRoot 'WindowsTemp.zip'
    $script:DOTraceCaptured = $false
    $script:NativeMdmTrace = $null
    $script:MsiWprTrace = $null
    $script:NativeMdmLogCount = 0
    $NoNetworkTrace = $true
    $NoNativeMdmTrace = $true
    $CaptureMsiWpr = $false
    $userInterrupted = $true
    $APP_VERSION = 'test'
    $APP_BUILD = 'test'
    $MaxMinutes = 1
    $cmdDir = $testRoot
    $summaryCommand = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and $node.CommandElements[1].Value -eq 'write _Summary.txt'
    }, $true) | Select-Object -First 1
    if (-not (& ([scriptblock]::Create($summaryCommand.Extent.Text)))) {
        throw "Temp summary failed: $($script:messages[-1].Message)"
    }
    $summaryText = Get-Content -LiteralPath $script:Summary -Raw
    if (-not $summaryText.Contains('7 new file(s), 1 copy failure(s), 2 unreadable subtree(s)') -or
        -not $summaryText.Contains($sourceRoot)) { throw 'Summary omitted temp collection status.' }
    $compression = $ast.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq 'Invoke-Safe' -and $node.CommandElements[1].Value -eq 'compress to ZIP'
    }, $true) | Select-Object -First 1
    if (-not (& ([scriptblock]::Create($compression.Extent.Text)))) { throw 'Synthetic ZIP packaging failed.' }
    $archive = [IO.Compression.ZipFile]::OpenRead($script:ZipPath)
    try {
        $names = @($archive.Entries | ForEach-Object { $_.FullName -replace '\\', '/' })
        foreach ($relative in $expected) {
            if ($names -notcontains ('Intune/Files/WindowsTemp/Files/' + ($relative -replace '\\', '/'))) {
                throw "Temp file missing from ZIP: $relative"
            }
        }
        if ($names -notcontains 'Intune/Files/WindowsTemp/CollectedFiles.csv' -or $names -notcontains '_Summary.txt') {
            throw 'Temp index or summary missing from ZIP.'
        }
    } finally { $archive.Dispose() }
    Write-Output 'PASS: complete summary, source/copy CSV index and recursive files inside the final ZIP.'
} finally {
    $env:SystemRoot = $originalSystemRoot
    if ($locked) { $locked.Dispose() }
    if (Test-Path -LiteralPath $junction) { [IO.Directory]::Delete($junction) }
    $script:blockedDirectory = $null
    if (Test-Path -LiteralPath $testRoot) { Remove-Item -LiteralPath $testRoot -Recurse -Force }
}
