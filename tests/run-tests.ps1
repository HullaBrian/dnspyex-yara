<#
.SYNOPSIS
    Generates YARA output for every method of several assemblies (3 wildcard modes, whole + partial ranges,
    rule + strings-only output, plus an edited-body case), then compiles and scans with yara-python to check that
    every rule matches the file it was generated from.
    Requires: .NET SDK, Python with `pip install yara-python`.
#>
param(
    [string]$DnSpyBin = (Join-Path $PSScriptRoot "..\.tools\dnSpy\bin"),
    [int]$MaxMethods = 4000,
    [string]$OutDir = (Join-Path ([IO.Path]::GetTempPath()) "dnspy-yara-tests")
)
$ErrorActionPreference = 'Stop'
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetExe = if ($dotnet) { $dotnet.Source } else { "$env:USERPROFILE\.dotnet\dotnet.exe" }
$DnSpyBin = (Resolve-Path $DnSpyBin).Path

& $dotnetExe build (Join-Path $PSScriptRoot "Sample\Sample.csproj") -c Release -nologo -v:q
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $dotnetExe build (Join-Path $PSScriptRoot "YaraGen.Tests\YaraGen.Tests.csproj") -c Release -nologo -v:q "-p:DnSpyBin=$DnSpyBin"
if ($LASTEXITCODE) { exit $LASTEXITCODE }

if (Test-Path $OutDir) { Remove-Item -Recurse -Force $OutDir }
$targets = @(
    (Join-Path $PSScriptRoot "Sample\bin\Release\net10.0\Sample.dll"),
    (Join-Path $DnSpyBin "dnlib.dll"),
    (Join-Path $DnSpyBin "dnSpy.Contracts.DnSpy.dll"),
    (Join-Path $DnSpyBin "dnSpy.dll")
)
& $dotnetExe (Join-Path $PSScriptRoot "YaraGen.Tests\bin\Release\net10.0\YaraGen.Tests.dll") $OutDir @targets --max $MaxMethods
if ($LASTEXITCODE) { exit $LASTEXITCODE }
python (Join-Path $PSScriptRoot "verify.py") (Join-Path $OutDir "manifest.json")
exit $LASTEXITCODE
