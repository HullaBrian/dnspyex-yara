<#
.SYNOPSIS
    Builds dnSpy.Yara and installs it into a dnSpyEx installation.
.EXAMPLE
    .\scripts\install.ps1 -DnSpyDir "C:\Tools\dnSpy"      # build against + install into your dnSpyEx
    .\scripts\install.ps1                                  # uses .tools\dnSpy (the dev copy)
    .\scripts\install.ps1 -DnSpyDir "C:\Tools\dnSpy" -OutputDir .\dist   # build only, copy dist\dnSpy.Yara yourself
#>
param(
    # Folder containing dnSpy.exe (the .NET build of dnSpyEx 6.5+). A "bin" subfolder is detected automatically.
    [string]$DnSpyDir = (Join-Path $PSScriptRoot "..\.tools\dnSpy"),
    [string]$Configuration = "Release",
    # Instead of installing into $DnSpyDir, put the extension folder (dnSpy.Yara\...) here.
    [string]$OutputDir
)
$ErrorActionPreference = 'Stop'

$DnSpyDir = (Resolve-Path $DnSpyDir).Path
$binDir = if (Test-Path (Join-Path $DnSpyDir "bin\dnSpy.Contracts.DnSpy.dll")) { Join-Path $DnSpyDir "bin" } else { $DnSpyDir }
if (-not (Test-Path (Join-Path $binDir "dnSpy.Contracts.DnSpy.dll"))) {
    throw "dnSpy.Contracts.DnSpy.dll not found under $DnSpyDir. Pass the folder that contains dnSpy.exe (.NET build, not the .NET Framework one)."
}

$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
$dotnetExe = if ($dotnet) { $dotnet.Source } elseif (Test-Path "$env:USERPROFILE\.dotnet\dotnet.exe") { "$env:USERPROFILE\.dotnet\dotnet.exe" } else { throw "The .NET SDK is required (https://dot.net)" }

$project = Join-Path $PSScriptRoot "..\src\dnSpy.Yara\dnSpy.Yara.csproj"
& $dotnetExe build $project -c $Configuration -nologo -v:m "-p:DnSpyBin=$binDir"
if ($LASTEXITCODE) { exit $LASTEXITCODE }

$outDir = Join-Path $PSScriptRoot "..\src\dnSpy.Yara\bin\$Configuration"
$target = if ($OutputDir) { Join-Path $OutputDir "dnSpy.Yara" } else { Join-Path $binDir "Extensions\dnSpy.Yara" }
New-Item -ItemType Directory -Force $target | Out-Null
foreach ($f in "dnSpy.Yara.x.dll", "dnSpy.Yara.x.pdb") {
    Copy-Item (Join-Path $outDir $f) $target -Force
}
Write-Host "Installed to $target"
if ($OutputDir) { Write-Host "Copy the dnSpy.Yara folder to <dnSpy>\bin\Extensions\ on the target machine." }
else { Write-Host "Restart dnSpy. Right-click code (or a method in the Assembly Explorer) -> YARA." }
