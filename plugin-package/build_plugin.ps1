param(
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "dist"),
    [string]$MinimumGhostVersion = "1.2.1",
    [string]$SdkRef = "bb0c51dc64587e0dbe898fd554593eb28438a11a",
    [string]$PythonExe = "",
    [switch]$SkipCompile = $false
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$pythonCandidate = if ($PythonExe) { $PythonExe } else { Join-Path $projectRoot ".venv\Scripts\python.exe" }
if (-not (Test-Path -LiteralPath $pythonCandidate -PathType Leaf)) {
    throw "Build Python not found: $pythonCandidate. Create the project venv and install requirements.txt plus plugin-package/build-requirements.txt, or pass -PythonExe."
}
$python = (Resolve-Path -LiteralPath $pythonCandidate).Path
$pyinstallerCheck = & $python -m PyInstaller --version 2>&1
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is missing from $python. Install plugin-package/build-requirements.txt first."
}

$buildRoot = Join-Path $PSScriptRoot ".build"
$sdkToolDirectory = Join-Path (Join-Path $buildRoot "sdk") $SdkRef
$gpkgTool = Join-Path $sdkToolDirectory "gpkg.py"

# Prefer the local repo copy of gpkg.py if available, otherwise fetch/cache official SDK tool
$localGpkg = "D:\Projects\ghost-proxifier-ui\tools\plugin\gpkg.py"
if (Test-Path -LiteralPath $localGpkg -PathType Leaf) {
    New-Item -ItemType Directory -Path $sdkToolDirectory -Force | Out-Null
    Copy-Item -LiteralPath $localGpkg -Destination $gpkgTool -Force
} elseif (-not (Test-Path -LiteralPath $gpkgTool -PathType Leaf)) {
    if ($SdkRef -notmatch '^[0-9a-f]{40}$') {
        throw "SdkRef must be a 40-character commit SHA."
    }
    New-Item -ItemType Directory -Path $sdkToolDirectory -Force | Out-Null
    $sdkToolUrl = "https://raw.githubusercontent.com/liliBestCoder/ghost-plugin-sdk/$SdkRef/tools/plugin/gpkg.py"
    Invoke-WebRequest -Uri $sdkToolUrl -OutFile $gpkgTool
}

$frozenDist = Join-Path $buildRoot "frozen"
$workPath = Join-Path $buildRoot "pyinstaller-work"
$hookPath = Join-Path $PSScriptRoot "hooks"
$relationshipFile = Join-Path $projectRoot "DATA_RELATIONSHIPS.md"
$entryScript = Join-Path $projectRoot "plugin_main.py"
$frozenSnagboxDir = Join-Path $frozenDist "snagbox"
$exePath = Join-Path $frozenSnagboxDir "snagbox.exe"

if (-not $SkipCompile -or -not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
    if (-not (Test-Path -LiteralPath $relationshipFile -PathType Leaf)) {
        throw "Relationship guide not found: $relationshipFile"
    }
    if (Test-Path -LiteralPath $frozenDist) {
        Remove-Item -LiteralPath $frozenDist -Recurse -Force
    }
    New-Item -ItemType Directory -Path $frozenDist -Force | Out-Null

    $pyinstallerArgs = @(
        "-m", "PyInstaller", "--noconfirm", "--clean", "--onedir", "--console",
        "--optimize", "2",
        "--name", "snagbox", "--distpath", $frozenDist, "--workpath", $workPath,
        "--specpath", $buildRoot, "--paths", $projectRoot,
        "--additional-hooks-dir", $hookPath,
        "--add-data", "$relationshipFile;.",
        "--hidden-import=addon", "--hidden-import=database", "--hidden-import=mcp_server",
        "--collect-all=mitmproxy", "--collect-all=mitmproxy_rs", "--collect-submodules=mcp.server",
        "--collect-all=uvicorn",
        "--hidden-import=pydivert",
        "--exclude-module=matplotlib",
        "--exclude-module=numpy",
        "--exclude-module=PIL",
        "--exclude-module=contourpy",
        "--exclude-module=tkinter",
        "--exclude-module=urwid",
        "--exclude-module=tornado",
        "--exclude-module=_pyrepl",
        "--exclude-module=setuptools",
        $entryScript
    )
    Write-Host "Building snagbox onedir binary bundle with PyInstaller..."
    & $python @pyinstallerArgs
    if ($LASTEXITCODE -ne 0) {
        throw "PyInstaller failed with exit code $LASTEXITCODE"
    }
    if (-not (Test-Path -LiteralPath $exePath -PathType Leaf)) {
        throw "PyInstaller did not produce $exePath"
    }
} else {
    Write-Host "Using existing compiled directory: $frozenSnagboxDir"
}

$stage = Join-Path $PSScriptRoot ".stage"
$stageFull = [System.IO.Path]::GetFullPath($stage)
if (-not [string]::Equals((Split-Path -Parent $stageFull), [System.IO.Path]::GetFullPath($PSScriptRoot), [System.StringComparison]::OrdinalIgnoreCase) -or
    (Split-Path -Leaf $stageFull) -ne ".stage") {
    throw "Refusing to stage outside plugin-package: $stageFull"
}
if (Test-Path -LiteralPath $stageFull) {
    Remove-Item -LiteralPath $stageFull -Recurse -Force
}
New-Item -ItemType Directory -Path $stageFull | Out-Null

try {
    Write-Host "Staging onedir distribution..."
    Copy-Item -Path "$frozenSnagboxDir\*" -Destination $stageFull -Recurse

    # Prune unused components to fit strictly within 64 MB package limit
    Remove-Item -Path "$stageFull\_internal\mitmproxy\tools\web" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$stageFull\_internal\mitmproxy\tools\console" -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path "$stageFull\_internal\mitmproxy_windows" -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path "$stageFull\_internal" -Recurse -Directory -Filter "sboms" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "manifest.json") -Destination $stageFull

    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Write-Host "Packaging .gpkg using $gpkgTool with --min-app-version $MinimumGhostVersion..."
    & $python $gpkgTool pack --src $stageFull --out $OutputDirectory --min-app-version $MinimumGhostVersion
    if ($LASTEXITCODE -ne 0) {
        throw "gpkg.py pack failed with exit code $LASTEXITCODE"
    }
}
finally {
    $resolvedStage = [System.IO.Path]::GetFullPath($stageFull)
    if ([string]::Equals((Split-Path -Parent $resolvedStage), [System.IO.Path]::GetFullPath($PSScriptRoot), [System.StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedStage) -eq ".stage") {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "Snagbox plugin packaged successfully to $OutputDirectory"
