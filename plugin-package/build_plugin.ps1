param(
    [Parameter(Mandatory = $true)]
    [string]$GhostRepo,
    [string]$OutputDirectory = (Join-Path $PSScriptRoot "dist"),
    [string]$MinimumGhostVersion = "1.2.3"
)

$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot ".." )).Path
$ghostRoot = (Resolve-Path $GhostRepo).Path
$gpkgTool = Join-Path $ghostRoot "tools\plugin\gpkg.py"
if (-not (Test-Path -LiteralPath $gpkgTool -PathType Leaf)) {
    throw "Ghost packaging tool not found: $gpkgTool"
}

$stage = Join-Path $PSScriptRoot ".stage"
$stageFull = [System.IO.Path]::GetFullPath($stage)
if (-not $stageFull.StartsWith([System.IO.Path]::GetFullPath($PSScriptRoot), [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to stage outside plugin-package: $stageFull"
}
if (Test-Path -LiteralPath $stageFull) {
    Remove-Item -LiteralPath $stageFull -Recurse -Force
}
New-Item -ItemType Directory -Path $stageFull | Out-Null

try {
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot "manifest.json") -Destination $stageFull
    foreach ($name in @("plugin_main.py", "addon.py", "database.py", "mcp_server.py", "DATA_RELATIONSHIPS.md")) {
        Copy-Item -LiteralPath (Join-Path $projectRoot $name) -Destination $stageFull
    }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    & py -3 $gpkgTool pack --src $stageFull --out $OutputDirectory --min-app-version $MinimumGhostVersion
    if ($LASTEXITCODE -ne 0) {
        throw "gpkg.py pack failed with exit code $LASTEXITCODE"
    }
}
finally {
    $resolvedStage = [System.IO.Path]::GetFullPath($stageFull)
    if ($resolvedStage.StartsWith([System.IO.Path]::GetFullPath($PSScriptRoot), [System.StringComparison]::OrdinalIgnoreCase) -and
        (Split-Path -Leaf $resolvedStage) -eq ".stage") {
        Remove-Item -LiteralPath $resolvedStage -Recurse -Force -ErrorAction SilentlyContinue
    }
}
