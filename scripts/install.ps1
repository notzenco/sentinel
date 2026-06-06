param(
    [string]$Version = $env:SENTINEL_VERSION,
    [string]$InstallDir = $env:SENTINEL_INSTALL_DIR,
    [string]$Repo = "notzenco/sentinel"
)

$ErrorActionPreference = "Stop"

if (-not $Version) {
    $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
    $Version = $release.tag_name
}

if (-not $InstallDir) {
    $InstallDir = Join-Path $HOME ".sentinel\bin"
}

$target = "x86_64-pc-windows-msvc"
$asset = "sentinel-$Version-$target.zip"
$baseUrl = "https://github.com/$Repo/releases/download/$Version"
$tmp = New-Item -ItemType Directory -Force -Path (Join-Path ([System.IO.Path]::GetTempPath()) "sentinel-install-$([guid]::NewGuid())")

try {
    $zipPath = Join-Path $tmp $asset
    $sumPath = "$zipPath.sha256"
    Invoke-WebRequest "$baseUrl/$asset" -OutFile $zipPath
    Invoke-WebRequest "$baseUrl/$asset.sha256" -OutFile $sumPath

    $expected = (Get-Content $sumPath).Split(" ")[0].ToLowerInvariant()
    $actual = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
        throw "checksum mismatch"
    }

    Expand-Archive $zipPath -DestinationPath $tmp -Force
    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    Copy-Item (Join-Path $tmp "sentinel-$Version-$target\sentinel.exe") (Join-Path $InstallDir "sentinel.exe") -Force
    Write-Host "sentinel installed to $(Join-Path $InstallDir 'sentinel.exe')"
} finally {
    Remove-Item $tmp -Recurse -Force
}
