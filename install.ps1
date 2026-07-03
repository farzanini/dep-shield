# install.ps1 — download and install dep-shield on Windows.
#
# Usage (always installs the latest release):
#   irm https://raw.githubusercontent.com/farzanini/dep-shield/main/install.ps1 | iex
#
# Usage (pin a version or choose a directory):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/farzanini/dep-shield/main/install.ps1))) -Version v1.2.3
#
# Flags:
#   -Version    VERSION   install a specific release tag (default: latest)
#   -InstallDir DIR       where to put dep-shield.exe (default: %LOCALAPPDATA%\dep-shield\bin)
#   -NoVerify             skip checksum verification (not recommended)
#
# Requires PowerShell 5.1+ or PowerShell 7+. goreleaser publishes a windows/amd64
# binary; on ARM64 Windows it runs via the built-in x64 emulation layer.

[CmdletBinding()]
param(
    [string]$Version = "",
    [string]$InstallDir = "$env:LOCALAPPDATA\dep-shield\bin",
    [switch]$NoVerify
)

$ErrorActionPreference = 'Stop'
$Repo = 'farzanini/dep-shield'

function Say($msg)  { Write-Host $msg -ForegroundColor Cyan }
function Fail($msg) { Write-Host "error: $msg" -ForegroundColor Red; exit 1 }

# ── Architecture ─────────────────────────────────────────────────────────────
# Only windows/amd64 is published; ARM64 Windows runs it under emulation.
$arch = 'amd64'
if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
    Write-Host "Note: only an amd64 build is published; it will run via emulation on ARM64." -ForegroundColor Yellow
}

# ── Resolve version ──────────────────────────────────────────────────────────
if ([string]::IsNullOrEmpty($Version)) {
    Say "Fetching latest release version..."
    try {
        $latest = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
            -Headers @{ 'User-Agent' = 'dep-shield-installer' }
        $Version = $latest.tag_name
    } catch {
        Fail "Could not determine latest version: $($_.Exception.Message)"
    }
    if ([string]::IsNullOrEmpty($Version)) { Fail "Could not determine latest version." }
}

Say "Installing dep-shield $Version (windows/$arch)"

# ── URLs (archive name matches goreleaser's name_template) ────────────────────
$archive      = "dep-shield_${Version}_windows_${arch}.zip"
$base         = "https://github.com/$Repo/releases/download/$Version"
$archiveUrl   = "$base/$archive"
$checksumsUrl = "$base/checksums.txt"

# ── Temp working directory ───────────────────────────────────────────────────
$tmp = Join-Path $env:TEMP ("dep-shield-" + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null
try {
    $archivePath   = Join-Path $tmp $archive
    $checksumsPath = Join-Path $tmp 'checksums.txt'

    Say "Downloading $archive..."
    Invoke-WebRequest -Uri $archiveUrl   -OutFile $archivePath   -UseBasicParsing
    Invoke-WebRequest -Uri $checksumsUrl -OutFile $checksumsPath -UseBasicParsing

    # ── Verify checksum ──────────────────────────────────────────────────────
    if (-not $NoVerify) {
        Say "Verifying checksum..."
        $expected = Get-Content $checksumsPath |
            Where-Object { $_ -match [regex]::Escape($archive) } |
            ForEach-Object { ($_ -split '\s+')[0] } |
            Select-Object -First 1
        if (-not $expected) { Fail "No checksum found for $archive in checksums.txt." }
        $actual = (Get-FileHash -Path $archivePath -Algorithm SHA256).Hash.ToLower()
        if ($actual -ne $expected.ToLower()) {
            Fail "Checksum verification failed (expected $expected, got $actual). The download may be corrupted."
        }
    }

    # ── Extract ──────────────────────────────────────────────────────────────
    Say "Extracting..."
    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force
    $binary = Join-Path $tmp 'dep-shield.exe'
    if (-not (Test-Path $binary)) { Fail "dep-shield.exe not found after extraction." }

    # ── Install ──────────────────────────────────────────────────────────────
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $dest = Join-Path $InstallDir 'dep-shield.exe'
    Copy-Item -Path $binary -Destination $dest -Force
    Say "Installed to $dest"

    # ── Add to the user PATH if missing ──────────────────────────────────────
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -split ';') -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
        $env:Path = "$env:Path;$InstallDir"
        Write-Host "Added $InstallDir to your user PATH (restart your terminal to pick it up)." -ForegroundColor Yellow
    }

    Write-Host ""
    Say "Run 'dep-shield --help' to get started."
}
finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
