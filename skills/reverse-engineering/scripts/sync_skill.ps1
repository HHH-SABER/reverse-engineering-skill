# Skill sync: package dir (SOURCE OF TRUTH) -> every existing live skill dir + zip.
#
# Direction is fixed: package dir -> live copies + zip. The package directory is
# the source of truth; live copies and the zip are derivatives. Never edit a
# live copy and sync it back.
#
# Targets: by default every live skill dir that ALREADY exists is mirrored:
#   - $env:DSH_HOME\skills\reverse-engineering   (DeepSeek Harness)
#   - ~\.zcode\skills\reverse-engineering        (ZCode)
# Missing locations are NOT created implicitly; pass -LiveDir to install
# somewhere new on purpose.
#
# NOTE: this file is intentionally ASCII-only. Windows PowerShell 5.1 reads a
#       .ps1 file WITHOUT a UTF-8 BOM as ANSI, so non-ASCII comments can break
#       parsing ("unexpected token )"). Keep it ASCII, or save with BOM.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File sync_skill.ps1
#   powershell -ExecutionPolicy Bypass -File sync_skill.ps1 -WhatIf
#   powershell -ExecutionPolicy Bypass -File sync_skill.ps1 -SkipLive
#   powershell -ExecutionPolicy Bypass -File sync_skill.ps1 -LiveDir C:\path
#   powershell -ExecutionPolicy Bypass -File sync_skill.ps1 -LiveDir C:\a,C:\b
#
# Live sync is a MIRROR (wipe then copy), so files deleted or renamed in the
# package do not linger. README.md ships along; loaders only read SKILL.md.
param(
    [string]$PackageDir,
    [string]$ZipPath,
    [string[]]$LiveDir,
    [switch]$SkipLive,
    [switch]$WhatIf
)
$ErrorActionPreference = 'Stop'

if (-not $PackageDir) { $PackageDir = Split-Path -Parent $PSScriptRoot }

# Git-aware zip target. This skill now lives inside a git repo (skills/<name>/),
# where the zip is a legacy artifact - git is the distribution channel. Writing
# the zip next to the skill dir would drop it inside the repo, so when a .git is
# found in any ancestor the default becomes "no zip"; pass -ZipPath to force one.
$repoRoot = $null
if (-not $ZipPath) {
    $probe = $PackageDir
    while ($true) {
        if (Test-Path -LiteralPath (Join-Path $probe '.git')) { $repoRoot = $probe; break }
        $parent = Split-Path -Parent $probe
        if (-not $parent -or $parent -eq $probe) { break }
        $probe = $parent
    }
    if ($repoRoot) {
        $ZipPath = $null
    } else {
        $ZipPath = Join-Path (Split-Path -Parent $PackageDir) 'reverse-engineering-skill.zip'
    }
}

if (-not (Test-Path -LiteralPath (Join-Path $PackageDir 'SKILL.md'))) {
    throw "package dir has no SKILL.md: $PackageDir"
}

if (-not $LiveDir) {
    $candidates = @()
    if ($env:DSH_HOME) { $candidates += (Join-Path (Join-Path $env:DSH_HOME 'skills') 'reverse-engineering') }
    $candidates += (Join-Path $HOME '.zcode\skills\reverse-engineering')
    $LiveDir = @($candidates | Where-Object { Test-Path -LiteralPath $_ })
    if ($LiveDir.Count -eq 0) { $LiveDir = @($candidates[0]) }
}

$srcCount = (Get-ChildItem -LiteralPath $PackageDir -Recurse -File).Count
Write-Output "source : $PackageDir ($srcCount files)"

# 1) package -> each live dir (mirror)
foreach ($d in $LiveDir) {
    if ($SkipLive) {
        Write-Output "live   : skipped (-SkipLive) $d"
        continue
    }
    if ($WhatIf) {
        Write-Output "live   : [WhatIf] would mirror -> $d"
        continue
    }
    if (Test-Path -LiteralPath $d) { Remove-Item -LiteralPath $d -Recurse -Force }
    New-Item -ItemType Directory -Path $d -Force | Out-Null
    Copy-Item -Path (Join-Path $PackageDir '*') -Destination $d -Recurse -Force
    $n = (Get-ChildItem -LiteralPath $d -Recurse -File).Count
    if ($n -ne $srcCount) { Write-Warning "live file count $n != source $srcCount ($d)" }
    Write-Output "live   : $d ($n files)"
}

# 2) repack the zip (whole folder; entry prefix = folder name)
if ($WhatIf) {
    if ($ZipPath) { Write-Output "zip    : [WhatIf] would repack -> $ZipPath" }
    else          { Write-Output "zip    : [WhatIf] would skip (git repo: $repoRoot)" }
} elseif (-not $ZipPath) {
    Write-Output "zip    : skipped - git repo detected at $repoRoot; pass -ZipPath to force"
} else {
    if (Test-Path -LiteralPath $ZipPath) { Remove-Item -LiteralPath $ZipPath -Force }
    Compress-Archive -Path $PackageDir -DestinationPath $ZipPath -CompressionLevel Optimal
    $hash = (Get-FileHash -LiteralPath $ZipPath -Algorithm SHA256).Hash
    $entries = $null
    try {
        Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction Stop
        $z = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
        try { $entries = @($z.Entries | Where-Object { $_.Name -ne '' }).Count } finally { $z.Dispose() }
    } catch { Write-Warning "zip entry count skipped: $($_.Exception.Message)" }
    Write-Output "zip    : $ZipPath"
    if ($null -ne $entries -and $entries -ne $srcCount) {
        Write-Warning "zip file entries $entries != source $srcCount"
    }
    $extra = if ($null -ne $entries) { ", zip $entries files" } else { "" }
    Write-Output "verify : source $srcCount files$extra, sha256 $hash"
}
