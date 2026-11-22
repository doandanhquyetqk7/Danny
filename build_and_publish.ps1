<#
.SYNOPSIS
    Dong goi va phat hanh Danny ver5.7.

.DESCRIPTION
    Script nay thuc hien day du chu trinh:
      1. Clean + build (Release) hai bien dich:
         - Danny-ver5.7.exe        : self-contained, single-file, win-x64
         - Danny-ver5.7-nethost.exe : framework-dependent (can .NET 8 Desktop Runtime)
      2. Dong goi thu muc phat hanh Danny-ver5.7/ (giong cau truc 5.0 / 5.5 / 5.6)
         kem thu muc tools/ (KVRT.exe, SetupMiAV.exe, RustDesk/, rules/, acronis/)
      3. Sinh SHA256SUMS.txt cho toan bo file phat hanh
      4. Tao file ZIP + file .sha256
      5. (Option) git add/commit/tag/push + tao GitHub Release

.EXAMPLE
    .\build_and_publish.ps1
    .\build_and_publish.ps1 -SkipPublish
    .\build_and_publish.ps1 -Push -Tag v5.7.0
#>

[CmdletBinding()]
param(
    # [switch]$SkipPublish : chi build + dong goi, khong git push
    [switch]$SkipPublish,

    # [string]$Tag : tag git cho release (mac dinh v5.7.0)
    [string]$Tag = 'v5.7.0',
    # [switch]$SkipZip : khong tao file ZIP
    [switch]$SkipZip
)

$ErrorActionPreference = 'Stop'

# =====================================================================
#  CAU HINH
# =====================================================================
$Root        = $PSScriptRoot
$Project     = Join-Path $Root 'NetSecTool\NetSecTool.csproj'
$Version     = '5.7'                                   # ten phien ban trong ten file
$AsmVersion  = '5.7.0'                                # AssemblyVersion trong .csproj
$ProductName = "Danny-ver$Version"
$ReleaseDir  = Join-Path $Root $ProductName
$DistDir     = Join-Path $Root 'dist'
$Rid         = 'win-x64'

function Write-Step ([string]$m) { Write-Host "`n=== $m" -ForegroundColor Cyan }
function Write-Ok   ([string]$m) { Write-Host "  [OK] $m" -ForegroundColor Green }
function Write-Warn ([string]$m) { Write-Host "  [!]  $m" -ForegroundColor Yellow }
function Write-Err  ([string]$m) { Write-Host "  [X]  $m" -ForegroundColor Red }

# =====================================================================
#  1. CLEAN
# =====================================================================
Write-Step '1/7 Don dep bin build'
foreach ($d in @('NetSecTool\bin', 'NetSecTool\obj')) {
    $p = Join-Path $Root $d
    if (Test-Path $p) { Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue }
}
if (Test-Path $ReleaseDir) { Remove-Item $ReleaseDir -Recurse -Force }
Write-Ok 'bin/obj va thu muc phat hanh cu da xoa'

# =====================================================================
#  2. RESTORE + BUILD
# =====================================================================
Write-Step '2/7 Restore + Build (Release)'
dotnet restore $Project --nologo | Out-Null
if ($LASTEXITCODE -ne 0) { Write-Err 'restore that bai'; exit 1 }
Write-Ok 'restore xong'

dotnet build $Project -c Release --nologo -v minimal
if ($LASTEXITCODE -ne 0) { Write-Err 'build that bai'; exit 1 }
Write-Ok 'build xong'

# =====================================================================
#  3. PUBLISH - SELF-CONTAINED SINGLE FILE
# =====================================================================
Write-Step "3/7 Publish self-contained single-file ($Rid)"
$scDir = Join-Path $DistDir 'publish-sc'
if (Test-Path $scDir) { Remove-Item $scDir -Recurse -Force }

dotnet publish $Project -c Release -r $Rid --self-contained true `
    -p:PublishSingleFile=true `
    -p:IncludeNativeLibrariesForSelfExtract=true `
    -p:EnableCompressionInSingleFile=true `
    -p:DebugType=none `
    -p:PublishTrimmed=false `
    -o $scDir --nologo -v minimal
if ($LASTEXITCODE -ne 0) { Write-Err 'publish self-contained that bai'; exit 1 }
Write-Ok "publish self-contained -> $scDir"

# =====================================================================
#  4. PUBLISH - FRAMEWORK DEPENDENT
# =====================================================================
Write-Step "4/7 Publish framework-dependent ($Rid)"
$fdDir = Join-Path $DistDir 'publish-fd'
if (Test-Path $fdDir) { Remove-Item $fdDir -Recurse -Force }

# KHONG dung PublishSingleFile cho ban framework-dependent: gom DLL vao exe se
# lam file nang ~148 MB, tro lai ~1.4 MB nhu cac ban 5.5 / 5.6 truoc.
dotnet publish $Project -c Release -r $Rid --self-contained false `
    -p:PublishSingleFile=false `
    -p:DebugType=none `
    -o $fdDir --nologo -v minimal
if ($LASTEXITCODE -ne 0) { Write-Err 'publish framework-dependent that bai'; exit 1 }
Write-Ok "publish framework-dependent -> $fdDir"

# =====================================================================
#  5. DONG GOI THU MUC PHAI HANH
# =====================================================================
Write-Step '5/7 Dong goi thu muc phat hanh'
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null

# --- 5a. exe self-contained (single-file, chay duoc moi may) ---
Copy-Item (Join-Path $scDir 'Danny.exe') (Join-Path $ReleaseDir "$ProductName.exe") -Force
Write-Ok "$ProductName.exe (self-contained, single-file)"

# --- 5b. Ban framework-dependent ---
# LUU Y KIEN THUC: .NET 8 WinForms framework-dependent KHONG tao duoc file
# "nethost" nho ~1.4 MB nhu ban 5.5/5.6. Khi PublishSingleFile=true, .NET gom
# native cua WinForms (D3DCompiler, PresentationNative, wpfgfx...) vao exe ->
# file le ~156 MB, LON HON ca ban self-contained.
#
# Giai phap dung: PublishSingleFile=false -> chi 5 file nho (~1.6 MB tong).
# Dat cung cap voi thu muc phat hanh (ke ca tools/) de:
#   - apphost tim dung "Danny.dll" (apphost doi ten van chay duoc - no tim
#     theo ten goc trong deps.json, khong phai theo ten file exe)
#   - code tim "tools\" qua AppContext.BaseDirectory van dung
$fdFiles = Get-ChildItem $fdDir -File
foreach ($f in $fdFiles) {
    Copy-Item $f.FullName $ReleaseDir -Force
}
if (Test-Path (Join-Path $ReleaseDir 'Danny.exe')) {
    Rename-Item -Path (Join-Path $ReleaseDir 'Danny.exe') -NewName "$ProductName-nethost.exe" -Force
}
$nethostSize = [math]::Round((Get-Item (Join-Path $ReleaseDir "$ProductName-nethost.exe")).Length / 1MB, 2)
Write-Ok "$ProductName-nethost.exe (framework-dependent, $nethostSize MB + DLL cung cap)"

# --- 5c. thu muc tools/ ---
$toolsOut = Join-Path $ReleaseDir 'tools'
New-Item -ItemType Directory -Force -Path $toolsOut | Out-Null
$resRoot = Join-Path $Root 'NetSecTool\Resources'

if (Test-Path (Join-Path $resRoot 'KVRT.exe')) {
    Copy-Item (Join-Path $resRoot 'KVRT.exe') (Join-Path $toolsOut 'KVRT.exe') -Force
    Write-Ok 'tools\KVRT.exe'
} else { Write-Warn 'thieu Resources\KVRT.exe' }

if (Test-Path (Join-Path $resRoot 'SetupMiAV.exe')) {
    Copy-Item (Join-Path $resRoot 'SetupMiAV.exe') (Join-Path $toolsOut 'SetupMiAV.exe') -Force
    Write-Ok 'tools\SetupMiAV.exe'
} else { Write-Warn 'thieu Resources\SetupMiAV.exe' }

$rustdeskOut = Join-Path $toolsOut 'RustDesk'
if (Test-Path (Join-Path $resRoot 'RustDesk')) {
    New-Item -ItemType Directory -Force -Path $rustdeskOut | Out-Null
    Copy-Item (Join-Path $resRoot 'RustDesk\*') $rustdeskOut -Recurse -Force
    Write-Ok 'tools\RustDesk\'
} else { Write-Warn 'thieu Resources\RustDesk' }

$rulesOut = Join-Path $toolsOut 'rules'
if (Test-Path (Join-Path $resRoot 'rules')) {
    New-Item -ItemType Directory -Force -Path $rulesOut | Out-Null
    Copy-Item (Join-Path $resRoot 'rules\*') $rulesOut -Recurse -Force
    Write-Ok 'tools\rules\forensic-rules.json'
} else { Write-Warn 'thieu Resources\rules' }

# thu muc acronis (placeholder - ban quyen rieng)
$acronisOut = Join-Path $toolsOut 'acronis'
New-Item -ItemType Directory -Force -Path $acronisOut | Out-Null
@'
# THU MUC ENGINE ACRONIS

Dat file acrocmd.exe (hoac AcronisTrueImageCmd.exe) vao thu muc nay de chuc nang
"Sao luu may tinh" tao duoc anh he thong (System Image).

Download: https://www.acronis.com/en-us/support/download

Neu khong co engine, phan "Anh he thong" se bao loi ro rang va chi chay duoc
phan "Du lieu nguoi dung" (robocopy).
'@ | Set-Content -Path (Join-Path $acronisOut 'README.txt') -Encoding UTF8
Write-Ok 'tools\acronis\ (placeholder)'

# --- 5d. tai lieu ---
foreach ($doc in @('README.md', 'CHANGELOG.md', 'HUONG-DAN-SU-DUNG.md')) {
    $src = Join-Path $Root $doc
    if (Test-Path $src) {
        Copy-Item $src $ReleaseDir -Force
        Write-Ok $doc
    } else {
        Write-Warn "thieu $doc"
    }
}

# =====================================================================
#  6. SHA256SUMS
# =====================================================================
Write-Step '6/7 Sinh SHA256SUMS.txt'
$sumFile = Join-Path $ReleaseDir 'SHA256SUMS.txt'
if (Test-Path $sumFile) { Remove-Item $sumFile -Force }

$lines = @()
Get-ChildItem $ReleaseDir -Recurse -File |
    Where-Object { $_.Name -ne 'SHA256SUMS.txt' } |
    Sort-Object FullName |
    ForEach-Object {
        $rel = $_.FullName.Substring($ReleaseDir.Length + 1).Replace('\', '/')
        $hash = (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        $lines += "$hash  $rel"
    }
Set-Content -Path $sumFile -Value $lines -Encoding UTF8
Write-Ok "SHA256SUMS.txt ($($lines.Count) file)"

# =====================================================================
#  7. ZIP
# =====================================================================
if (-not $SkipZip) {
    Write-Step '7/7 Tao file ZIP'
    New-Item -ItemType Directory -Force -Path $DistDir | Out-Null
    $zipPath = Join-Path $DistDir "$ProductName.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

    Compress-Archive -Path (Join-Path $ReleaseDir '*') -DestinationPath $zipPath -CompressionLevel Optimal -Force
    $zipSize = [math]::Round((Get-Item $zipPath).Length / 1MB, 2)
    Write-Ok "$ProductName.zip ($zipSize MB)"

    $zipHash = (Get-FileHash $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    Set-Content -Path (Join-Path $DistDir "$ProductName.zip.sha256") -Value "$zipHash  $ProductName.zip" -Encoding UTF8
    Write-Ok "$ProductName.zip.sha256"
} else {
    Write-Warn 'bo qua tao ZIP ( -SkipZip )'
}

# =====================================================================
#  TOM TAT
# =====================================================================
Write-Host ''
Write-Host '=========================================================' -ForegroundColor Green
Write-Host "  DONG GOI THANH CONG - Danny ver$Version" -ForegroundColor Green
Write-Host '=========================================================' -ForegroundColor Green
Write-Host "  Thu muc : $ReleaseDir"
Write-Host ''
Get-ChildItem $ReleaseDir -File | Select-Object Name, @{n='MB';e={[math]::Round($_.Length/1MB,2)}} |
    Format-Table -AutoSize

if ($SkipPublish) {
    Write-Host '  (bo qua git push - dung -SkipPublish)' -ForegroundColor DarkGray
    return
}

# =====================================================================
#  GIT + GITHUB RELEASE
# =====================================================================
Write-Step 'Git: branch + commit + tag + push'

$branch = "release/Danny-ver$Version-$(Get-Date -Format yyyyMMdd)"

git fetch origin --tags
git checkout -b $branch 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Warn "khong tao duoc branch $branch, dung branch hien tai: $(git branch --show-current)"
}

git add -A
git status --short | Select-Object -First 30

git commit -m "Danny ver$Version - Bo sung Forensic DFIR, KVRT updater, Uncover files, don dep 4 buoc, PC Backup" `
    -m "Modules moi (C# native):" `
    -m "- Forensic: bo thu thap chi doc + rule engine + timeline + bao cao HTML/MD/CSV/JSON" `
    -m "- KvrtUpdater: cap nhat Kaspersky KVRT voi xac thuc chu ky so + thay the atomic" `
    -m "- UncoverFiles: hien file/thu muc an (khong goi attrib.exe)" `
    -m "- PcCleanerV57: lam sach PC 4 buoc voi lenh thang quyen + bao cao chuan hoa" `
    -m "- BackupService: anh he thong (Acronis) + du lieu nguoi dung (robocopy), chi nho o di dong >= 1TB" `
    -m "" `
    -m "CLI moi: --kvrt-update | --uncover | --backup | --forensic"

$commitSha = (git rev-parse HEAD).Trim()
Write-Ok "commit: $commitSha"

git tag -a $Tag -m "Danny ver$Version" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Warn "tag $Tag da ton tai" }

git push -u origin $branch
git push origin $Tag

Write-Step 'Tao GitHub Release'
$releaseNotes = Join-Path $Root 'CHANGELOG.md'
$zipPath = Join-Path $DistDir "$ProductName.zip"

if ((Test-Path $zipPath) -and (Test-Path $releaseNotes)) {
    gh release create $Tag $zipPath `
        --repo doandanhquyetqk7/Danny `
        --title "Danny ver$Version" `
        --notes-file $releaseNotes `
        --verify-tag
} else {
    gh release create $Tag `
        --repo doandanhquyetqk7/Danny `
        --title "Danny ver$Version" `
        --notes "Dong goi Danny ver$Version - xem CHANGELOG.md va SHA256SUMS.txt." `
        --verify-tag
}

Write-Ok "Release $Tag da tao tren GitHub"

Write-Host ''
Write-Host ('  BRANCH  : https://github.com/doandanhquyetqk7/Danny/tree/' + $branch)
Write-Host ('  PULL REQ: https://github.com/doandanhquyetqk7/Danny/compare/main...' + $branch + '?expand=1')
