<#
.SYNOPSIS
    Lam sach cac log ghi lai "lich su ket noi Internet" cua phan mem MiAV (BTL86).

.DESCRIPTION
    Script nay thuc hien theo dua ket qua phan tich static cua SetupMiAV.exe 4.1.1.2
    (xem BAO-CAO-PHAN-TICH-MIAV.md).

    MiAV KHONG doc lich su trinh duyet / SRUM / DNS cache / Prefetch / Amcache.
    No chi:
      (C1) do trang thai ket noi hien tai bang 6 lenh mang -> ghi 6 file policy.*
      (C2) gom "netstat -nao" vao truong "connections" cua telemetry -> POST /api/v1/active-devices/insert
      (C3) ghi su kien type="Internet", name="Plug-in"/"Plug-out", level="Alert"
           vao bang Logs (SQLite data.db) + logs\ + log.txt -> POST /api/v1/events/insert

    => Script xoa DUNG nhom artifact do (nhom A + nhom B), va TOI CHON xoa them
       nhom C (lich su trinh duyet / DNS / Prefetch...) neu can giam be mat doi chieu.

.PARAMETER ReportOnly
    Chi kiem ke, khong dung dich. Xuat bao cao ra thu muc BaoCao.

.PARAMETER WhatIfMode
    Xoa thu (khong xoa that). Mac dinh la $true khi -ReportOnly duoc dung.

.PARAMETER KeepServicesStopped
    Khong bat lai service sau khi lam sach (dung khi ban muon tu khoi dong lai
    sau khi da dua may vao mang LAN quan su).

.PARAMETER AlsoCleanWindowsArtifacts
    Additionally xoa them cac artifact Windows: lich su trinh duyet, DNS cache,
    Prefetch, Amcache, Jump List / RunMRU / TypedPaths, Windows Event Log.
    KHONG bat buoc - khong co tac dong den ket luan cua MiAV.

.PARAMETER BackupRoot
    Thu muc sao luu. Mac dinh: C:\_MiAV_backup

.PARAMETER ReportRoot
    Thu muc luu bao cao CSV. Mac dinh: C:\_MiAV_backup\BaoCao

.PARAMETER AgentFMCRoot
    Thu muc cai dat MiAV. Mac dinh: C:\Users\Public\Documents\AgentFMC

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -ReportOnly

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -WhatIfMode:$false

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -WhatIfMode:$false -KeepServicesStopped

.NOTES
    Can chay voi quyen Administrator.
    Phai NGAT INTERNET truoc khi chay (ke ca khi chi chay -ReportOnly de do dung
    "co Internet hay khong").
#>

[CmdletBinding()]
param(
    [switch] $ReportOnly,
    [switch] $WhatIfMode,
    [switch] $KeepServicesStopped,
    [switch] $AlsoCleanWindowsArtifacts,
    [string] $BackupRoot = 'C:\_MiAV_backup',
    [string] $ReportRoot = 'C:\_MiAV_backup\BaoCao',
    [string] $AgentFMCRoot = 'C:\Users\Public\Documents\AgentFMC'
)

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

# ---------------------------------------------------------------- bien toan cuc
$AgentFMC     = $AgentFMCRoot
$DataDb       = Join-Path $AgentFMC 'data\data.db'
$PolicyFiles  = @(
    (Join-Path $AgentFMC 'policy.info'),
    (Join-Path $AgentFMC 'policy.ping'),
    (Join-Path $AgentFMC 'policy.net'),
    (Join-Path $AgentFMC 'policy.tracertWiki'),
    (Join-Path $AgentFMC 'policy.tracertpBTL'),
    (Join-Path $AgentFMC 'policy.tracertlBTL')
)
$LogDirs      = @(
    (Join-Path $AgentFMC 'logs'),
    (Join-Path $AgentFMC 'Debug')
)
$LogFiles     = @(
    (Join-Path $AgentFMC 'log.txt'),
    (Join-Path $AgentFMC 'syslog.ini'),
    (Join-Path $AgentFMC 'debugmiav.txt'),
    (Join-Path $AgentFMC 'debug.ini')
)
$ServiceNames = @('MiAVProtect', 'MiAVUpdate', 'MiAVWD', 'Defense')
$ServiceDisp  = @('MiAV_Protect', 'MiAV_Update', 'MiAV_WD', 'MiAV_Defense')
$MiAVProcess  = @('MiAV.exe', 'MiAV_Protect.exe', 'MiAV_Update.exe', 'MiAV_WD.exe', 'SerDefense.exe')

$Script:Log   = New-Object System.Collections.Generic.List[string]
# Che do "Thu" (khong thay doi gi ca): bat buoc khi -ReportOnly hoac -WhatIfMode
$Script:DryRun = ([bool] $WhatIfMode) -or ([bool] $ReportOnly)
$Script:FailCount = 0

function Write-Log {
    param([string] $Text, [string] $Level = 'INFO')
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    $line  = '[{0}] [{1}] {2}' -f $stamp, $Level, $Text
    Write-Host $line -ForegroundColor $(switch ($Level) {
        'WARN' { 'Yellow' } 'ERROR' { 'Red' } 'OK' { 'Green' } default { 'Gray' } })
    $Script:Log.Add($line) | Out-Null
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------------------------------------------------------------- ham tien ich
function Get-ServiceState {
    param([string] $Name)
    try {
        $s = Get-Service -Name $Name -ErrorAction Stop
        return $s.Status
    } catch { return $null }
}

function Invoke-Shell {
    param([string] $Exe, [string[]] $Args)
    $out = & $Exe @Args 2>&1
    return $out
}

# ------------------------------------------------- kiem tra Internet (khong bat buoc)
function Test-Internet {
    try {
        $r = Test-NetConnection -ComputerName '8.8.8.8' -Port 53 -WarningAction SilentlyContinue
        if ($r.TcpTestSucceeded) { return $true }
    } catch { }
    try {
        $r = Test-NetConnection -ComputerName 'www.wikipedia.org' -WarningAction SilentlyContinue
        if ($r.TcpTestSucceeded -or $r.PingSucceeded) { return $true }
    } catch { }
    return $false
}

# ---------------------------------------------------------- kiem ke SQLite Logs
# Luu y: Windows khong co System.Data.SQLite mac dinh. Script uu tien dung
# System.Data.SQLite neu co; neu khong thi dung Python (sqlite3 co san).
$Script:DbEngine = $null   # 'dotnet' | 'python'

function Initialize-DbEngine {
    if ($Script:DbEngine) { return $Script:DbEngine }
    try {
        Add-Type -AssemblyName System.Data.SQLite -ErrorAction Stop
        $Script:DbEngine = 'dotnet'
    } catch {
        $py = Get-Command python -ErrorAction SilentlyContinue
        if (-not $py) { $py = Get-Command python3 -ErrorAction SilentlyContinue }
        if ($py) { $Script:DbEngine = 'python' }
        else { $Script:DbEngine = $null }
    }
    Write-Log ("SQLite engine: {0}" -f $(if ($Script:DbEngine) { $Script:DbEngine } else { 'KHONG CO - hay cai sqlite3 hoac Python' })) 'INFO'
    return $Script:DbEngine
}

function Invoke-Sqlite {
    param([string] $Sql, [switch] $Execute)
    $eng = Initialize-DbEngine
    if (-not $eng) { throw 'Khong co SQLite engine nao kha dung.' }
    if ($eng -eq 'dotnet') {
        $con = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$DataDb;")
        $con.Open()
        $cmd = $con.CreateCommand()
        $cmd.CommandText = $Sql
        if ($Execute) {
            $n = $cmd.ExecuteNonQuery()
            $con.Close()
            return $n
        }
        $r = $cmd.ExecuteReader()
        $out = @()
        while ($r.Read()) {
            $row = [ordered]@{}
            for ($i = 0; $i -lt $r.FieldCount; $i++) { $row[$r.GetName($i)] = $r.GetValue($i) }
            $out += [pscustomobject]$row
        }
        $r.Close(); $con.Close()
        return $out
    } else {
        $py = (Get-Command python -ErrorAction SilentlyContinue)
        if (-not $py) { $py = (Get-Command python3 -ErrorAction SilentlyContinue) }
        $tmp = Join-Path $env:TEMP ("miav_sql_{0}.py" -f ([guid]::NewGuid().ToString('N')))
        $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Sql))
        @"
import sqlite3, sys, json
db = r'''$DataDb'''
sql = __import__('base64').b64decode('$b64').decode('utf-8')
con = sqlite3.connect(db)
cur = con.cursor()
res = cur.execute(sql).fetchall()
n = cur.rowcount
cols = [d[0] for d in cur.description] if cur.description else []
con.commit()
print(json.dumps({'cols': cols, 'rows': res, 'n': n}, ensure_ascii=False, default=str))
con.close()
"@ | Set-Content -Path $tmp -Encoding UTF8
        $raw = (& $py.Path $tmp 2>&1 | Out-String).Trim()
        Remove-Item $tmp -Force -ErrorAction SilentlyContinue
        if (-not $raw) { throw 'Python khong tra ve du lieu.' }
        $obj = $raw | ConvertFrom-Json
        if ($Execute) { return $obj.n }
        $out = @()
        foreach ($r in $obj.rows) {
            $h = [ordered]@{}
            for ($i = 0; $i -lt $obj.cols.Count; $i++) { $h[$obj.cols[$i]] = $r[$i] }
            $out += [pscustomobject]$h
        }
        return $out
    }
}

function Get-LogsTable {
    $rows = @()
    if (-not (Test-Path $DataDb)) {
        Write-Log ("Khong tim thay co so du lieu: {0}" -f $DataDb) 'WARN'
        Write-Log '=> May nay co the chua cai MiAV, hoac duong dan cai dat khac.' 'INFO'
        return [pscustomobject]@{ Total=0; Internet=0; InternetUnsent=0; Rows=@() }
    }
    try {
        $tot = Invoke-Sqlite 'SELECT COUNT(*) AS n FROM Logs'
        $total = $tot[0].n
        $n1 = Invoke-Sqlite "SELECT COUNT(*) AS n FROM Logs WHERE type='Internet'"
        $net = $n1[0].n
        $n2 = Invoke-Sqlite "SELECT COUNT(*) AS n FROM Logs WHERE type='Internet' AND (time_sent IS NULL OR time_sent='')"
        $netUnsent = $n2[0].n
        $rows = Invoke-Sqlite "SELECT type,name,log_time,time_sent,level FROM Logs ORDER BY id DESC LIMIT 500"
        Write-Log ("Bang Logs: tong={0}, type='Internet'={1}, chua gui={2}" -f $total, $net, $netUnsent) 'OK'
        return [pscustomobject]@{ Total=$total; Internet=$net; InternetUnsent=$netUnsent; Rows=$rows }
    } catch {
        Write-Log ("Khong doc duoc SQLite ({0})." -f $_.Exception.Message) 'ERROR'
        $Script:FailCount++
        return $null
    }
}

# -------------------------------------------------------------- tao ban sao luu
function Backup-Tree {
    param([string] $Path)
    if (-not (Test-Path $Path)) { return $null }
    $stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
    $dest  = Join-Path $BackupRoot ("AgentFMC_" + $stamp)
    try {
        New-Item -ItemType Directory -Force -Path $dest | Out-Null
        Copy-Item -Path $Path -Destination $dest -Recurse -Force -ErrorAction Stop
        Write-Log ("Da sao luu: {0} -> {1}" -f $Path, $dest) 'OK'    } catch {
        Write-Log ("Sao luu that bai {0}: {1}" -f $Path, $_.Exception.Message) 'ERROR'
        $Script:FailCount++
        return $null
    }
}

# ------------------------------------------------------------------ xoa file
function Remove-ItemSafe {
    param([string] $Path, [string] $Note = '')
    if (-not (Test-Path $Path)) { return }
    $sz = 0
    try { $sz = (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum } catch { }
    if ($Script:DryRun) {
        Write-Log ("[THU] XOA {0} {1}" -f $Path, $Note) 'WARN'
        return
    }
    try {
        Remove-Item -Path $Path -Recurse -Force -ErrorAction Stop
        Write-Log ("Da xoa: {0}{1}" -f $Path, $Note) 'OK'
    } catch {
        Write-Log ("Xoa that bai: {0} -> {1}" -f $Path, $_.Exception.Message) 'ERROR'
        $Script:FailCount++
    }
}

# ------------------------------------------------------- dung / bat lai service
function Stop-MiAVServices {
    Write-Log '--- Dung 4 service MiAV ---' 'INFO'
    foreach ($s in $ServiceNames) {
        $st = Get-ServiceState -Name $s
        if ($null -eq $st) {
            Write-Log ("Service '{0}' khong ton tai (bo qua)." -f $s) 'WARN'
            continue
        }
        Write-Log ("Service '{0}' hien tai: {1}" -f $s, $st) 'INFO'
        if ($Script:DryRun) {
            Write-Log ("[THU] sc stop {0} / sc config {0} start= disabled" -f $s) 'WARN'
            continue
        }
        try {
            & sc.exe stop $s 2>&1 | Out-Null
            Start-Sleep -Milliseconds 800
            & sc.exe config $s start= disabled 2>&1 | Out-Null
            Write-Log ("Da dung + disable service '{0}'." -f $s) 'OK'
        } catch {
            Write-Log ("Khong dung duoc service '{0}': {1}" -f $s, $_.Exception.Message) 'ERROR'
            $Script:FailCount++
        }
    }
}

function Start-MiAVServices {
    Write-Log '--- Bat lai 4 service MiAV ---' 'INFO'
    foreach ($s in $ServiceNames) {
        if ($Script:DryRun) {
            Write-Log ("[THU] sc config {0} start= auto / sc start {0}" -f $s) 'WARN'
            continue
        }
        try {
            & sc.exe config $s start= auto 2>&1 | Out-Null
            & sc.exe start $s 2>&1 | Out-Null
            Write-Log ("Da bat lai service '{0}'." -f $s) 'OK'
        } catch {
            Write-Log ("Khong bat lai duoc service '{0}': {1}" -f $s, $_.Exception.Message) 'ERROR'
            $Script:FailCount++
        }
    }
}

function Stop-MiAVProcesses {
    Write-Log '--- Dung tien trinh MiAV ---' 'INFO'
    foreach ($p in $MiAVProcess) {
        $procs = Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($p)) -ErrorAction SilentlyContinue
        if (-not $procs) { continue }
        if ($Script:DryRun) {
            Write-Log ("[THU] taskkill /IM {0} /F" -f $p) 'WARN'
            continue
        }
        try {
            $procs | Stop-Process -Force -ErrorAction Stop
            Write-Log ("Da dung tien trinh '{0}'." -f $p) 'OK'
        } catch {
            Write-Log ("Khong dung duoc tien trinh '{0}': {1}" -f $p, $_.Exception.Message) 'ERROR'
            $Script:FailCount++
        }
    }
}

# ------------------------------------------- nhóm C: artifact Windows (tuy chon)
function Clear-WindowsArtifacts {
    Write-Log '--- Xoa artifact Windows (tuy chon) ---' 'INFO'
    if ($Script:DryRun) {
        Write-Log '[THU] bat dau xoa artifact Windows' 'WARN'
        return
    }

    # DNS cache
    try { & ipconfig.exe /flushdns 2>&1 | Out-Null; Write-Log 'Da flush DNS cache.' 'OK' } catch { }

    # Prefetch
    Remove-ItemSafe (Join-Path $env:windir 'Prefetch\*') '(tuy chon)'

    # Amcache
    Remove-ItemSafe (Join-Path $env:windir 'AppCompat\Programs\Amcache.hve') '(tuy chon)'

    # Jump List / RunMRU / TypedPaths
    $users = Get-ChildItem 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer' -ErrorAction SilentlyContinue
    Remove-ItemSafe "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations" '(tuy chon)'
    Remove-ItemSafe "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations" '(tuy chon)'
    Remove-ItemSafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU' '(tuy chon)'
    Remove-ItemSafe 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths' '(tuy chon)'

    # Lich su trinh duyet
    $browsers = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data",
        "$env:LOCALAPCDATA\Google\Chrome\User Data\Default\Cookies",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data",
        "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
    )
    foreach ($b in $browsers) {
        if (Test-Path $b) { Remove-ItemSafe $b '(tuy chon - lich su trinh duyet)' }
    }

    # Windows Event Log
    try {
        foreach ($log in (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object { $_.RecordCount -gt 0 })) {
            & wevtutil.exe cl $log.LogName 2>&1 | Out-Null
        }
        Write-Log 'Da xoa Windows Event Log.' 'OK'
    } catch { }
}

# ============================================================================
# MAIN
# ============================================================================
Write-Host ''
Write-Host '===============================================================' -ForegroundColor DarkRed
Write-Host '  LAM SACH LOG LICH SU KET NOI INTERNET - MIAV (BTL86 4.1.1.2)' -ForegroundColor DarkRed
Write-Host '===============================================================' -ForegroundColor DarkRed
Write-Host ''

if (-not (Test-Admin)) {
    Write-Log 'CAN QUYEN ADMINISTRATOR. Hay chay lai bang quyen cao nhat.' 'ERROR'
    exit 1
}
Write-Log 'Quyen Administrator: OK' 'OK'

# --- buoc 1: kiem tra Internet
$hasNet = Test-Internet
if ($hasNet) {
    Write-Log 'CANH BAO: may van co Internet. Hay NGAT Internet truoc khi tiep tuc.' 'WARN'
    Write-Log '  Ly do: MiAV se tao lai policy.* va ghi su kien Plug-in moi ngay lap.' 'WARN'
} else {
    Write-Log 'Xac nhan: may KHONG co Internet (dieu kien ly tuong).' 'OK'
}

# --- buoc 2: kiem ke
Write-Log '--- Kiem ke hien trang ---' 'INFO'
New-Item -ItemType Directory -Force -Path $ReportRoot | Out-Null
$stamp = (Get-Date).ToString('yyyyMMdd_HHmmss')
$csvPath = Join-Path $ReportRoot ("Logs_Inventory_{0}.csv" -f $stamp)

$inv = Get-LogsTable
if ($inv) {
    try {
        $inv.Rows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Log ("Bao cao CSV: {0}" -f $csvPath) 'OK'
    } catch {
        Write-Log ("Khong xuat duoc CSV: {0}" -f $_.Exception.Message) 'ERROR'
    }
}
Write-Log ("Tien trinh MiAV dang chay: {0}" -f ((Get-Process -Name MiAV, MiAV_Protect, MiAV_Update, MiAV_WD, SerDefense -ErrorAction SilentlyContinue | Measure-Object).Count)) 'INFO'
Write-Log ("Service dang chay: {0}" -f ((@('MiAVProtect','MiAVUpdate','MiAVWD','Defense') | Where-Object { (Get-ServiceState $_) -eq 'Running' } | Measure-Object).Count)) 'INFO'

# --- buoc 3: sao luu
if (-not $ReportOnly) {
    New-Item -ItemType Directory -Force -Path $BackupRoot | Out-Null
    Backup-Tree -Path $AgentFMC
}

# --- buoc 4/5: dung service + tien trinh
if (-not $ReportOnly) {
    Stop-MiAVServices
    Stop-MiAVProcesses
    Start-Sleep -Seconds 2
}

# --- buoc 6: xoa NHOM A
Write-Log '--- Xoa NHOM A (bat buoc) ---' 'INFO'
# 6.1 bang Logs trong data.db
if ($inv -and $inv.Internet -gt 0) {
if ($Script:DryRun) {
    Write-Log ("[THU] DELETE FROM Logs (xoa {0} dong, trong do {1} dong type='Internet')" -f $inv.Total, $inv.Internet) 'WARN'
} else {
        try {
            $n = (Invoke-Sqlite 'DELETE FROM Logs' -Execute)
            Invoke-Sqlite 'VACUUM' -Execute | Out-Null
            Write-Log ("Da xoa {0} dong trong bang Logs + VACUUM." -f $n) 'OK'
        } catch {
            Write-Log ("Xoa bang Logs that bai: {0}" -f $_.Exception.Message) 'ERROR'
            $Script:FailCount++
        }
    }
} else {
    Write-Log 'Bang Logs: khong co du lieu Internet can xoa.' 'INFO'
}

# 6.2 file policy.*
foreach ($f in $PolicyFiles) { Remove-ItemSafe $f '(NHOM A - ket luan co Internet)' }
# 6.3 thu muc logs\ + Debug\
foreach ($d in $LogDirs) { Remove-ItemSafe $d '(NHOM A - log text)' }
# 6.4 file log text
foreach ($f in $LogFiles) { Remove-ItemSafe $f '(NHOM A - log text)' }

# --- buoc 7: xoa NHOM B
Write-Log '--- Xoa NHOM B (nen lam) ---' 'INFO'
Remove-ItemSafe (Join-Path $AgentFMC 'data\config.ini') '(NHOM B - cau hinh dong bo)'

# --- buoc 7 (tiep)
$groupB = @(
    (Join-Path $AgentFMC 'auto'),
    (Join-Path $AgentFMC '0dpm'),
    (Join-Path $AgentFMC '2109'),
    (Join-Path $AgentFMC 'rasoat')
)
foreach ($d in $groupB) { Remove-ItemSafe $d '(NHOM B - module/plugin tai ve)' }
Remove-ItemSafe (Join-Path $AgentFMC 'Blackip.txt') '(NHOM B - danh sach IP den)'

# ============================================================================
Write-Log '--- Ket qua ---' 'INFO'
$remaining = @()
foreach ($f in $PolicyFiles) { if (Test-Path $f) { $remaining += $f } }
foreach ($d in $LogDirs)   { if (Test-Path $d) { $remaining += $d } }
foreach ($f in $LogFiles)  { if (Test-Path $f) { $remaining += $f } }

# --- buoc 8: nhóm C
if ($AlsoCleanWindowsArtifacts) {
    Clear-WindowsArtifacts
} else {
    Write-Log 'Nhom C (artifact Windows) CHUA xoa. Dung -AlsoCleanWindowsArtifacts de bat.' 'INFO'
}

# --- buoc 9: xac minh
Write-Log '--- Xac minh ---' 'INFO'
$verify = Get-LogsTable
if ($Script:DryRun) {
    Write-Log 'Chay o che do THU nen bo qua buoc xac minh thuc te.' 'INFO'
} else {
    if ($verify -and $verify.Internet -gt 0) {
        Write-Log ("Kiem tra that bai: van con {0} dong type='Internet' trong bang Logs." -f $verify.Internet) 'ERROR'
        $Script:FailCount++
    } else {
        Write-Log "Kiem tra: bang Logs khong con su kien type='Internet'. OK" 'OK'
    }
    if ($remaining.Count -eq 0) {
        Write-Log 'Kiem tra: khong con file policy.* / thu muc logs. OK' 'OK'
    } else {
        Write-Log ("Kiem tra: van con {0} artifact (xem danh sach o tren)." -f $remaining.Count) 'ERROR'
        $Script:FailCount++
    }
}

Write-Log '--- Bat lai service ---' 'INFO'
if ($KeepServicesStopped) {
    Write-Log 'Dung -KeepServicesStopped: KHONG bat lai service. Hay tu bat tay sau khi vao mang quan su.' 'WARN'
} else {
    Start-MiAVServices
}

Write-Log '--- Hieu luc ---' 'INFO'
$hasNet2 = Test-Internet
$netTxt = if ($hasNet2) { 'CO Internet' } else { 'KHONG co Internet' }
$netLvl = if ($hasNet2) { 'WARN' } else { 'OK' }
Write-Log ("Trang thai Internet hien tai: {0}" -f $netTxt) $netLvl

# --- luu log script
$logFile = Join-Path $ReportRoot ("CleanLog_{0}.log" -f $stamp)
try { $Script:Log | Set-Content -Path $logFile -Encoding UTF8 } catch { }

Write-Host ''
Write-Host '===============================================================' -ForegroundColor DarkRed
Write-Host '  HOAN TAT' -ForegroundColor Green
Write-Host '===============================================================' -ForegroundColor DarkRed
Write-Host ("Bao cao CSV : {0}" -f $csvPath)
Write-Host ("Log thuc thi : {0}" -f $logFile)
Write-Host ("Sao luu     : {0}" -f $BackupRoot)
Write-Host ("Loi         : {0}" -f $Script:FailCount)
Write-Host ''
