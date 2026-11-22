# CHANGELOG — Danny ver5.7

**Ngày phát hành:** 22/11/2026
**Phiên bản trước:** `Danny-ver5.6`
**Phiên bản này:** `Danny-ver5.7` (Assembly version `5.7.0.0`)

> Trợ lý Công nghệ Thông tin — Trung tá Đoàn Danh Quyết
> Bộ Chỉ huy Quân sự tỉnh Lâm Đồng

---

## 1. Tổng quan

Danny ver5.7 bổ sung **03 tab chức năng mới** hoàn toàn bằng **C# native**
(không phụ thuộc Python, không gọi script ngoài), nâng cấp quy trình dọn dẹp
thành quy trình 4 bước chuẩn hoá, thêm cơ chế tự cập nhật KVRT có xác thực
chữ ký số, và gỡ bỏ các tab/button không còn dùng.

Toàn bộ mã nguồn mới nằm trong namespace `NetSecTool` và `NetSecTool.Forensic`.

---

## 2. ĐÃ XÓA

| # | Hạng mục | Vị trí | Ghi chú |
|---|----------|--------|---------|
| 1 | Tab **"CẤU HÌNH MẠNG"** | `Form1.cs` | Gỡ khỏi `BuildTabs()`, xóa `BuildNetTab()`, `BtnChangeIP_Click` và các control liên quan. Chức năng chẩn đoán kết nối vẫn chạy được nhờ nhập IP/Gateway trực tiếp trong tab `KIỂM TRA KẾT NỐI`. |
| 2 | Nút **"Xóa nhật ký Event Viewer"** | Tab `BẢO MẬT & TIỆN ÍCH` | Chuyển vào Bước 4 của quy trình `LÀM SẠCH PC MỘT CHẠM`. |
| 3 | Nút **"Chạy Kaspersky (KVRT)"** | Tab `BẢO MẬT & TIỆN ÍCH` | Thay bằng nút **"Kiểm tra cập nhật KVRT ngay"** + trạng thái KVRT + checkbox tự động cập nhật. |
| 4 | Nút **"Hiện File/Folder ẩn"** (vị trí cũ) | Tab `BẢO MẬT & TIỆN ÍCH` | Tách thành tab độc lập **"HIỆN FILE/FOLDER ẨN"**. |
| 5 | `LoadDrives()` + `BtnUncoverFiles_Click` | `Form1.cs` | Xóa cùng `cmbDrives` / `btnUncoverFiles` không còn tham chiếu. |

> **Lưu ý:** tệp `tools\KVRT.exe` vẫn được giữ nguyên trong gói phát hành và
> vẫn được gọi ở Bước 1/Bước 5 của quy trình dọn dẹp.

---

## 3. ĐÃ THÊM MỚI

### 3.1 Tab `HIỆN FILE/FOLDER ẨN`

| Tệp | Mô tả |
|-----|--------|
| `NetSecTool/UncoverFiles.cs` | Engine bỏ thuộc tính `Hidden` / `System` / `ReadOnly` cho file & thư mục bằng `File.SetAttributes` / `DirectoryInfo.Attributes` — **không gọi `attrib.exe`**. Duyệt cây thư mục theo BFS, **bỏ qua reparse point** (junction/symlink) để tránh vòng lặp vô hạn. Hỗ trợ chế độ dry-run. |

Giao diện: chọn ổ đĩa / thư mục, tùy chọn quét đệ quy, thanh tiến trình,
bảng log từng mục đã khôi phục.

### 3.2 Tab `SAO LƯU MÁY TÍNH`

| Tệp | Mô tả |
|-----|--------|
| `NetSecTool/BackupService.cs` | Engine sao lưu 2 phần: **(A) Ảnh hệ thống** qua Acronis CLI (`acrocmd.exe`) — bắt buộc bao gồm ESP, MSR, Recovery, phân vùng Windows và bảng phân vùng GPT/MBR; **(B) Dữ liệu người dùng** qua `robocopy.exe` với bộ tham số `/E /COPY:DAT /DCOPY:T /R:2 /W:3 /MT:8 /XJ /XD "$RECYCLE.BIN" "System Volume Information" /UNILOG+:<log>`. |

**Ràng buộc bắt buộc đã hiện thực hoá:**

- Quét ổ vật lý theo chuỗi WMI 3 tầng:
  `Win32_DiskDrive` → `Win32_LogicalDiskToPartition` → `Win32_DiskPartition`.
- Chỉ chấp nhận **ổ di động gắn ngoài ≥ 1 TB** (ngưỡng `930 GiB` = `998,211,063,680` bytes,
  tương đương ổ 1 TB thật hiển thị ~931 GiB trên Windows).
- **Tuyệt đối từ chối mọi phân vùng thuộc ổ gắn trong** (internal disk).
- Kiểm tra dung lượng trống còn lại so với tổng dung lượng cần sao lưu.
- Tự động loại trừ ổ đích khỏi danh sách ổ dữ liệu nguồn (tránh `robocopy` copy vào chính nó).
- Cấu trúc thư mục: `<O_Di_Dong>\<TenMay>_<yyyyMMdd_HHmmss>\SystemImage\` và `...\UserData\Drive_X\`.

> **Lưu ý kỹ thuật:** WMI trên Windows 10/11 **không expose property `Removable`**
> của `Win32_DiskDrive` khi refresh object theo path → truy cập trực tiếp sẽ ném
> `ManagementException("Not found")` và làm hỏng toàn bộ lần quét. Vì vậy mọi đọc
> property WMI đều đi qua helper `WmiStr` / `WmiLong` / `WmiBool` (bọc try-catch,
> trả giá trị mặc định). Phân loại "di động/gắn trong" dựa vào
> `InterfaceType` (USB/SD/MMC/FLASH) và `MediaType` (External/Removable).

### 3.3 Tab `KIỂM TRA AN TOÀN THÔNG TIN` (Forensic DFIR)

Module mới hoàn toàn: `NetSecTool/Forensic/`

| Tệp | Trách nhiệm |
|-----|-------------|
| `ForensicModels.cs` | Kiểu dữ liệu lõi: `Severity`, `IncidentCategory`, `Finding`, `Artifact`, `TimelineEvent`, `EvidenceBundle`, `RuleSet` (có `[JsonInclude]` để `System.Text.Json` serialize đầy đủ field). |
| `EvidenceCollector.cs` | Bộ thu thập **chỉ đọc**: bảng định tuyến, ARP cache, DNS cache, adapter (bao gồm card ảo/Wi-Fi/Bluetooth/RNDIS), cấu hình proxy/WinHTTP, cổng đang mở, khóa Registry `USBSTOR`/`USB`/`MountedDevices`, tiến trình & dịch vụ đang chạy, Windows Event Log, Prefetch, JumpLists, Recent LNK, `setupapi.*.log`, cơ sở dữ liệu SQLite trình duyệt. Mỗi artifact đều được tính **SHA-256**. |
| `RuleEngine.cs` | Đánh giá artifact theo bộ quy tắc regex, tính **điểm nghi ngờ 0–100**. |
| `TimelineEngine.cs` | Hợp nhất sự kiện đa nguồn theo trục thời gian chuẩn hoá, phát hiện chuỗi tương quan hành vi: `[ACCESS] → [STAGE] → [CONNECT] → [EXFIL]`. |
| `ReportWriter.cs` | Xuất `Bao-cao-dieu-tra.html`, `Bao-cao-dieu-tra.md`, `Dong-thoi-gian.csv`, `raw/evidence.json`, và **`manifest.sha256`** chống sửa đổi. |
| `ForensicEngine.cs` | Bộ điều phối cấp cao (`RunAsync`). |

**Bộ quy tắc cấu hình ngoài (editable):** `tools/rules/forensic-rules.json`
(15 quy tắc mặc định: truy cập Internet trái phép, đồng bộ cloud drive,
cắm USB, dàn file nén dàn dọp, công cụ nhắn tin, dấu vết anti-forensics).
Người dùng sửa file này **không cần build lại phần mềm**.

**Nguyên tắc bảo toàn chứng cứ:** tuyệt đối không sửa/ghi/xoá dữ liệu trên máy đích.

### 3.4 Nâng cấp tab `LÀM SẠCH PC MỘT CHẠM` (4 bước)

| Tệp | Mô tả |
|-----|--------|
| `NetSecTool/PcCleanerV57.cs` | Quy trình dọn dẹp 4 bước với kết quả chuẩn hoá `CheckOutcome { Pass, Warn, Fail, Skipped, Error }` + `SkipReason`. |

1. **Bước 1 — Xóa tệp rác:** `%TEMP%`, `C:\Windows\Temp`, `C:\Windows\Prefetch`,
   `C:\Windows\SoftwareDistribution\Download`. Thống kê số tệp đã xoá / bị khoá.
2. **Bước 2 — Xóa lịch sử trình duyệt:** tắt triệt để `chrome`, `msedge`,
   `browser` (Cốc Cốc), `firefox`; xoá `History`, `Cache` và `places.sqlite`.
3. **Bước 3 — Xóa sâu lịch sử USB:**
   - `ntdll!RtlAdjustPrivilege` bật `SeBackupPrivilege` (19), `SeRestorePrivilege` (18),
     `SeSecurityPrivilege` (17) qua `advapi32!AdjustTokenPrivileges`.
   - `RegistrySecurity.SetOwner` chiếm quyền sở hữu khóa Registry (`LocalSystemSid`)
     rồi cấp `FullControl` cho user hiện tại.
   - Xoá: `USBSTOR\*`, `USB\*`, `DeviceClasses\{53f56307…}`, `{53f5630d…}`,
     `{10497b1b…}`, `MountedDevices` (**loại trừ `\DosDevices\C:`**),
     `EMDMgmt`, `Portable Devices\Devices`,
     `MountPoints2` (**loại trừ `CPC`**), và `C:\Windows\inf\setupapi.*.log`.
4. **Bước 4 — Xóa sạch Event Log:** `wevtutil.exe el` lấy danh sách kênh rồi
   `wevtutil.exe cl <kênh>` cho từng kênh; xoá trực tiếp tệp `.evtx`.

### 3.5 Tự động cập nhật Kaspersky KVRT

| Tệp | Mô tả |
|-----|--------|
| `NetSecTool/KvrtUpdater.cs` | Kiểm tra Internet bất đồng bộ (`IsOnlineAsync`) — **fail-soft**, offline thì bỏ qua im lặng. Tải từ endpoint Kaspersky (fallback URL trực tiếp) về `tools\KVRT_update.tmp`, kiểm tra magic PE `MZ` (0x4D 0x5A), xác thực chứng thư X509 ký bởi **"Kaspersky Lab"**, thay thế **atomic** (backup `.bak` → ghi đè → xoá `.bak`, tự khôi phục `.bak` nếu ghi đè thất bại). |

Giao diện: hiển thị trạng thái KVRT, checkbox **tự động cập nhật khi khởi động**
(hook vào sự kiện `Shown` của form), nút **"Kiểm tra cập nhật KVRT ngay"**.

---

## 4. ĐÃ ĐIỀU CHỈNH

| Tệp | Nội dung |
|-----|----------|
| `NetSecTool/NetSecTool.csproj` | Version → `5.7.0` / `5.7.0.0`; `Product`/`AssemblyTitle` → "Danny ver5.7"; thêm liên kết `Resources\rules\forensic-rules.json` → `tools\rules\forensic-rules.json` (copy sang output & publish). |
| `NetSecTool/Form1.cs` | Thêm 3 tab mới vào `BuildTabs()`; thêm ô nhập IP/Gateway thủ công trong `tabDiag`; thay `BuildCleanOptionsPanel()` + `BtnCleanNow_Click()` bằng quy trình 4 bước `PcCleanerV57`. |
| `NetSecTool/Form1.NewTabs.cs` | *(mới)* UI + event handler async cho tab `HIỆN FILE/FOLDER ẨN`. |
| `NetSecTool/Form1.BackupTab.cs` | *(mới)* UI + event handler async cho tab `SAO LƯU MÁY TÍNH`. |
| `NetSecTool/Form1.ForensicTab.cs` | *(mới)* UI + event handler async cho tab `KIỂM TRA AN TOÀN THÔNG TIN`. |
| `NetSecTool/Program.cs` | Thêm CLI headless: `--kvrt-update`, `--uncover "<path>" [--no-recursive] [--dry-run]`, `--backup --target <X:> [--no-system-image] [--no-user-data] [--dry-run]`, `--forensic [--out "<path>"]`. In thêm `scan.Errors` / `scan.Rejected` khi quét ổ đĩa. |
| `build_and_publish.ps1` | *(mới)* Script đóng gói tự động (xem mục 6). |

---

## 5. CLI mới (chạy không cần GUI)

```powershell
# Cập nhật KVRT (tự kiểm tra Internet, bỏ qua nếu offline)
Danny-ver5.7.exe --kvrt-update

# Hiện file/thư mục ẩn
Danny-ver5.7.exe --uncover "D:\Data" [--no-recursive] [--dry-run]

# Sao lưu máy tính (chỉ ổ di động ≥ 1 TB mới được chấp nhận)
Danny-ver5.7.exe --backup --target I: [--no-system-image] [--no-user-data] [--dry-run]

# Điều tra chứng cứ số
Danny-ver5.7.exe --forensic [--out "C:\Bao-cao"]
```

---

## 6. Đóng gói & phát hành

Script: `build_and_publish.ps1`

```powershell
# Build + đóng gói (không push)
.\build_and_publish.ps1 -SkipPublish

# Build + đóng gói + commit/tag/push + tạo GitHub Release
.\build_and_publish.ps1 -Tag v5.7.0
```

**Sản phẩm phát hành** (thư mục `dist/Danny-ver5.7/`):

```
Danny-ver5.7/
├── Danny-ver5.7.exe            # self-contained, single-file, win-x64
├── Danny-ver5.7-nethost.exe    # framework-dependent (cần .NET 8 Desktop Runtime)
├── SHA256SUMS.txt              # hash SHA-256 mọi file trong gói
├── CHANGELOG.md
├── README.md
├── HUONG-DAN-SU-DUNG.md
└── tools/
    ├── KVRT.exe                # Kaspersky Virus Removal Tool (~116 MB)
    ├── SetupMiAV.exe           # trình cài đặt MiAV 4.1.1.2 của BTL86 (~21 MB)
    ├── RustDesk/               # rustdesk.exe + hbbs.exe/hbbr.exe (Direct IP)
    ├── rules/
    │   └── forensic-rules.json # bộ quy tắc Forensic (sửa được ngoài, không cần build lại)
    └── acronis/
        └── README.txt          # đặt acrocmd.exe vào đây để bật ảnh hệ thống
```

Ngoài ra: `dist/Danny-ver5.7.zip` (gói nén) + `dist/Danny-ver5.7.zip.sha256`.

> **Lưu ý GitHub:** gói phát hành vượt giới hạn 100 MB của Git nên **không commit**
> `dist/` vào git (đã thêm vào `.gitignore`). Mã nguồn + `CHANGELOG.md` được push
> lên branch mới, còn gói `.zip` được đính kèm trực tiếp vào GitHub Release
> bằng `gh release create`.

---

## 7. Kết quả kiểm thử thực tế (máy đơn vị)

| Tác vụ | Kết quả |
|--------|---------|
| Build | `Build succeeded — 0 Error(s)` |
| `--backup --target F:` (ổ 2 TB **gắn trong**) | ✅ Bị **từ chối đúng thiết kế**: "Ổ GẮN TRONG — Tuyệt đối không cho phép lưu bản sao lưu vào ổ cứng nội bộ" |
| `--backup --target I:` (Samsung S2 Portable 1 TB, USB) | ✅ Chấp nhận, tạo lệnh `robocopy` đúng tham số, dry-run **không** ghi thư mục thật lên USB |
| Ánh xạ WMI ổ → phân vùng | ✅ 8/8 ổ vật lý nhận diện đúng (C,D,E,F,G,H,I + Virtual Disk) |
| `--uncover "D:\_UncoverTest"` | ✅ 3/3 mục (2 thư mục + 1 file) gỡ thuộc tính Hidden/System, 0 lỗi |
| `--forensic` | ✅ Thu thập **874 artifact**, **14 finding** từ rule engine, **888 sự kiện** timeline, điểm nghi ngờ **91/100 (HIGH)**, xuất đủ HTML + MD + CSV + JSON + `manifest.sha256` |

---

## 8. Ghi chú kỹ thuật / hạn chế

- **Acronis CLI không được đóng gói** vì bản quyền. Người dùng phải tự tải
  `acrocmd.exe` và đặt vào `tools\acronis\` (hoặc cài Acronis True Image rồi
  chọn đường dẫn engine trong giao diện). Không có engine → chỉ chạy được
  phần dữ liệu người dùng qua robocopy.
- **Bước 3 dọn dẹp** cần `SeBackupPrivilege` / `SeRestorePrivilege` /
  `SeSecurityPrivilege`; phần mềm đã yêu cầu chạy với quyền Administrator
  (`app.manifest` → `requireAdministrator`).
- **Các khóa Registry được bảo vệ** có thể không xoá được dù đã chiếm quyền sở hữu —
  kết quả được báo cáo rõ ràng qua `CheckOutcome.Warn` / `SkipReason` thay vì báo lỗi chung chung.
- **Chế độ Forensic chỉ đọc**: mất volatile data (kết nối đang mở, tiến trình tạm)
  nếu máy đã tắt; file đã xoá vĩnh viễn không khôi phục được; dữ liệu mã hoá
  đầu-cuối không đọc được.

---

## 9. Danh sách tệp đã thêm / sửa / xoá

### Thêm mới
```
NetSecTool/BackupService.cs
NetSecTool/UncoverFiles.cs
NetSecTool/PcCleanerV57.cs
NetSecTool/KvrtUpdater.cs
NetSecTool/Form1.NewTabs.cs
NetSecTool/Form1.BackupTab.cs
NetSecTool/Form1.ForensicTab.cs
NetSecTool/Forensic/ForensicModels.cs
NetSecTool/Forensic/EvidenceCollector.cs
NetSecTool/Forensic/RuleEngine.cs
NetSecTool/Forensic/TimelineEngine.cs
NetSecTool/Forensic/ReportWriter.cs
NetSecTool/Forensic/ForensicEngine.cs
NetSecTool/Resources/rules/forensic-rules.json
build_and_publish.ps1
CHANGELOG.md
```

### Sửa
```
NetSecTool/Form1.cs
NetSecTool/Program.cs
NetSecTool/NetSecTool.csproj
.gitignore
```

### Xoá (mã nguồn đã gỡ)
```
BuildNetTab()             trong Form1.cs
BtnChangeIP_Click()       trong Form1.cs
BuildCleanOptionsPanel()  trong Form1.cs (thay bằng PcCleanerV57)
BtnCleanNow_Click()       trong Form1.cs (thay bằng PcCleanerV57)
LoadDrives()              trong Form1.cs
BtnUncoverFiles_Click()   trong Form1.cs
```

---

*Hết CHANGELOG — Danny ver5.7*
