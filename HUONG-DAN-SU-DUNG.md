# DANNY ver5.7 — Hướng dẫn sử dụng

**Trợ lý Công nghệ thông tin**
Phần mềm được viết bởi **Trung tá Đoàn Danh Quyết** — Trợ lý Công nghệ thông tin — Cellphone: 0366.714.139

---

## 0. Nội dung mới của bản 5.7

| # | Thay đổi | Chi tiết |
|---|----------|---------|
| 1 | **Tab mới `KIỂM TRA AN TOÀN THÔNG TIN`** | Module **Forensic DFIR** viết bằng C# native: thu thập chứng cứ **chỉ đọc**, rule engine, timeline tương quan, báo cáo HTML/MD/CSV/JSON + `manifest.sha256` |
| 2 | **Tab mới `SAO LƯU MÁY TÍNH`** | Ảnh hệ thống (Acronis CLI) + dữ liệu người dùng (robocopy). **Chỉ chấp nhận ổ di động gắn ngoài ≥ 1 TB** |
| 3 | **Tab mới `HIỆN FILE/FOLDER ẨN`** | Tách từ tab `BẢO MẬT & TIỆN ÍCH`. Bỏ thuộc tính ẩn bằng API .NET, **không gọi `attrib.exe`** |
| 4 | **Dọn dẹp PC 4 bước chuẩn hoá** | Tạm, trình duyệt, USB sâu, Event Log — kết quả chuẩn hoá `Pass/Warn/Fail/Skipped/Error` + lý do bỏ qua |
| 5 | **Tự động cập nhật Kaspersky KVRT** | Kiểm tra Internet nền, xác thực chữ ký số **"Kaspersky Lab"**, thay thế atomic (`.bak` rollback) |
| 6 | **Xoá tab `CẤU HÌNH MẠNG`** | Chức năng chẩn đoán vẫn chạy được — nhập IP/Gateway trực tiếp trong tab `KIỂM TRA KẾT NỐI` |
| 7 | **CLI headless** | `--kvrt-update`, `--uncover`, `--backup`, `--forensic` — chạy tự động, không hiện hộp thoại |
| 8 | **Bộ quy tắc Forensic sửa ngoài** | `tools\rules\forensic-rules.json` — **sửa file là có hiệu lực, không cần build lại** |

---

## 1. Cấu trúc bộ cài đặt

```
Danny-ver5.7/
├── Danny-ver5.7.exe            ~72 MB   ← bản khuyến nghị (chạy được mọi máy)
├── Danny-ver5.7-nethost.exe    ~1,4 MB  ← bản nhẹ (cần .NET 8 Desktop Runtime)
├── tools\
│   ├── KVRT.exe               116,28 MB  ← Kaspersky Virus Removal Tool
│   ├── SetupMiAV.exe           21,20 MB  ← trình cài đặt MiAV 4.1.1.2 (BTL86)
│   ├── RustDesk\                          ← bộ công cụ hỗ trợ từ xa
│   │   ├── rustdesk.exe            25,02 MB  ← RustDesk client 1.5.3 (Direct IP)
│   │   └── server\
│   │       ├── hbbs.exe             6,77 MB  ← ID server (tuỳ chọn)
│   │       ├── hbbr.exe             2,77 MB  ← Relay server (tuỳ chọn)
│   │       └── rustdesk-utils.exe   0,40 MB  ← sinh cặp khoá server
│   ├── rules\
│   │   └── forensic-rules.json           ← bộ quy tắc Forensic (sửa được)
│   └── acronis\
│       └── README.txt                    ← đặt acrocmd.exe vào đây
├── CHANGELOG.md
├── README.md
└── SHA256SUMS.txt
```

> **Bắt buộc:** giữ nguyên thư mục `tools\` cạnh file `.exe`.

| File | Dùng khi nào |
|---|---|
| **Danny-ver5.7.exe** | Máy chưa cài .NET — **khuyến nghị dùng bản này** |
| Danny-ver5.7-nethost.exe | Máy đã có .NET 8 Desktop Runtime (khởi động nhanh hơn ~1 giây) |

---

## 2. Yêu cầu hệ thống

- Windows 10 / Windows 11 (32-bit hoặc 64-bit)
- **Quyền Administrator** — phần mềm tự yêu cầu (biểu tượng UAC)
- Hai máy hỗ trợ từ xa phải **cùng nằm trong một mạng LAN**
- Dung lượng trống tối thiểu: ~250 MB (Kaspersky 116 MB + MiAV 21 MB + RustDesk 25 MB + phần mềm)

---

## 3. Danh sách tab

| # | Tab | Nội dung |
|---|---|---|
| 1 | `KIỂM TRA KẾT NỐI` | Chẩn đoán mạng LAN/WAN, tra cứu đơn vị theo tên (có dấu/không dấu) |
| 2 | `CẤU HÌNH IP MỘT CHẠM` | Đặt IP tĩnh theo dải được cấp, tìm đơn vị bằng tên |
| 3 | `TẠO USB AN TOÀN` | Tạo USB 2.6 (NTFS + `inf.bin` hợp lệ), thư mục `DATA` ghi được nhưng không chạy được `.exe` |
| 4 | `LÀM SẠCH PC MỘT CHẠM` | **4 bước** — Tạm → Trình duyệt → USB sâu → Event Log |
| 5 | `HỖ TRỢ KỸ THUẬT TỪ XA` | RustDesk Direct IP (cổng 21118, whitelist CIDR) |
| 6 | `BẢO MẬT & TIỆN ÍCH` | Trạng thái KVRT, tự cập nhật, công cụ phụ |
| 7 | `HIỆN FILE/FOLDER ẨN` | **Mới** — gỡ thuộc tính ẩn / system / read-only |
| 8 | `SAO LƯU MÁY TÍNH` | **Mới** — ảnh hệ thống + dữ liệu người dùng |
| 9 | `KIỂM TRA AN TOÀN THÔNG TIN` | **Mới** — Forensic DFIR |

---

## 4. Tab `LÀM SẠCH PC MỘT CHẠM` — quy trình 4 bước

**Yêu cầu:** chạy bằng quyền Administrator. Thao tác **không thể hoàn tác**.

### Bước 1 — Xóa tệp rác
`%TEMP%` · `C:\Windows\Temp` · `C:\Windows\Prefetch` · `C:\Windows\SoftwareDistribution\Download`
→ thống kê số tệp đã xoá và số tệp bị tiến trình khác khoá (bỏ qua, không dừng).

### Bước 2 — Xóa lịch sử trình duyệt
- Tắt triệt để: `chrome`, `msedge`, `browser` (Cốc Cốc), `firefox`
- Xoá `History`, `Cache` (Chrome/Edge/Cốc Cốc), `places.sqlite` (Firefox)

### Bước 3 — Xóa sâu lịch sử USB
- Bật đặc quyền `SeBackupPrivilege` (19), `SeRestorePrivilege` (18), `SeSecurityPrivilege` (17)
- Chiếm quyền sở hữu khóa Registry rồi xoá:
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\*`
  - `HKLM\SYSTEM\CurrentControlSet\Enum\USB\*`
  - `HKLM\SYSTEM\CurrentControlSet\Control\DeviceClasses\{53f56307…}`, `{53f5630d…}`, `{10497b1b…}`
  - `HKLM\SYSTEM\MountedDevices` — **loại trừ `\DosDevices\C:`** (không được làm lỗi khởi động)
  - `HKLM\SYSTEM\CurrentControlSet\Enum\EMDMgmt`
  - `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`
  - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` — **loại trừ `CPC`**
- Xoá `C:\Windows\inf\setupapi.*.log`

### Bước 4 — Xóa sạch Event Log
`wevtutil.exe el` (liệt kê kênh) → `wevtutil.exe cl <kênh>` cho từng kênh → xoá trực tiếp tệp `.evtx`.

### Sau khi dọn
Quét toàn bộ ổ cục bộ + phân vùng boot bằng `tools\KVRT.exe`, tự động `Disinfected`, cài lại
`tools\SetupMiAV.exe` (tạo lại 4 service MiAV), khởi động lại máy.

> **Kết quả mỗi tách vụ** hiển thị theo chuẩn:
> `✔ Pass` · `⚠ Warn` · `✖ Fail` · `⏭ Skipped (lý do)` · `⚠ Error`.

---

## 5. Tab `SAO LƯU MÁY TÍNH`

### Ràng buộc bắt buộc

| Điều kiện | Giá trị |
|---|---|
| Loại ổ đích | **Chỉ ổ di động gắn ngoài** (USB / External) |
| Dung lượng tối thiểu | **1 TB** — ngưỡng kiểm tra `930 GiB` (= `998.211.063.680` bytes) vì ổ 1 TB thật hiển thị ~931 GiB trên Windows |
| Ổ gắn trong (internal) | **Tuyệt đối từ chối** — hiển thị cảnh báo đỏ |
| Kiểm tra thêm | Dung lượng trống còn lại vs. tổng dung lượng cần sao lưu |

> Phần mềm quét ổ vật lý qua chuỗi WMI 3 tầng:
> `Win32_DiskDrive` → `Win32_LogicalDiskToPartition` → `Win32_DiskPartition`.

### Bước A — Ảnh hệ thống (Acronis)

Bắt buộc bao gồm: **EFI System Partition (ESP)**, **MSR**, **Recovery**, phân vùng
Windows (`C:\`) và **bảng phân vùng GPT/MBR** — để khôi phục được trên ổ cứng mới.

**Cần chuẩn bị engine Acronis:**
1. Tải `acrocmd.exe` từ <https://www.acronis.com/en-us/support/download>
2. Đặt vào `tools\acronis\` cạnh phần mềm
3. Hoặc cài Acronis True Image rồi chọn đường dẫn engine trong giao diện

> Không có engine → phần này báo lỗi rõ ràng, phần dữ liệu người dùng vẫn chạy bình thường.

### Bước B — Dữ liệu người dùng (robocopy)

Tự động phát hiện ổ dữ liệu gắn trong (`D:\`, `E:\`…), **loại trừ `C:\` và ổ đích**.
Lệnh sinh ra:

```
robocopy "D:" "<O_Đích>\<TenMay>_<yyyyMMdd_HHmmss>\UserData\Drive_D" /E /COPY:DAT /DCOPY:T /R:2 /W:3 /MT:8 /XJ /XD "$RECYCLE.BIN" "System Volume Information" /UNILOG+:"<...>\robocopy_D.log" /NFL /NDL /NP
```

Cấu trúc thư mục:

```
<O_Đích>\<TenMay>_<yyyyMMdd_HHmmss>\
├── SystemImage\          ← ảnh hệ thống (Acronis)
└── UserData\
    ├── Drive_D\          ← dữ liệu ổ D
    ├── Drive_E\
    └── robocopy_D.log    ← nhật ký từng lệnh
```

### Chạy thử không ghi thật

Để kiểm tra cấu hình mà không ghi dữ liệu, dùng CLI:

```powershell
Danny-ver5.7.exe --backup --target I: --dry-run
```

---

## 6. Tab `KIỂM TRA AN TOÀN THÔNG TIN` (Forensic DFIR)

> **Nguyên tắc bất di bất dịch:** chế độ **chỉ đọc** — không sửa, không ghi đè, không xoá
> dữ liệu nào trên máy đích.

### 6.1 Bộ thu thập chứng cứ

| Nhóm | Nội dung |
|---|---|
| **Mạng & kết nối** | Bảng định tuyến, ARP cache, DNS cache, danh sách adapter (card ảo, Wi-Fi, Bluetooth, RNDIS/USB tethering), proxy/PAC/WinHTTP, cổng đang mở, khóa Registry `USBSTOR`/`USB`/`MountedDevices` |
| **Dấu vết truy cập & lộ lọt** | Prefetch, JumpLists, Recent LNK, `setupapi.*.log`, cơ sở dữ liệu SQLite trình duyật (Chrome/Edge/Firefox), dấu vết nén (`7z`, `rar`, `zip`, `tar`), thư mục staging |
| **Hệ thống & tiến trình** | Tiến trình đang chạy, dịch vụ, Windows Event Log |

Mỗi artifact đều được tính **SHA-256** và ghi vào `manifest.sha256` chống sửa đổi.

### 6.2 Rule Engine & điểm nghi ngờ

Bộ quy tắc nằm ở **`tools\rules\forensic-rules.json`** — 15 quy tắc mặc định:

| Nhóm | Ví dụ quy tắc |
|---|---|
| Internet trái phép | Proxy lạ, DNS ngoài vùng, tunnel/remote tool |
| Lộ lọt tài liệu | Cloud drive sync, FTP/SFTP, công cụ chat, nén file dàn dọp |
| Thiết bị lưu trữ | Cắm USB, thiết bị gắn ngoài lạ |
| Anti-forensics | Xoá log, xoá lịch sử trình duyệt, dọn Prefetch |

> **Sửa file này là có hiệu lực ngay** — không cần build lại phần mềm.

**Cấu trúc một quy tắc:**

```json
{
  "id": "CLOUD-DRIVE-SYNC",
  "name": "Đồng bộ tài liệu lên cloud drive",
  "category": "Exfiltration",
  "severity": "High",
  "score": 12,
  "patterns": ["(?i)onedrive", "(?i)dropbox", "(?i)google drive"],
  "description": "Phát hiện dấu vết thư mục đồng bộ cloud drive"
}
```

**Điểm nghi ngờ (0–100):**

| Điểm | Mức | Hành động |
|---|---|---|
| 0–24 | THẤP | Ghi nhận, tiếp tục theo dõi |
| 25–49 | TRUNG BÌNH | Rà soát chi tiết |
| 50–74 | CAO | Cần điều tra |
| 75–100 | **RẤT CAO** | Cô lập máy ngay |

### 6.3 Timeline & tương quan

Dòng thời gian chuẩn hoá (UTC + giờ máy) hợp nhất mọi nguồn, tự động làm nổi bật chuỗi hành vi:

```
[ACCESS] Truy cập tài liệu nhạy cảm
   ↓
[STAGE]  Đóng gói / nén / dàn dọp
   ↓
[CONNECT]Thiết lập kết nối ra ngoài
   ↓
[EXFIL]  Truyền dữ liệu đi
```

### 6.4 Sản phẩm báo cáo

```
Bao-cao-dieu-tra/
├── Bao-cao-dieu-tra.html      ← báo cáo đầy đủ (mở bằng trình duyệt)
├── Bao-cao-dieu-tra.md        ← bản Markdown
├── Dong-thoi-gian.csv         ← dòng thời gian (mở bằng Excel)
├── manifest.sha256            ← hash SHA-256 mọi artifact
└── raw/
    └── evidence.json          ← dữ liệu gốc đầy đủ
```

### 6.5 Chạy thử

```powershell
Danny-ver5.7.exe --forensic --out "C:\Bao-cao"
```

---

## 7. Tab `HIỆN FILE/FOLDER ẨN`

1. Chọn ổ đĩa hoặc thư mục đích
2. Tích chọn **quét đệ quy** (bỏ chọn nếu chỉ muốn xử lý thư mục gốc)
3. Bấm **Bắt đầu** — tiến trình + log từng mục đã khôi phục hiển thị realtime

Thao tác gỡ thuộc tính: `Hidden`, `System`, `ReadOnly` cho cả file và thư mục.
Duyệt cây thư mục theo BFS và **bỏ qua reparse point** (junction/symlink) nên không bị lặp vô hạn.

```powershell
Danny-ver5.7.exe --uncover "D:\Data" [--no-recursive] [--dry-run]
```

---

## 8. Tự động cập nhật Kaspersky KVRT

**Trong giao diện** (tab `BẢO MẬT & TIỆN ÍCH`):
- Trạng thái KVRT hiện tại
- ☐ **Tự động cập nhật khi khởi động** (mặc định bật)
- Nút **Kiểm tra cập nhật KVRT ngay**

**Cơ chế:**
1. Kiểm tra Internet nền — **offline thì bỏ qua im lặng**, không hiện hộp thoại lỗi
2. Tải về `tools\KVRT_update.tmp`
3. Xác thực: tệp không rỗng · magic PE `MZ` (`0x4D 0x5A`) · chứng thư X509 ký bởi **"Kaspersky Lab"**
4. Thay thế **atomic**: sao lưu `.bak` → ghi đè → xoá `.bak`; ghi đè thất bại thì tự khôi phục `.bak`

```powershell
Danny-ver5.7.exe --kvrt-update
```

---

## 9. CLI tổng hợp

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

> Chế độ CLI **không hiện hộp thoại** — phù hợp chạy tự động qua script/kịch bản.

---

## 10. Kịch bản kiểm thử nhanh

| # | Tác vụ | Cách kiểm tra | Kết quả mong đợi |
|---|---|---|---|
| 1 | KVRT **online** | Bấm *Kiểm tra cập nhật KVRT ngay* | Thông báo phiên bản mới + xác thực chữ ký thành công |
| 2 | KVRT **offline** | Ngắt mạng → kiểm tra cập nhật | Bỏ qua im lặng, chỉ ghi log trạng thái offline, **không** hiện hộp thoại lỗi |
| 3 | Backup **chặn ổ gắn trong** | Chọn ổ `F:` (2 TB internal) | Báo đỏ "Ổ GẮN TRONG — Tuyệt đối không cho phép lưu vào ổ nội bộ" |
| 4 | Backup **chặn ổ < 1 TB** | Cắm USB 512 GB | Báo dung lượng dưới ngưỡng 1 TB, nút *Bắt đầu* bị khoá |
| 5 | Backup **chấp nhận ổ USB 1 TB** | Cắm Samsung S2 Portable → `--target I:` | "Ổ đích hợp lệ", hiện lệnh robocopy đúng tham số |
| 6 | Backup **dry-run** | `--backup --target I: --dry-run` | In lệnh, **không** tạo thư mục trên ổ đích |
| 7 | Forensic **dry-run / toàn bộ** | `--forensic --out "C:\Bao-cao"` | Đủ HTML + MD + CSV + JSON + `manifest.sha256` |
| 8 | Forensic **kiểm tra hash** | `Get-FileHash` 1 artifact, so với `manifest.sha256` | Khớp |
| 9 | Forensic **sửa rule** | Mở `tools\rules\forensic-rules.json`, thêm quy tắc, chạy lại | Quy tắc mới được áp dụng **không cần build lại** |
| 10 | Uncover | Tạo file/thư mục ẩn (`attrib +h +s`), chạy tab | Tất cả mục mất thuộc tính Hidden/System |

---

## 11. Build lại từ mã nguồn

```powershell
# Build + đóng gói (không push)
.\build_and_publish.ps1 -SkipPublish

# Build + đóng gói + commit/tag/push + tạo GitHub Release
.\build_and_publish.ps1 -Tag v5.7.0
```

Script sẽ:
1. Xoá `bin/`, `obj/`, thư mục phát hành cũ
2. `dotnet restore` + `dotnet build -c Release`
3. Publish **self-contained single-file** → `Danny-ver5.7.exe`
4. Publish **framework-dependent** → `Danny-ver5.7-nethost.exe`
5. Copy `tools/` (KVRT, SetupMiAV, RustDesk, rules, acronis) + tài liệu
6. Sinh `SHA256SUMS.txt`
7. Tạo `dist\Danny-ver5.7.zip` + `.sha256`
8. (Option) Tạo branch `release/Danny-ver5.7-<yyyyMMdd>`, commit, tag, push, `gh release create`

> **Lưu ý kích thước:** gói phát hành vượt 100 MB nên dùng **Git LFS**
> (repo đã cấu hình `*.exe` / `*.zip` qua `.gitattributes`) hoặc đính kèm
> trực tiếp trong GitHub Release bằng `gh release create`.

---

## 12. Khắc phục sự cố

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| "Không tìm thấy engine Acronis CLI" | Chưa đặt `acrocmd.exe` | Đặt vào `tools\acronis\` hoặc cài Acronis rồi chọn đường dẫn |
| "Không xác định được ổ vật lý của X:" | ổ chưa cắm / không map được | Cắm ổ rồi bấm *Làm mới* |
| "Ổ GẮN TRONG" | Chọn nhầm ổ nội bộ | Chọn ổ USB ≥ 1 TB |
| "dung lượng dưới ngưỡng 1 TB" | ổ USB nhỏ hơn 1 TB | Dùng ổ ≥ 1 TB |
| KVRT không cập nhật | Máy offline | Kiểm tra kết nối mạng rồi thử lại |
| Báo cáo Forensic rỗng | Máy không có dữ liệu phù hợp | Kiểm tra `raw/evidence.json` — vẫn có artifact thô |
| Tab không mở được | Thiếu `tools\` | Giữ nguyên cấu trúc thư mục khi sao chép |

---

*Hết tài liệu — Danny ver5.7*
