# DANNY ver5.0 — Hướng dẫn sử dụng

**Trợ lý Công nghệ thông tin**
Phần mềm được viết bởi **Trung tá Đoàn Danh Quyết** — Trợ lý Công nghệ thông tin — Cellphone: 0366.714.139

---

## 0. Nội dung mới của bản 5.0

| # | Thay đổi | Chi tiết |
|---|---|---|
| 1 | **Bước cuối: cài đặt lại phần mềm MiAV** | Sau khi quét KVRT xong, phần mềm tự chạy `SetupMiAV.exe /VERYSILENT` để tạo lại 4 service giám sát (MiAVWD / MiAVUpdate / MiAVProtect / Defense) — máy tính trở lại đạt chuẩn cài đặt bắt buộc của BTL86 |
| 2 | **`tools\SetupMiAV.exe` đi kèm bộ cài** | Trình cài đặt MiAV 4.1.1.2 (BTL86), đặt cùng thư mục `tools\` với `KVRT.exe` |
| 3 | **Xác minh sau khi cài** | Phần mềm kiểm tra tự động 4 service đã được tạo; ghi kết quả vào báo cáo CSV |
| 4 | **Nhật ký cài đặt Inno Setup** | Lưu tại `C:\_Danny_Cleanup\<thời điểm>\SetupMiAV_install.log` để điều tra khi cài lỗi |
| 5 | **Cờ CLI mới** | `--no-install-miav` để bỏ qua bước cài lại MiAV |
| 6 | **Thứ tự quy trình đầy đủ** | Làm sạch → Quét KVRT → **Cài lại MiAV** → Khởi động lại máy |

> Bản 5.0 kế thừa toàn bộ tính năng của bản 4.0 (5 tab chức năng + tab "Làm sạch PC một chạm").

---

## 1. Cấu trúc bộ cài đặt

```
Danny-ver5.0/
├── Danny-ver5.0.exe            69,15 MB  ← bản khuyến nghị (chạy được mọi máy)
├── Danny-ver5.0-nethost.exe     1,36 MB  ← bản nhẹ (cần .NET 8 Desktop Runtime)
├── tools\
│   ├── KVRT.exe               116,28 MB  ← Kaspersky Virus Removal Tool
│   └── SetupMiAV.exe           21,20 MB  ← trình cài đặt MiAV (BTL86)
└── HUONG-DAN-SU-DUNG.md
```

> **Bắt buộc:** giữ nguyên thư mục `tools\` cạnh file `.exe`.
> Cả hai chức năng đều báo rõ ràng nếu không tìm thấy file tương ứng.

| File | Dùng khi nào |
|---|---|
| **Danny-ver5.0.exe** | Máy chưa cài .NET — **khuyến nghị dùng bản này** |
| Danny-ver5.0-nethost.exe | Máy đã có .NET 8 Desktop Runtime (khởi động nhanh hơn ~1 giây) |

---

## 2. Yêu cầu hệ thống

- Windows 10 / Windows 11 (32-bit hoặc 64-bit)
- **Quyền Administrator** — phần mềm tự yêu cầu (biểu tượng UAC)
- Dung lượng trống tối thiểu: ~300 MB (Kaspersky 116 MB + SetupMiAV 21 MB + bản sao lưu)
- Máy **nên ngắt Internet** trước khi làm sạch (xem mục 4)

---

## 3. Mở phần mềm

Nhấp đúp `Danny-ver5.0.exe` → chấp thuận quyền Administrator → phần mềm hiện 6 tab:

| # | Tab | Chức năng |
|---|---|---|
| 1 | **KIỂM TRA KẾT NỐI** | Chẩn đoán 4 bước, tra cứu 130 đơn vị, xuất báo cáo |
| 2 | **USB AN TOÀN 2.6** | Tạo USB an toàn cho MiAV (không bị chặn ở tầng kernel) |
| 3 | **CẤU HÌNH IP MỘT CHẠM** | Đặt IP tĩnh LAN đúng dải đơn vị, có rollback |
| 4 | **CẤU HÌNH MẠNG** | Cấu hình IP/DNS thủ công |
| 5 | **LÀM SẠCH PC MỘT CHẠM** | **Quy trình vệ sinh tự động + quét virus + cài lại MiAV** |
| 6 | **BẢO MẬT & TIỆN ÍCH** | Chạy KVRT thủ công, xóa Event Viewer, hiện file ẩn |

---

## 4. TAB “LÀM SẠCH PC MỘT CHẠM”

### 4.1. Quy trình đầy đủ (13 bước)

```
BƯỚC 1   Kiểm tra trạng thái Internet (ping 8.8.8.8)
BƯỚC 2   Kiểm kê hiện trạng — đếm dòng Logs type='Internet' và time_sent
BƯỚC 3   Sao lưu toàn bộ C:\Users\Public\Documents\AgentFMC
BƯỚC 4   Dừng + tạm khóa 4 service MiAV
BƯỚC 5   Dừng tiến trình GUI (MiAV.exe, MiAV_Protect.exe, …)
BƯỚC 6   Xóa NHÓM A — bảng Logs, logs\, Debug\, log.txt, policy.*, syslog.ini
BƯỚC 7   Xóa NHÓM B — config.ini, auto\, 0dpm\, 2109\, rasoat\, Blackip.txt, bảng LocalFiles
BƯỚC 8   Xóa NHÓM C — lịch sử trình duyệt, SRUM, DNS, Prefetch, Amcache, RunMRU, Jump List, Event Log
BƯỚC 9   Xác minh — Logs không còn 'Internet', không còn policy.*
BƯỚC 10  Bật lại 4 service (start= auto)
BƯỚC 11  Chạy Kaspersky KVRT — quét toàn bộ ổ + tự khử nhiễm
BƯỚC 12  ★ Cài đặt lại phần mềm MiAV (BTL86) — MỚI Ở BẢN 5.0
BƯỚC 13  Lập báo cáo CSV + đề nghị xóa dữ liệu phía server FMS
         → Khởi động lại máy
```

### 4.2. Bước 12 — Cài đặt lại MiAV (chi tiết)

Trình cài đặt `SetupMiAV.exe` là **Inno Setup 6.6.1 (Unicode)**. Danny gọi nó với dòng lệnh:

```
SetupMiAV.exe /VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART /LANG=english /LOG="<đường dẫn log>"
```

| Tham số | Tác dụng |
|---|---|
| `/VERYSILENT` | Cài đặt không tương tác, không hiện cửa sổ |
| `/SUPPRESSMSGBOXES` | Bỏ qua mọi hộp thoại nhắc |
| `/SP-` | Bỏ qua hộp thoại “This will install…” |
| `/NORESTART` | Không tự khởi động lại — Danny sẽ reboot ở bước cuối |
| `/LANG=english` | Bỏ qua hộp chọn ngôn ngữ (`ShowLanguageDialog=yes`) |
| `/LOG="..."` | Ghi nhật ký cài đặt để điều tra |

Trước khi chạy trình cài đặt, Danny thực hiện:

1. **Dừng tiến trình** `MiAV.exe`, `MiAV_WD.exe`, `MiAV_Protect.exe`, `MiAV_Update.exe`, `SerDefense.exe`, `MiAV_Listdlls.exe` — tránh lỗi “file đang được sử dụng” (tương ứng `BeforeInstall: TaskKill` trong `install_script.iss`).
2. **Gỡ service cũ**: `UpdateServices`, `FMCAgent` (bị `sc delete` trong `[Run]`), cùng 4 service chính — để trình cài đặt tạo lại sạch.
3. **Chạy trình cài đặt** và chờ tối đa 30 phút.
4. **Xác minh**: kiểm tra 4 service `MiAVWD`, `MiAVUpdate`, `MiAVProtect`, `Defense` đã được tạo. Nếu đủ 4/4 → báo **thành công**.

Thư mục cài đặt kết quả: `C:\Users\Public\Documents\AgentFMC\`
(đúng như `{commondocs}\AgentFMC` trong `install_script.iss`)

### 4.3. Các hạng mục có thể chọn

| Nhóm | Hạng mục | Tác động |
|---|---|---|
| **A — MiAV (bắt buộc)** | Xóa log MiAV | Quyết định kết luận “máy đã từng nối Internet” của MiAV |
| **B — Artifact MiAV** | (đã gộp vào nhóm A) | `config.ini`, module tải về, `Blackip.txt`, bảng `LocalFiles` |
| **C — Artifact Windows** | Lịch sử trình duyệt | Không ảnh hưởng kết luận của MiAV — dùng để giảm bề mặt đối chiếu |
| | SRUM (`SRUDB.dat`) | |
| | DNS cache + ARP | |
| | Prefetch | |
| | Amcache | |
| | RunMRU / TypedPaths | |
| | Jump List | |
| | Windows Event Log | |
| **D — Quét virus** | Kaspersky KVRT | Quét toàn bộ ổ đĩa + phân vùng boot, tự khử nhiễm |
| **E — Cài đặt lại** | **Cài lại phần mềm MiAV (BTL86)** | **Tạo lại 4 service giám sát bắt buộc** |
| | Khởi động lại sau khi quét | |

### 4.4. Cách dùng

1. **Ngắt Internet** (rút cáp WAN / tắt adapter Internet) — bước này rất quan trọng.
2. Mở tab **LÀM SẠCH PC MỘT CHẠM**.
3. Giữ nguyên các lựa chọn mặc định (đã chọn toàn bộ).
4. Nhấn **BẮT ĐẦU LÀM SẠCH** → xác nhận.
5. Theo dõi tiến trình trên khung nhật ký (mỗi bước có số thứ tự và kết quả ✓/✗).
6. Chờ KVRT quét xong (có thể **30–120 phút** tuỳ ổ đĩa).
7. Chờ bước cài lại MiAV (1–5 phút).
8. Chọn **Khởi động lại máy** khi được hỏi.

> Nhấn **DỪNG** để dừng giữa chừng — hạng mục đang chạy sẽ hoàn tất rồi mới dừng.

### 4.5. Đọc kết quả

| Ký hiệu | Ý nghĩa |
|---|---|
| `[ OK ]` | Thực hiện thành công |
| `[CẢNH BÁO]` | Không tồn tại / không áp dụng — thường là bình thường |
| `[ LỖI ]` | Thất bại — xem thông báo chi tiết |

Các cảnh báo quan trọng cần chú ý:

- **“Máy ĐANG có Internet”** → nên ngắt Internet rồi chạy lại, nếu không MiAV sẽ tự tạo lại `policy.*` và ghi sự kiện Plug-in mới ngay lập.
- **“N dòng ‘Internet’ đã gửi lên server FMS”** → dữ liệu **đã thoát khỏi máy**, xóa cục bộ không thu hồi được. Cần đề nghị quản trị viên server FMS/BTL86 xóa phía server.
- **“Cài đặt MiAV không hoàn tất: mới tạo được N/4 service”** → xem `SetupMiAV_install.log` trong thư mục làm sạch.

### 4.6. Vị trí bản sao lưu & báo cáo

```
C:\_Danny_Cleanup\20261102_115030\
├── AgentFMC\                 ← bản sao lưu toàn bộ thư mục MiAV
├── KVRT_Data\                ← thư mục quarantine + báo cáo của Kaspersky
├── SetupMiAV_install.log     ← nhật ký cài đặt MiAV (Inno Setup)
└── BaoCao\
    └── BaoCao_LamSach.csv    ← báo cáo tổng hợp kết quả
```

---

## 5. Chế độ CLI (tự động hoá)

```cmd
:: Làm sạch đầy đủ (xóa log → quét KVRT → cài lại MiAV)
Danny-ver5.0.exe --clean

:: Bỏ qua bước cài lại MiAV
Danny-ver5.0.exe --clean --no-install-miav

:: Chỉ làm sạch log MiAV, bỏ qua quét virus
Danny-ver5.0.exe --clean --no-kvrt

:: Bỏ qua nhóm C (artifact Windows)
Danny-ver5.0.exe --clean --no-kvrt --no-browser --no-srum --no-dns ^
                  --no-prefetch --no-amcache --no-runmru --no-jumplist --no-eventlog

:: Khởi động lại máy sau khi quét
Danny-ver5.0.exe --clean --reboot
```

| Lệnh | Chức năng |
|---|---|
| `--make-safe "J:\"` | Tạo USB An Toàn 2.6 |
| `--check "J:\"` | Kiểm tra trạng thái USB an toàn |
| `--diag [--full]` | Kiểm tra kết nối mạng (4 bước chẩn đoán) |
| `--clean` | **Làm sạch PC một chạm** |

---

## 6. Lưu ý quan trọng

1. **Xóa log cục bộ không thu hồi được dữ liệu đã gửi lên server FMS.**
   Cột `time_sent` cho biết dữ liệu nào đã thoát khỏi máy. Với những dòng đó,
   phải đề nghị quản trị viên FMS/BTL86 xử lý phía server.

2. **Không xóa driver/kernel của MiAV** (CBFSFilter, …) — không liên quan lịch sử
   Internet, xóa có thể phá vỡ tính năng USB an toàn mà đơn vị đang dùng.
   Việc cài lại MiAV ở bước 12 sẽ tái tạo đầy đủ driver này.

3. **Nên ngắt Internet trước khi chạy** và chỉ bật lại service khi máy đã ổn định trong LAN.

4. **Sao lưu luôn được tạo trước khi xóa** — có thể rollback từ `C:\_Danny_Cleanup\`.

5. **KVRT cần quét cả phân vùng boot** — nếu lây lan trong MBR/boot sector, chỉ quét
   phân vùng hệ điều hành sẽ không phát hiện được.

6. **Bước cài lại MiAV là bắt buộc về mặt quy trình vận hành**: sau khi làm sạch,
   máy tính phải có đủ 4 service giám sát để đáp ứng quy định cài đặt phần mềm
   bắt buộc của BTL86.

---

## 7. Xử lý sự cố

| Hiện tượng | Nguyên nhân | Cách xử lý |
|---|---|---|
| “Không tìm thấy file KVRT.exe” | Thiếu thư mục `tools\` | Copy đủ thư mục `tools\` sang cạnh file `.exe` |
| “Không tìm thấy SetupMiAV.exe” | Thiếu thư mục `tools\` | Như trên — file phải nằm trong `tools\` |
| “Cài đặt MiAV không hoàn tất: 2/4 service” | Trình cài đặt bị chặn (UAC, AV, service cũ còn khoá) | Mở `SetupMiAV_install.log`; chạy `SetupMiAV.exe` thủ công với quyền Admin |
| “Dịch vụ không tồn tại” khi dừng MiAV | Máy không cài MiAV | Bỏ qua — hiển thị `[CẢNH BÁO]`, không phải lỗi |
| Không xóa được `Amcache.hve` / `SRUDB.dat` | Tệp bị TrustedInstaller/SYSTEM giữ khoá | Phần mềm tự chạy Scheduled Task với quyền SYSTEM; nếu vẫn lỗi, khởi động lại Safe Mode rồi chạy lại |
| KVRT chạy lâu | Quét sâu toàn bộ ổ đĩa | Bình thường, có thể 30–120 phút. Không được tắt |
| “Cần .NET 8 Desktop Runtime” | Bản nethost | Dùng `Danny-ver5.0.exe` (bản self-contained) |
| Báo “vẫn còn dòng Internet” sau khi làm sạch | MiAV đã bật lại và ghi lại (do còn Internet) | Ngắt Internet, chạy lại lần 2 |

---

## 8. Thông tin phiên bản

| Mục | Giá trị |
|---|---|
| Tên | Danny |
| Phiên bản | 5.0.0 |
| Tác giả | Trung tá Đoàn Danh Quyết |
| Liên hệ | 0366.714.139 |
| Đơn vị | Bộ Chỉ huy Quân sự tỉnh Lâm Đồng |
| Nền tảng | .NET 8 / Windows Forms |
| Yêu cầu quyền | Administrator (manifest) |

---

*Tham chiếu kỹ thuật: `Phan tich MiAV/BAO-CAO-PHAN-TICH-MIAV.md` — Mục 6 (Ma trận artifact)
và Mục 7 (Quy trình & script làm sạch log). Tham số dòng lệnh KVRT được xác minh từ
bảng “KVRT2020 — Command line arguments help” trong `tools\KVRT.exe`; tham số cài đặt
MiAV được xác minh từ `install_script.iss` trích từ `tools\SetupMiAV.exe` bằng `innounp`.*
