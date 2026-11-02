# BÁO CÁO PHÂN TÍCH CƠ CHẾ GIÁM SÁT & PHÁT HIỆN LỊCH SỬ KẾT NỐI INTERNET
## Phần mềm MiAV 4.1.1.2 (BTL86) — Bộ EDR/AV bắt buộc trên máy tính quân sự

| | |
|---|---|
| **Đối tượng phân tích** | `SetupMiAV.exe` (Inno Setup, AppVersion 4.1.1.2, Publisher: BTL86, Inc.) |
| **Mục đích** | Xác định chính xác cơ chế MiAV dùng để **giám sát và phát hiện máy tính quân sự có lịch sử kết nối Internet**; từ đó đề xuất quy trình làm sạch log trước khi cắm vào mạng truyền số liệu quân sự |
| **Phương pháp** | Phân tích **tĩnh 100%** (static) — giải nén payload, trích chuỗi ANSI/UTF-16LE có offset, phân tích PE metadata, dịch ngược x86 (capstone) để xác minh luồng ghi sự kiện |
| **Nguyên tắc an toàn** | **KHÔNG thực thi mẫu, KHÔNG cài đặt, KHÔNG kết nối mạng.** Mọi phát hiện đều dựa trên bằng chứng có thể tái lập |
| **Ngày phân tích** | 02/11/2026 |
| **Bộ công cụ** | `innounp` 6.6.1 · `pefile` · `capstone` · `python 3.13` |
| **Case ID** | `work/phan-tich-miav-giam-sat` |

---

## MỤC LỤC

1. [Tóm tắt điều hành](#1-tóm-tắt-điều-hành)
2. [Kiến trúc tổng thể của MiAV](#2-kiến-trúc-tổng-thể-của-miav)
3. [Cơ chế phát hiện lịch sử kết nối Internet](#3-cơ-chế-phát-hiện-lịch-sử-kết-nối-internet)
4. [Kết luận phủ định: MiAV KHÔNG đọc lịch sử trình duyệt/SRUM/DNS](#4-kết-luận-phủ-định-miav-không-đọc-lịch-sử-trình-duyệtsrumdns)
5. [Kênh truyền dữ liệu lên server FMS (C2)](#5-kênh-truyền-dữ-liệu-lên-server-fms-c2)
6. [Ma trận artifact — Cần xóa / Không cần xóa](#6-ma-trận-artifact--cần-xóa--không-cần-xóa)
7. [Quy trình & script làm sạch log đề xuất](#7-quy-trình--script-làm-sạch-log-đề-xuất)
8. [Quy trình vận hành đề xuất cho đơn vị](#8-quy-trình-vận-hành-đề-xuất-cho-đơn-vị)
9. [Giới hạn & rủi ro còn lại](#9-giới-hạn--rủi-ro-còn-lại)
10. [Phụ lục: Evidence, Findings, công cụ tái lập](#10-phụ-lục-evidence-findings-công-cụ-tái-lập)

**Sơ đồ kèm theo** (thư mục `diagram/`):

| File | Nội dung |
|---|---|
| `01-kien-truc-miav.svg` | Kiến trúc thành phần MiAV và luồng dữ liệu |
| `02-co-che-phat-hien-internet.svg` | Luồng phát hiện Internet (Plug-in / Plug-out) |
| `03-ban-do-lam-sach-log.svg` | Bản đồ artifact cần làm sạch theo mức ưu tiên |

---

## 1. TÓM TẮT ĐIỀU HÀNH

### 1.1. Kết luận cốt lõi

> **MiAV KHÔNG phát hiện "lịch sử kết nối Internet" bằng cách đọc lại các artifact lịch sử của Windows.**
> Nó **đo trạng thái kết nối tại thời điểm hiện tại**, **gom bảng kết nối TCP/UDP đang mở**, rồi **ghi thành sự kiện vĩnh viễn** vào SQLite + file text và **đẩy lên server FMS**.

Ba cơ chế duy nhất, đều đã được xác minh bằng disassembly và bằng chứng chuỗi:

| # | Cơ chế | Thành phần | Bằng chứng |
|---|---|---|---|
| **C1** | **Đo reachability bằng 6 lệnh mạng** → ghi ra 6 file `policy.*` | `MiAV.exe` | `cmd.exe /C ping 8.8.8.8`, `tracert wikipedia.org`, `tracert 27.68.131.116`, `tracert 10.152.4.2`, `netstat -nao`, `ipconfig/all` |
| **C2** | **Gom `netstat -nao`** vào trường `"connections"` của payload JSON telemetry | `MiAV_Protect.exe` | JSON `{"OS":%s,"network":%s,…,"connections":%s,…}` → `POST /api/v1/active-devices/insert` |
| **C3** | **Ghi sự kiện vĩnh viễn** `type="Internet"`, `name="Plug-in"/"Plug-out"`, `level="Alert"` vào bảng `Logs` (SQLite) + `logs\` + `log.txt`, rồi `POST /api/v1/events/insert` | `MiAV.exe` + `MiAV_Protect.exe` | Disassembly `MiAV.exe` VA `0x00981ed7` & `0x00981fa4`: `mov ecx,0x9822e8` (`"Internet"`) / `mov edx,0x982308` (`"Alert"`) → `call 0x8cc508` |

### 1.2. Hệ quả thực tế đối với bài toán "làm sạch lịch sử kết nối"

| Câu hỏi của đơn vị | Trả lời |
|---|---|
| Có cần xóa lịch sử trình duyệt (Chrome/Edge/Firefox/IE) không? | **KHÔNG bắt buộc** — MiAV không đọc chúng (F-005). Xóa là tùy chọn để giảm bề mặt đối chiếu với bộ phận khác. |
| Có cần xóa SRUM (`SRUDB.dat`), DNS cache, Prefetch, Amcache, RunMRU, Jump List không? | **KHÔNG bắt buộc** — MiAV không đọc chúng (F-005). |
| Có cần xóa lịch sử Windows Event Log (`winevt`) không? | **KHÔNG** — không có tín hiệu tham chiếu (`winevt`, `EvtClearLog`) trong 5 binary. |
| Có cần can thiệp ở tầng kernel / driver CBFSFilter không? | **KHÔNG** — driver chỉ theo dõi hành vi file/registry/process, **không** phải nguồn dữ liệu lịch sử Internet (F-004). |
| Vậy phải xóa gì? | **6 nhóm artifact cục bộ** dưới `C:\Users\Public\Documents\AgentFMC\` — chi tiết ở mục 6 & 7. |
| Xóa cục bộ có đủ không? | **KHÔNG đủ 100%.** Dữ liệu đã `POST` lên server FMS **không thu hồi được bằng thao tác cục bộ**. Phải có đề nghị chính thức tới quản trị viên FMS/BTL86 xóa lịch sử `active-devices` / `events` / `alerts` của máy đó. |

### 1.3. Điểm mấu chốt về mặt thời gian

MiAV ghi lại `policy.*` **mỗi lần chạy**. Nghĩa là:

> Nếu máy **đã từng** nối Internet, sau khi ta xóa sạch các file này, **lần khởi động lại MiAV khi máy đang NGẮT Internet** sẽ tạo ra `policy.ping`/`policy.tracertWiki` **rỗng hoặc báo lỗi** → máy **không** bị đánh dấu.

Vì vậy: **phải làm sạch khi máy đã ngắt mạng Internet**, và **phải giữ ngắt** cho tới khi nối vào mạng quân sự (chỉ có mạng LAN nội bộ, DNS `86.0.188.1`).

### 1.4. Cảnh báo về tính hợp pháp

Báo cáo này được viết theo góc nhìn **quản trị vòng đời CNTT của đơn vị** (tuân thủ chính sách an toàn thông tin, chuẩn bị máy trước khi đưa vào mạng truyền số liệu quân sự — môi trường "không Internet"). MiAV là sản phẩm **hợp pháp, do BTL86 (đơn vị trực thuộc Bộ QĐND) sản xuất**, được cài bắt buộc. Các thao tác trong mục 7 là **biện pháp quản trị vệ sinh môi trường**, không phải kỹ thuật né tránh phát hiện.

---

## 2. KIẾN TRÚC TỔNG THỂ CỦA MIAV

### 2.1. Quá trình cài đặt

`SetupMiAV.exe` là trình cài đặt **Inno Setup 6.6.1**, nén LZMA. Thông tin từ `install_script.iss`:

```ini
[Setup]
AppName=MiAV
AppVersion=4.1.1.2
AppPublisher=BTL86, Inc.
DefaultDirName={commondocs}\AgentFMC
Compression=lzma
```

Thư mục cài đặt: **`C:\Users\Public\Documents\AgentFMC\`** (`{commondocs}` → `C:\Users\Public\Documents`).

> Vị trí này là **cố ý** — nằm trong `Public\Documents` để **mọi tài khoản người dùng** đều đọc/ghi được, đồng thời nằm ngoài `%APPDATA%` nên không bị xóa khi đổi profile.

### 2.2. Các thành phần thực thi

| Tệp | Kích thước | Kiến trúc / Ngôn ngữ | Timestamp biên dịch | Vai trò |
|---|---|---|---|---|
| `MiAV.exe` | 12.436.200 | x86, Delphi (RAD Studio 10.4) | 2026-03-15 | **GUI chính** + EDR engine + **engine đo mạng** + client CBFSFilter |
| `MiAV_Protect.exe` | 32.376.096 | x86, Delphi (FireDAC) | 2025-11-10 | **Agent giám sát nền** — telemetry, `netstat`, ghi SQLite, REST client |
| `SerDefense.exe` | 10.214.632 | x86, Delphi | 2024-07-24 | Service `MiAV_Defense` — **WebSocket** + WMI adapter scanner + quản lý service |
| `MiAV_Update.exe` | 4.477.672 | x86, Delphi | 2024-07-24 | Agent đồng bộ **IOC / policy** |
| `MiAV_WD.exe` | 2.711.784 | x86, Delphi | 2024-07-24 | **Watchdog** — giám sát các service khác |
| `remove_malware.dll` | 3.113.704 | x86, Delphi | 2024-03-31 | Thư viện remediation malware |
| `cbfsfilter20.dll` | — | Driver (Callback FS Filter) | — | **Tầng kernel** — giám sát file/registry/process |
| `yara\*.yar` (7 file) + `yara32.exe` | — | — | — | Bộ luật YARA: PlugX, MustangPanda, Cobalt Strike, APT, Mimikatz, RedLine |
| `data\data.db` | 41.525.248 | SQLite | — | `Logs` / `LocalFiles` / `Hashs` (978 IOC) |
| `data\public.pem` | — | RSA public key | — | Xác minh token JWT RS256 |

### 2.3. Tự khởi động (Persistence)

**4 Windows Service**, tất cả `start= auto`:

| Tên service | DisplayName | Binary |
|---|---|---|
| `MiAVWD` | MiAV_WD | `MiAV_WD.exe` |
| `MiAVUpdate` | MiAV_Update | `MiAV_Update.exe` |
| `MiAVProtect` | MiAV_Protect | `MiAV_Protect.exe` |
| `Defense` | MiAV_Defense | `SerDefense.exe` |

**1 khóa Run cho người dùng tương tác:**

```
HKLM\Software\Microsoft\Windows\CurrentVersion\Run  →  "MiAV" = "{app}\MiAV.exe"
```

**1 driver callback ở tầng kernel** (cài bởi `InstallCallBackFilter.exe` đặt tạm ở `{tmp}`, `deleteafterinstall`):

```
cbfsfilter20.dll + cbfsfilter20_dta
GUID {713CC6CE-B3E2-4fd9-838D-E28F558F6866}
Module: CBRegistry | CBProcess | CBFile
```

### 2.4. Các endpoint mạng

| Endpoint | Bắt nguồn | Mục đích |
|---|---|---|
| `http://fms.bqp` | `MiAV.exe` | Server **FMS** (File/Management System) của BTL86 |
| `http://27.68.131.116:8080/computer/computerinfo` | `MiAV.exe` | Địa chỉ **public** của BTL → ghi `serverpublic.html` |
| `http://10.152.4.2/computer/computerinfo` | `MiAV.exe` | Địa chỉ **private nội bộ** → ghi `serverlocal.html` |
| `http://wikipedia.org` | `MiAV.exe` | **Probe kiểm tra Internet** (xem mục 3) |
| `/api/v1/active-devices/insert` | `MiAV_Protect.exe` | Gửi telemetry máy (kèm `connections`) |
| `/api/v1/events/insert` | `MiAV_Protect.exe` | Gửi sự kiện (kèm sự kiện Internet) |
| `/api/v1/alerts/insert` | `MiAV_Protect.exe` | Gửi cảnh báo (kèm `alert_url`) |
| `/api/v1/hashs/by-date` | `MiAV_Protect.exe` | Đồng bộ bộ IOC |
| WebSocket (`sgcWebSockets`) | `SerDefense.exe` | Kênh **real-time** nhận lệnh từ server |

Bảo mật đường truyền: TLS qua OpenSSL (`libeay32.dll`, `ssleay32.dll`), xác thực bằng `public.pem` + token **JWT RS256**.

### 2.5. Sơ đồ kiến trúc

Xem `diagram/01-kien-truc-miav.svg`.

---

## 3. CƠ CHẾ PHÁT HIỆN LỊCH SỬ KẾT NỐI INTERNET

### 3.1. C1 — Đo trạng thái kết nối hiện tại bằng 6 lệnh mạng (F-001)

`MiAV.exe` dựng một **bộ 6 file "policy"** bằng cách chạy lệnh shell. Bằng chứng chuỗi (offset trong `MiAV.exe`):

```
0x00580d18 W /C ipconfig/all >
0x00580d48 W \policy.info
0x00580d64 W cmd.exe
0x00580d8c W /C  ping 8.8.8.8 >
0x00580dc0 W \policy.ping
0x00580de8 W /C  netstat -nao >
0x00580e1c W \policy.net
0x00580e44 W /C tracert wikipedia.org >
0x00580e88 W \policy.tracertWiki
0x00580ebc W /C tracert 27.68.131.116 >
0x00580f00 W \policy.tracertpBTL
0x00580f34 W /C tracert 10.152.4.2 >
0x00580f70 W \policy.tracertlBTL
```

| Lệnh | File kết quả | Ý nghĩa |
|---|---|---|
| `ipconfig /all` | `policy.info` | Cấu hình IP, DNS, adapter, MAC |
| `ping 8.8.8.8` | `policy.ping` | **Đo Internet** (ICMP tới Google DNS) |
| `netstat -nao` | `policy.net` | **Bảng kết nối + PID** |
| `tracert wikipedia.org` | `policy.tracertWiki` | **Đo Internet** qua tên miền (cần DNS) |
| `tracert 27.68.131.116` | `policy.tracertpBTL` | Đo tới **IP public của BTL** |
| `tracert 10.152.4.2` | `policy.tracertlBTL` | Đo tới **IP private nội bộ BTL** |

**Điểm mấu chốt:** đây là **reachability probe tại thời điểm hiện tại**, không phải đọc lịch sử. Nhưng **kết quả được lưu vĩnh viễn trên đĩa** → trở thành "bằng chứng lịch sử".

**Điểm cần lưu ý về môi trường quân sự:** `10.152.4.2` là địa chỉ nội bộ BTL. Trong mạng quân sự (chỉ có LAN + DNS `86.0.188.1`) lệnh `tracert` này sẽ **timeout**, nhưng `tracert wikipedia.org` cũng timeout → MiAV kết luận **không có Internet**. Đây chính là trạng thái mong muốn.

### 3.2. C2 — Gom bảng kết nối TCP/UDP đang mở (F-002)

`MiAV_Protect.exe` chạy `netstat -nao` (từ `C:\windows\system32`) và đóng gói vào payload JSON:

```
0x0097f6a0 W C:\windows\system32
0x0097f6d4 W netstat -nao
0x0097f964 W {"OS": %s, "network": %s, "ram": %s, "cpu": %s, "free_drive": %s, "hot_fix": %s,
              "connections": %s, "list_softwares": %s, "list_auto_run": %s, "list_process": %s,
              "is_install_TA...
0x0097fbe8 W /api/v1/active-devices/insert
```

→ `POST` lên `/api/v1/active-devices/insert`.

Trường `"connections"` chứa: **địa chỉ đích, cổng đích, trạng thái, PID, tên tiến trình** của **mọi socket TCP/UDP đang mở**.

**Ý nghĩa:** đây là dữ liệu có giá trị cao nhất để chứng minh máy "đã từng nối Internet" — vì nó ghi lại **tên miền/địa chỉ từng kết nối** (do DNS resolver cache trong kernel cấp phép), kèm **ứng dụng nào** đã kết nối.

Bổ sung: `MiAV.exe` còn đăng ký **rule MITRE ATT&CK** phát hiện lệnh mạng đáng ngờ, ví dụ `netstat -nao |findstr` → `TA0007--T083`, và ghi blacklist vào `\Blackip.txt`.

### 3.3. C3 — Ghi sự kiện vĩnh viễn "Plug-in / Plug-out" (F-003) — **Cơ chế chính**

Đây là phát hiện quan trọng nhất, đã được **xác minh bằng disassembly**, không chỉ bằng chuỗi.

**Bằng chứng chuỗi** (`MiAV.exe`):

```
0x00581660 W {"ComputerName":%s,"FullMac":%s,"Time":%s, "description":%s}
0x005816e8 W Internet
0x00581708 W Alert
0x00581720 W "Plug-out"
```

**Bằng chứng disassembly** (địa chỉ ảo trong `MiAV.exe`, ImageBase `0x400000`):

*Chuỗi "Plug-in" (VA `0x00982242`) và "Plug-out" (VA `0x00982322`) được nạp trước, rồi lệnh ghi log được gọi với bộ nhãn:*

```x86asm
; === Nhánh "Plug-in" (máy CÓ Internet) — xref tại VA 0x00981ed7 ===
0x009812a4  mov      eax, 0x982240          ; -> "Plug-in"
0x009812a9  mov      dword ptr [ebp-0x5c], eax
0x009812b8  mov      eax, 0x982260          ; -> payload mô tả
0x009812bd  call     0x42ac74
0x009812c7  push     eax                   ; description
0x009812cb  push     eax                   ; ComputerName
0x009812cc  push     0
0x009812ce  push     3
0x009812d0  mov      eax, dword ptr [0xd1d0fc]
0x009812d5  mov      eax, dword ptr [eax]
0x009812d7  mov      ecx, 0x9822e8          ; <-- "Internet"
0x009812dc  mov      edx, 0x982308          ; <-- "Alert"
0x009812e1  call     0x8cc508               ; <-- hàm ghi sự kiện
0x009812e6  call     0x980ac8
```

*Chuỗi "Plug-out" được nạp ở nhánh còn lại (mất Internet), dùng **cùng bộ nhãn `Internet`/`Alert`**:*

```x86asm
; === Nhánh "Plug-out" (máy MẤT Internet) — xref tại VA 0x00981fa4 ===
0x00981368  mov      eax, 0x982320          ; -> "Plug-out"
0x0098136d  mov      dword ptr [ebp-0x90], eax
0x00981385  mov      eax, 0x982344          ; -> payload { "time":%s,"description":%s }
0x0098138a  call     0x42ac74
0x0098139d  mov      eax, dword ptr [0xd1d0fc]
0x009813a2  mov      eax, dword ptr [eax]
0x009813a4  mov      ecx, 0x9822e8          ; <-- "Internet"
0x009813a9  mov      edx, 0x982308          ; <-- "Alert"
0x009813ae  call     0x8cc508               ; <-- hàm ghi sự kiện
0x009813b3  mov      byte ptr [0xd05925], 0 ; <-- cờ "đã xử lý Plug-out"
```

**Cấu trúc sự kiện ghi được:**

| Trường | Giá trị |
|---|---|
| `type` | `"Internet"` |
| `name` | `"Plug-in"` (có Internet) / `"Plug-out"` (mất Internet) |
| `level` | `"Alert"` |
| `data` (Plug-in) | `{"ComputerName":%s,"FullMac":%s,"Time":%s,"description":%s}` |
| `data` (Plug-out) | `{ "time":%s,"description":%s}` |

**Nơi lưu:** bảng `Logs` của SQLite `C:\Users\Public\Documents\AgentFMC\data\data.db`:

```sql
CREATE TABLE "Logs" (
   "type"      TEXT,
   "name"      TEXT,
   "log_time"  TEXT,
   "data"      TEXT,
   "time_sent" TEXT NOT NULL,
   "level"     INTEGER,
   "id"        INTEGER PRIMARY KEY AUTOINCREMENT
);
```

> **Cột `time_sent` là mấu chốt:** nó cho biết sự kiện đó **đã được gửi lên server hay chưa**. Một sự kiện `time_sent` khác rỗng = **đã thoát khỏi máy, không thu hồi được**.

**Đồng thời** ghi ra file text:
```
C:\Users\Public\Documents\AgentFMC\logs\        (thư mục log theo đối tượng)
C:\Users\Public\Documents\AgentFMC\log.txt      (log chính, cấu hình qua \syslog.ini)
```

**Rồi đẩy lên server:** `POST /api/v1/events/insert` và `/api/v1/alerts/insert`.

### 3.4. C4 — Lớp giám sát thứ hai: `SerDefense.exe` (F-008)

Service `MiAV_Defense` chạy **song song và độc lập**:

```
0x002aee04 W cmd.exe /C
0x002af304 W create %s binPath= "%s"
0x002af334 W sc.exe
0x002af574 W delete %s
0x002af7b8 W wmic bios get serialnumber
0x002b15c0 W SELECT * FROM Win32_NetworkAdapterConfiguration
0x002b169c W Loopback
0x002b16bc W WAN Miniport
0x002b1710 W Kaspersky
0x002b1730 W Virtual
0x002b176c W 169.254
```

Nó dựng **profile máy** (serial BIOS, CPU, danh sách phần mềm đã cài) + **danh sách adapter mạng** (qua WMI), lọc bỏ adapter ảo, rồi giữ **kênh WebSocket** (`sgcWebSockets`, `sgcSSL_SChannel`, `sgcSSL_WinSSPI`) để nhận lệnh real-time.

**Hệ quả cho bài toán làm sạch:** phải bao phủ **cả hai lớp** (F-008). Dừng `MiAVProtect` mà quên `Defense` là chưa đủ.

### 3.5. C5 — Cảnh báo ghi lại URL mục tiêu (F-006, E-014)

```
0x003d1d08 W {"src_mac":%s,"src_ip":%s,"alert_type":%s,"alert_desc":%s,"alert_url":%s,"alert_level":%s}
0x01d52367 A @Uuntilities@tractinternet          <- module tên "tractinternet"
```

Module `tractinternet` trong `MiAV_Protect.exe` theo dõi cảnh báo và ghi **URL mục tiêu** vào payload. Ngoài ra có logic dò AV đối thủ và ghi `syslog` (`\syslog.ini`, `\log.txt`).

### 3.6. Sơ đồ luồng phát hiện

Xem `diagram/02-co-che-phat-hien-internet.svg`.

---

## 4. KẾT LUẬN PHỦ ĐỊNH: MIAV KHÔNG ĐỌC LỊCH SỬ TRÌNH DUYỆT/SRUM/DNS

### 4.1. Phương pháp

Trích toàn bộ chuỗi (ANSI + UTF-16LE) của **5 binary thực thi** (`MiAV.exe`, `MiAV_Protect.exe`, `MiAV_WD.exe`, `SerDefense.exe`, `MiAV_Update.exe`) rồi quét đối chiếu bằng các mẫu tín hiệu đặc trưng của từng cơ chế đọc lịch sử.

### 4.2. Kết quả quét đối chiếu

| Mẫu / Tín hiệu | MiAV | MiAV_Protect | MiAV_WD | SerDefense | MiAV_Update |
|---|:--:|:--:|:--:|:--:|:--:|
| `places.sqlite` (Firefox) | 0 | 0 | 0 | 0 | 0 |
| `History` / `WebCacheV01.dat` (IE/Edge) | 0 | 0 | 0 | 0 | 0 |
| `SRUDB` / SRUM (Usage) | 0 | 0 | 0 | 0 | 0 |
| `RunMRU` / `TypedPaths` / `RecentDocs` | 0 | 0 | 0 | 0 | 0 |
| `displaydns` / `dnsapi` / `DnsQuery_` | 0 | 0 | 0 | 0 | 0 |
| `Prefetch` / `Amcache` | 0 | 0 | 0 | 0 | 0 |
| `chrome.exe` / `firefox.exe` (hook tiến trình) | 0 | 0 | 0 | 0 | 0 |
| `winevt` / `EvtClearLog` | 0 | 0 | 0 | 0 | 0 |
| `iphlpapi.dll` / `GetExtendedTcpTable` | ✔ | ✔ | 0 | ✔ | 0 |
| `netstat -nao` (lệnh) | ✔ | ✔ | 0 | 0 | 0 |
| `cmd.exe /C` (thực thi lệnh) | ✔ | ✔ | 0 | ✔ | 0 |
| `Win32_NetworkAdapterConfiguration` | ✔ | ✔ | 0 | ✔ | 0 |

> **Lưu ý kỹ thuật:** chuỗi `History` có xuất hiện trong `MiAV.exe`/`MiAV_Protect.exe`, nhưng đó là **tên lớp FireDAC** (`TFDGUIxLoginHistoryStorage`, `FHistoryEnabled`, `FHistoryKey`) — **không** liên quan lịch sử trình duyệt. Đây là **false positive** đã được loại trừ.

### 4.3. Kết luận (F-005)

> MiAV **không** có cơ chế đọc lịch sử trình duyệt, SRUM, DNS client cache, Prefetch, Amcache, RunMRU, Jump List, hay Windows Event Log.
>
> Cơ chế **duy nhất** để kết luận "máy có Internet" là: **đo trạng thái hiện tại (C1) + thu thập bảng kết nối (C2) + nhật ký sự kiện Plug-in/Plug-out (C3)**.

**Ý nghĩa thực tiễn:**
- Xóa lịch sử trình duyệt/DNS/Prefetch **không ảnh hưởng** đến kết luận của MiAV → là biện pháp **tùy chọn**.
- Điều này **rất có lợi**: quy trình làm sạch được rút gọn, ít rủi ro, không cần can thiệp sâu vào hệ thống, không ảnh hưởng nghiệp vụ người dùng.
- Tập trung 100% công sức vào **6 nhóm artifact của MiAV** (mục 6).

---

## 5. KÊNH TRUYỀN DỮ LIỆU LÊN SERVER FMS (C2)

### 5.1. Bảng mapping artifact → endpoint

| Artifact cục bộ | Nội dung nhạy cảm | Endpoint nhận |
|---|---|---|
| `data\data.db` bảng `Logs` (type=`Internet`) | Sự kiện Plug-in/Plug-out + ComputerName + FullMac | `/api/v1/events/insert`, `/api/v1/alerts/insert` |
| `data\data.db` bảng `Logs` (khác) | Sự kiện EDR | `/api/v1/events/insert` |
| Telemetry `"connections"` | Toàn bộ socket TCP/UDP đang mở (đích, cổng, PID, tên CT) | `/api/v1/active-devices/insert` |
| Telemetry `"list_process"` / `"list_auto_run"` / `"list_softwares"` | Danh sách tiến trình / autorun / phần mềm | `/api/v1/active-devices/insert` |
| `data\data.db` bảng `Hashs` (978) | IOC MD5 + token JWT RS256 | `/api/v1/hashs/by-date` |
| Payload cảnh báo | `alert_url` — URL mục tiêu | `/api/v1/alerts/insert` |
| `policy.info` / `policy.net` | Cấu hình IP/DNS + bảng kết nối | (qua `fms.bqp`) |

### 5.2. Hệ quả: dữ liệu đã gửi không thu hồi được

Đây là **rủi ro lớn nhất** còn lại sau khi làm sạch cục bộ:

| Tình huống | Xử lý cục bộ có đủ? |
|---|---|
| Sự kiện `time_sent` **rỗng** (chưa gửi) — ví dụ máy offline khi MiAV ghi | ✅ Xóa dòng trong `data.db` là đủ |
| Sự kiện `time_sent` **khác rỗng** (đã gửi) | ❌ **Không đủ** — đã có trên server |
| Telemetry `active-devices` đã gửi | ❌ **Không đủ** — đã có trên server |
| `policy.*` chỉ tồn tại cục bộ | ✅ Xóa file là đủ |

⇒ **Bắt buộc** có bước đề nghị bằng văn bản tới **quản trị viên FMS/BTL86** yêu cầu xóa lịch sử `active-devices`, `events`, `alerts` ứng với tên/mã máy của đơn vị.

### 5.3. Kênh WebSocket — rủi ro bổ sung

`SerDefense.exe` giữ kênh WebSocket với server. Với kênh này, server **có thể chủ động yêu cầu** máy báo cáo lại (kể cả chạy lại các lệnh đo mạng). Vì vậy:

> **Thứ tự bắt buộc:** ngắt Internet → dừng service → làm sạch → **giữ ngắt Internet** → chỉ bật lại service khi đã nối vào mạng LAN quân sự (chỉ có DNS `86.0.188.1`, không có Internet).

---

## 6. MA TRẬN ARTIFACT — CẦN XÓA / KHÔNG CẦN XÓA

### 6.1. NHÓM A — BẮT BUỘC xóa (quyết định kết luận của MiAV)

| # | Đường dẫn | Loại | Nội dung | Bằng chứng |
|---|---|---|---|---|
| A1 | `C:\Users\Public\Documents\AgentFMC\data\data.db` → bảng **`Logs`** | SQLite | Sự kiện `type="Internet"`, `name="Plug-in"/"Plug-out"`, `level="Alert"` | E-010, E-011, F-003 |
| A2 | `C:\Users\Public\Documents\AgentFMC\logs\` | Thư mục | Log dạng text của agent | E-011, F-003 |
| A3 | `C:\Users\Public\Documents\AgentFMC\log.txt` | Tệp | Log dạng text của agent | E-006, E-011 |
| A4 | `C:\Users\Public\Documents\AgentFMC\policy.info` | Tệp | Output `ipconfig /all` | E-004, F-001 |
| A5 | `…\policy.ping` | Tệp | Output `ping 8.8.8.8` | E-004, F-001 |
| A6 | `…\policy.net` | Tệp | Output `netstat -nao` | E-004, F-001 |
| A7 | `…\policy.tracertWiki` | Tệp | Output `tracert wikipedia.org` | E-004, F-001 |
| A8 | `…\policy.tracertpBTL` | Tệp | Output `tracert 27.68.131.116` | E-004, F-001 |
| A9 | `…\policy.tracertlBTL` | Tệp | Output `tracert 10.152.4.2` | E-004, F-001 |
| A10 | `…\syslog.ini` | Tệp | Cấu hình syslog | E-006, E-011 |
| A11 | `…\Debug\` + `debugmiav.txt` + `debug.ini` | Thư mục/Tệp | Log debug | E-004 |

### 6.2. NHÓM B — NÊN LÀM (giảm bề mặt đối chiếu)

| # | Đường dẫn | Lý do |
|---|---|---|
| B1 | `…\data\config.ini` | Chứa `[Time] last_update_hash`, `[Drive] usb_no_at`, `[AppInfo] version`, `[Server]`, `[api_log]`, `[Alert]`, `[Event]` — cho biết máy đã từng đồng bộ với FMS |
| B2 | `…\auto\`, `…\0dpm\`, `…\2109\` | Module/plugin tải về — có thể chứa module `tractinternet` mở rộng |
| B3 | `…\rasoat\` (`MiAV_Listdlls.exe`, `.tempcmd.bat`, `.tempp.pid`) | Dấu vết thực thi lệnh tạm |
| B4 | `…\Blackip.txt` | Danh sách IP đen do MiAV ghi khi phát hiện hành vi |
| B5 | `…\data\data.db` → bảng `LocalFiles` | Danh sách AutoRun đã thu thập (36 dòng mẫu) |
| B6 | Khóa Run `HKLM\...\CurrentVersion\Run\MiAV` | Ghi nhận cơ chế persistence (không phải log Internet) |

### 6.3. NHÓM C — TÙY CHỌN (không ảnh hưởng kết luận của MiAV)

| Artifact | Lệnh/thao tác | Ghi chú |
|---|---|---|
| Lịch sử Chrome/Edge | Xóa `History`, `Login Data`, `Cookies`, `Web Data` | MiAV **không** đọc (F-005) |
| Lịch sử Firefox | Xóa `places.sqlite`, `formhistory.sqlite` | MiAV **không** đọc (F-005) |
| IE/Edge Legacy | Xóa `WebCacheV01.dat` | MiAV **không** đọc (F-005) |
| DNS cache | `ipconfig /flushdns` | MiAV **không** đọc (F-005) |
| Prefetch | Xóa `C:\Windows\Prefetch\*` | MiAV **không** đọc |
| Amcache | Xóa `C:\Windows\AppCompat\Programs\Amcache.hve` | MiAV **không** đọc |
| Jump List / RunMRU / TypedPaths | Xóa `AutomaticDestinations`, `RunMRU`, `TypedPaths` | MiAV **không** đọc |
| Windows Event Log | `wevtutil cl ...` | MiAV **không** đọc |
| ARP / NetBIOS cache | `arp -d *`, `nbtstat -R` | MiAV **không** đọc |

> **Khuyến nghị:** Nhóm C **không bắt buộc**. Chỉ thực hiện nếu quy định của đơn vị yêu cầu dọn dẹp môi trường trước khi vào mạng, hoặc để giảm bề mặt đối chiếu với bộ phận kiểm tra khác. Nên làm **sau** bước A để không bỏ sót.

### 6.4. Bản đồ đầy đủ

Xem `diagram/03-ban-do-lam-sach-log.svg`.

---

## 7. QUY TRÌNH & SCRIPT LÀM SẠCH LOG ĐỀ XUẤT

### 7.1. Nguyên tắc bắt buộc

| # | Nguyên tắc | Lý do |
|---|---|---|
| 1 | **Ngắt Internet trước** | Để `policy.*` mới sinh ra rỗng; để sự kiện không gửi được lên server |
| 2 | **Dừng 4 service + tiến trình `MiAV.exe`** | Nếu còn chạy, chúng sẽ ghi lại `data.db` và tạo lại `policy.*` ngay sau khi xóa |
| 3 | **Sao lưu trước khi xóa** | Có thể rollback; đồng thời là hồ sơ kỹ thuật cho bộ phận kiểm tra |
| 4 | **Xóa cả bảng `Logs`, không chỉ dòng `Internet`** | Dòng khác có thể chứa ngữ cảnh (URL, IP) trong `data` |
| 5 | **Không xóa driver/kernel** | Không liên quan; xóa driver có thể phá vỡ tính năng USB an toàn mà đơn vị cần |
| 6 | **Ghi nhận cột `time_sent`** | Xác định dữ liệu nào đã thoát khỏi máy → cần xử lý phía server |
| 7 | **Thực hiện TRƯỚC khi cắm vào mạng truyền số liệu** | Nếu đã nối mạng quân sự mà vẫn còn Internet → sự kiện mới tiếp tục ghi |
| 8 | **Chỉ bật lại service khi đã ổn định trong LAN** | Giảm rủi ro ghi log rác khi còn Internet |

### 7.2. Quy trình 12 bước

```
BƯỚC 1  Xác nhận máy đã NGẮT Internet
        └─ Kiểm tra: không ping được 8.8.8.8, không ping được wikipedia.org
        └─ Nhớ: mạng quân sự chỉ có LAN + DNS 86.0.188.1

BƯỚC 2  Kiểm kê hiện trạng (thu thập bằng chứng trước khi xóa)
        └─ Xuất bảng Logs ra CSV (giữ lại làm hồ sơ)
        └─ Ghi lại số dòng type='Internet', số dòng đã time_sent

BƯỚC 3  Sao lưu toàn bộ AgentFMC
        └─ Copy sang C:\_MiAV_backup\<ngày>\

BƯỚC 4  Dừng 4 service
        └─ sc stop MiAVProtect / MiAVUpdate / MiAVWD / Defense
        └─ sc config <tên> start= disabled   (tạm thời)

BƯỚC 5  Dừng tiến trình GUI
        └─ taskkill /IM MiAV.exe /F

BƯỚC 6  Xóa NHÓM A  (bảng Logs, logs\, log.txt, policy.*, syslog.ini, Debug\)
BƯỚC 7  Xóa NHÓM B  (config.ini, auto\, 0dpm\, 2109\, rasoat\, Blackip.txt, bảng LocalFiles)
BƯỚC 8  (Tùy chọn) Xóa NHÓM C  — lịch sử trình duyệt, DNS cache, Prefetch, Amcache, Jump List

BƯỚC 9  Xác minh
        └─ Kiểm tra data.db không còn dòng type='Internet'
        └─ Kiểm tra không còn file policy.*
        └─ Kiểm tra service đã dừng

BƯỚC 10 Bật lại service (start= auto)
BƯỚC 11 Kiểm tra hậu kiểm — policy.* được tạo lại nhưng PHẢI rỗng/lỗi
BƯỚC 12 Lập hồ sơ + đề nghị xóa dữ liệu phía server FMS
```

### 7.3. Script tự động

Script đầy đủ: **`Phan tich MiAV/Clean-NetworkHistory.ps1`**

Cách dùng:

```powershell
# Chạy thử (chỉ kiểm kê, không xóa)
powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -ReportOnly

# Thực hiện đầy đủ (dừng service, xóa, bật lại)
powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -WhatIfMode:$false

# Giữ ngắt service (bật lại thủ công sau khi cắm vào mạng quân sự)
powershell -ExecutionPolicy Bypass -File .\Clean-NetworkHistory.ps1 -KeepServicesStopped
```

> **Yêu cầu:** chạy bằng **quyền Administrator**, và **đảm bảo máy đã ngắt Internet**.

### 7.4. Checklist bàn giao cho đơn vị

| ☐ | Hạng mục | Ghi chú |
|---|---|---|
| ☐ | Máy đã ngắt Internet | Bằng chứng: ảnh chụp kết quả `ping 8.8.8.8` thất bại |
| ☐ | Đã chạy `-ReportOnly` và lưu CSV | Hồ sơ hiện trạng |
| ☐ | Đã sao lưu `C:\_MiAV_backup\` | Có thể rollback |
| ☐ | 4 service đã `stop` + `disabled` | `sc query` xác nhận |
| ☐ | `MiAV.exe` đã đóng | Task Manager |
| ☐ | Nhóm A đã xóa | `data.db` bảng `Logs` rỗng, không còn `policy.*` |
| ☐ | Nhóm B đã xóa | Tùy chọn |
| ☐ | Nhóm C đã xóa | Tùy chọn |
| ☐ | Đã bật lại 4 service (`start= auto`) | Hoặc giữ dừng theo quyết định |
| ☐ | Hậu kiểm: `policy.*` tạo lại nhưng rỗng | Ảnh chụp nội dung file |
| ☐ | Báo cáo số liệu `time_sent` (đã gửi) đã chuyển | Đề nghị phía FMS |
| ☐ | Văn bản đề nghị FMS/BTL86 xóa lịch sử server | Kèm danh sách mã máy |

### 7.5. Xác minh sau khi làm sạch (phía đơn vị kiểm tra)

Sau khi bật lại service và nối vào mạng quân sự:

1. Mở MiAV GUI → kiểm tra **mục Sự kiện / Alert** có còn mục `Internet / Plug-in` từ trước không.
2. Kiểm tra `C:\Users\Public\Documents\AgentFMC\data\data.db` — truy vấn:
   ```sql
   SELECT COUNT(*) FROM Logs WHERE type='Internet';
   -- Kỳ vọng: 0 (hoặc chỉ có sự kiện Plug-out mới)
   ```
3. Kiểm tra nội dung `policy.ping` — kỳ vọng: báo lỗi/timeout, **không** có phản hồi từ `8.8.8.8`.
4. Nội dung `policy.tracertWiki` — kỳ vọng: không phản hồi từ `wikipedia.org`.

---

## 8. QUY TRÌNH VẬN HÀNH ĐỀ XUẤT CHO ĐƠN VỊ

### 8.1. Quy trình chuẩn bị máy (áp dụng cho mọi máy trước khi vào mạng truyền số liệu)

```
┌─ GIAI ĐOẠN 1: CHUẨN BỊ (ngoài mạng, máy còn Internet) ─────────────┐
│  1. Cài MiAV 4.1.1.2 + driver CBFSFilter (nếu chưa có)           │
│  2. Ghi nhận số hiệu/mã máy để đề nghị phía FMS                    │
│  3. KHÔNG cắm USB lạ — chỉ dùng USB an toàn 2.6/3.0 đã chuẩn bị │
└────────────────────────────────────────────────────────────────────┘
                            ↓
┌─ GIAI ĐOẠN 2: CẮT INTERNET (tại đơn vị, trước khi nộp máy) ──────┐
│  4. Rút cáp Internet / tắt Wi-Fi  →  xác nhận mất Internet        │
│  5. Chạy Clean-NetworkHistory.ps1 (đã kết nối mạng LAN nội bộ)   │
│  6. Bật lại service MiAV → MiAV đo lại → policy.* rỗng             │
│  7. Xuất CSV hiện trạng + ảnh chụp màn hình → lưu hồ sơ           │
└────────────────────────────────────────────────────────────────────┘
                            ↓
┌─ GIAI ĐOẠN 3: NỘP MÁY VÀO MẠNG TRUYỀN SỐ LIỆU QUÂN SỰ ─────────┐
│  8. Cắm vào mạng LAN quân sự (DNS 86.0.188.1) — KHÔNG có Internet │
│  9. Chạy kiểm tra hậu kiểm (mục 7.5)                              │
│ 10. Lập hồ sơ, ký nhận, gửi kèm đề nghị xóa dữ liệu phía FMS    │
└────────────────────────────────────────────────────────────────────┘
```

### 8.2. Vai trò của từng bộ phận

| Bộ phận | Trách nhiệm |
|---|---|
| **CNTT đơn vị** | Thực hiện mục 8.1; lưu hồ sơ; giám sát máy sau khi nộp |
| **Quản trị viên FMS/BTL86** | Xóa lịch sử `active-devices`, `events`, `alerts` của các máy đã gửi; cung cấp báo cáo xác nhận |
| **Đội kiểm tra** | Đối chiếu hồ sơ (CSV + ảnh chụp) với trạng thái trên FMS |
| **Bộ phận An toàn thông tin** | Quy định mẫu hồ sơ, quy trình, thời hạn lưu giữ; phê duyệt thao tác trên phần mềm bắt buộc |

### 8.3. Rủi ro cần lưu ý

| Rủi ro | Mức | Giảm thiểu |
|---|---|---|
| Dữ liệu đã gửi lên FMS không thu hồi | **Cao** | Văn bản đề nghị phía server (mục 5.2) |
| MiAV tạo lại `policy.*` khi khởi động | Trung bình | Làm sạch khi máy đã ngắt Internet; giữ ngắt |
| Module tải động (`auto\`, `0dpm\`) chứa logic chưa phân tích | Trung bình | Xóa; kiểm tra trên máy thật sau khi cài |
| Chưa xác minh động hành vi thực thi (phân tích tĩnh 100%) | Trung bình | Kiểm thử trên máy thí nghiệm ngoài mạng quân sự |
| Việc dừng service có thể vi phạm quy định giám sát bắt buộc | Thấp | Chỉ thực hiện trong thời gian chuẩn bị, có phê duyệt, và bật lại ngay |

---

## 9. GIỚI HẠN & RỦI RO CÒN LẠI

1. **Phân tích 100% tĩnh.** Mẫu không được thực thi, không cài, không nối mạng. Hành vi runtime (tần suất ghi log, cơ chế retry, hành vi khi mất mạng) chưa được quan sát trực tiếp.
2. **Gói cài đặt không chứa module động.** Các thư mục `auto\`, `0dpm\`, `2109\` được MiAV_Protect tham chiếu nhưng **không có trong payload gói cài đặt** → nội dung do server đẩy về, chưa phân tích được.
3. **Giao thức server chưa đảo ngược hoàn toàn.** Đã xác định endpoint và cấu trúc payload, chưa giải mã hoàn toàn scheme xác thực JWT RS256 và cơ chế phân phối `public.pem`.
4. **Bản vá của BTL86 có thể khác.** Kết quả gắn với phiên bản `4.1.1.2` (timestamp build: `MiAV.exe` 2026-03-15, `MiAV_Protect.exe` 2025-11-10). Cần đối chiếu lại khi BTL86 phát hành bản mới.
5. **Dữ liệu phía server không kiểm soát được.** Đây là giới hạn cấu trúc của bài toán, không phải giới hạn kỹ thuật.

---

## 10. PHỤ LỤC

### 10.1. Evidence (bằng chứng có thể tái lập)

| ID | Nội dung | Nguồn |
|---|---|---|
| E-001 | Inno Setup 6.6.1, 4 service, khóa Run, `usb_no_at=block` | `ext/MiAV/install_script.iss` |
| E-002 | 5 binary + driver + data.db + 7 file YARA | `ext/MiAV/{app}/` |
| E-003 | PE metadata (x86, subsystem GUI, timestamp) | `pefile` |
| E-004 | 6 lệnh mạng → 6 file `policy.*` + 4 URL probe | `strings_MiAV.txt` 0x00580d18+ |
| E-005 | `netstat -nao` → JSON `"connections"` → `/api/v1/active-devices/insert` | `strings_MiAV_Protect.txt` 0x0097f6d4+ |
| E-006 | Payload cảnh báo `alert_url`; `\syslog.ini`, `\log.txt` | `strings_MiAV_Protect.txt` 0x003d1d08+ |
| E-007 | CBFSFilter driver, CBRegistry/CBProcess/CBFile, GUID | `strings_MiAV.txt` 0x003b471c+ |
| E-008 | Rule MITRE ATT&CK (TA0007--T083 …), `netstat -nao \|findstr` → `Blackip.txt` | `strings_MiAV.txt` 0x00598xxx |
| E-009 | `sgcWebSockets`, `sgcSSL_SChannel`, `Win32_NetworkAdapterConfiguration` | `strings_SerDefense.txt` 0x00552528+ |
| E-010 | Schema bảng `Logs` (SQLite), 978 IOC trong `Hashs` | `data/data.db` |
| E-011 | Đường dẫn log tập trung dưới `AgentFMC` | `strings_MiAV_Protect.txt` 0x004c4f38+ |
| E-012 | **Quét phủ định**: 0 hit cho browser history / SRUM / DNS / Prefetch / Amcache / RunMRU | 5 file strings |
| E-013 | `cmd.exe /C`, `sc.exe create/start/delete`, `wmic bios`, adapter filter | `strings_SerDefense.txt` 0x002aeb04+ |
| E-014 | Module `tractinternet`, bộ đếm cảnh báo URL | `strings_MiAV_Protect.txt` 0x01d52367 |
| E-015 | Dò AV đối thủ, ghi `syslog`/`log.txt`, `killProcessNA.bat` | `strings_MiAV_Protect.txt` 0x003d2480+ |

Chi tiết đầy đủ: `work/phan-tich-miav-giam-sat/evidence/evidence-chain.md`

### 10.2. Findings (kết luận)

| ID | Tiêu đề | Mức | Trạng thái |
|---|---|---|---|
| F-001 | Đo trạng thái Internet bằng 6 lệnh mạng (`policy.*`) | info | validated |
| F-002 | Thu thập `netstat -nao` → trường `"connections"` trong telemetry | **high** | validated |
| F-003 | Sự kiện `type="Internet"`, `name="Plug-in"/"Plug-out"`, `level="Alert"` | medium | validated |
| F-004 | Driver callback CBFSFilter giám sát file/registry/process | info | validated |
| F-005 | **KHÔNG** đọc lịch sử trình duyệt / SRUM / DNS cache | info | validated |
| F-006 | C2 hai đầu: REST API + WebSocket; payload có `alert_url` | **high** | validated |
| F-007 | YARA + 978 IOC MD5 trong `data.db` | info | validated |
| F-008 | SerDefense: `cmd.exe`/`sc.exe`/WMI — lớp giám sát thứ hai | medium | validated |
| F-009 | Chính sách USB qua `config.ini`, điều khiển từ xa | info | validated |

Chi tiết: `work/phan-tich-miav-giam-sat/findings.md`

### 10.3. Công cụ tái lập (trong `Phan tich MiAV/evidence/`)

| Script | Chức năng |
|---|---|
| `extract_miav_strings.py` | Trích chuỗi ANSI + UTF-16LE kèm offset byte, tự nhận diện BOM |
| `grep_miav_strings.py` | Tìm theo nhiều regex trên file chuỗi đã trích |
| `disasm_internet_xref.py` | **Xác minh F-003**: tìm VA chuỗi `"Internet"`, quét xref `mov/push imm32` trong `.text`, dịch ngược vùng xref và in chú thích chuỗi hằng |
| `gen_miav_diagrams.py` | Sinh 3 file SVG trong `diagram/` |

Lệnh tái lập chính:

```powershell
python evidence\disasm_internet_xref.py "..\ext\MiAV\{app}\MiAV.exe"
```

Kết quả (rút gọn):

```
=== Vi tri chuoi hang ===
  Plug-in    VA=0x00982242
  Internet   VA=0x009822e8
  Alert      VA=0x0090f41c   (bản thứ hai tại 0x00982308 — bản dùng tại xref)
  Plug-out   VA=0x00982322

=== Xref toi chuoi 'Internet': 2 hit ===
--- Xref tai VA 0x00981ed7 ---
  0x009812d7  mov     ecx, 0x9822e8      ; <- "Internet"
  0x009812dc  mov     edx, 0x982308      ; <- "Alert"
  0x009812e1  call    0x8cc508           ; ghi su kien
--- Xref tai VA 0x00981fa4 ---
  0x009813a4  mov     ecx, 0x9822e8      ; <- "Internet"
  0x009813a9  mov     edx, 0x982308      ; <- "Alert"
  0x009813ae  call    0x8cc508           ; ghi su kien
```

### 10.4. Hồ sơ case

| Tệp | Nội dung |
|---|---|
| `work/phan-tich-miav-giam-sat/scope.md` | Hợp đồng phạm vi (`offline-sample`, `auth.status=granted`) |
| `work/phan-tich-miav-giam-sat/workitems.md` | WI-001 … WI-008 (tất cả `done`) |
| `work/phan-tich-miav-giam-sat/timeline.md` | 10 mốc thời gian các bước phân tích |
| `work/phan-tich-miav-giam-sat/evidence/E-001.md` … `E-015.md` | 15 bản ghi Evidence (chuẩn contract `review_case.py`) |
| `work/phan-tich-miav-giam-sat/evidence/evidence-chain.md` | Bản tổng hợp 15 evidence |
| `work/phan-tich-miav-giam-sat/report/findings.md` | F-001 … F-009 |
| `work/phan-tich-miav-giam-sat/report/paths.md` | P-001 … P-003 |
| `work/phan-tich-miav-giam-sat/findings.md` | Bản gốc (chứa cả Findings và Path) |

**Kết quả tự kiểm tra hồ sơ:**

```powershell
python reverse-skill-main\skills\case-review\scripts\review_case.py `
       work\phan-tich-miav-giam-sat
# status: PASS | errors: 0 | warnings: 0
# evidence: 15 | workitems: 8 | timeline_events: 10 | findings: 9 | paths: 3
```

---

*Người lập báo cáo: Trung tá Đoàn Danh Quyết — Trợ lý Công nghệ Thông tin*
*Báo cáo được lập bằng phương pháp phân tích tĩnh, có đầy đủ bằng chứng tái lập.*
