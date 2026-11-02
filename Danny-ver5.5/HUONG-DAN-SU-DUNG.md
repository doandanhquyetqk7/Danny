# DANNY ver5.5 — Hướng dẫn sử dụng

**Trợ lý Công nghệ thông tin**
Phần mềm được viết bởi **Trung tá Đoàn Danh Quyết** — Trợ lý Công nghệ thông tin — Cellphone: 0366.714.139

---

## 0. Nội dung mới của bản 5.5

| # | Thay đổi | Chi tiết |
|---|---|---|
| 1 | **Tab mới: “HỖ TRỢ KỸ THUẬT TỪ XA”** | Hỗ trợ điều khiển máy tính từ xa qua **UltraVNC 1.4.2.0 Portable**, phân biệt 2 vai trò: **Máy nhận kết nối** (máy kỹ thuật viên) và **Máy cần hỗ trợ** (máy quân sự) |
| 2 | **Tự động hoá toàn bộ quy trình** | Người dùng chỉ cần chọn vai trò + bấm nút — phần mềm tự mở firewall, cấu hình `ultravnc.ini`, tạo shortcut, cài service WinVNC và phát lệnh kết nối |
| 3 | **Bộ công cụ UltraVNC đi kèm** | `tools\UltraVNC\x64\` và `tools\UltraVNC\x86\` — gồm `vncviewer.exe`, `winvnc.exe`, các DLL driver và **plugin mã hoá DSM** |
| 4 | **Mã hoá DSM (SecureVNCPlugin64.dsm)** | Mặc định **BẬT** — mã hoá toàn bộ hình ảnh & phím bấm trên đường truyền LAN, chống bị bắt gói tin |
| 5 | **Hiển thị & chép IP LAN** | Phần mềm tự dò IP của card mạng đang hoạt động, hiển thị ngay để kỹ thuật viên chép gửi cho người dùng |
| 6 | **Cờ CLI mới** | `--remote-listen` và `--remote-connect` cho chế độ headless (automation) |

> Bản 5.5 kế thừa toàn bộ tính năng của bản 5.0 (6 tab chức năng) và bổ sung tab thứ 7.

---

## 1. Cấu trúc bộ cài đặt

```
Danny-ver5.5/
├── Danny-ver5.5.exe            69,16 MB  ← bản khuyến nghị (chạy được mọi máy)
├── Danny-ver5.5-nethost.exe     1,36 MB  ← bản nhẹ (cần .NET 8 Desktop Runtime)
├── tools\
│   ├── KVRT.exe               116,28 MB  ← Kaspersky Virus Removal Tool
│   ├── SetupMiAV.exe           21,20 MB  ← trình cài đặt MiAV (BTL86)
│   └── UltraVNC\                          ← bộ công cụ hỗ trợ từ xa
│       ├── Readme.txt
│       ├── x64\                           ← bản 64-bit (dùng cho Windows 10/11 64-bit)
│       │   ├── vncviewer.exe              ← máy NHẬN kết nối
│       │   ├── winvnc.exe                 ← máy CẦN hỗ trợ
│       │   ├── SecureVNCPlugin64.dsm      ← plugin mã hoá DSM
│       │   ├── ddengine64.dll, logging.dll, vnchooks.dll
│       │   └── UVncVirtualDisplay64\      ← driver màn hình ảo (đa màn hình)
│       └── x86\                           ← bản 32-bit (dự phòng cho máy cũ)
└── HUONG-DAN-SU-DUNG.md
```

> **Bắt buộc:** giữ nguyên thư mục `tools\` cạnh file `.exe` (đặc biệt `tools\UltraVNC\`).
> Tab "Hỗ trợ kỹ thuật từ xa" sẽ báo rõ ràng nếu không tìm thấy bộ công cụ này.

| File | Dùng khi nào |
|---|---|
| **Danny-ver5.5.exe** | Máy chưa cài .NET — **khuyến nghị dùng bản này** |
| Danny-ver5.5-nethost.exe | Máy đã có .NET 8 Desktop Runtime (khởi động nhanh hơn ~1 giây) |

---

## 2. Yêu cầu hệ thống

- Windows 10 / Windows 11 (32-bit hoặc 64-bit)
- **Quyền Administrator** — phần mềm tự yêu cầu (biểu tượng UAC)
- Hai máy phải **cùng nằm trong một mạng LAN** (mạng nội bộ đơn vị)
- Dung lượng trống tối thiểu: ~310 MB (Kaspersky 116 MB + SetupMiAV 21 MB + UltraVNC ~16 MB + bản sao lưu)

---

## 3. Mở phần mềm

Nhấp đúp `Danny-ver5.5.exe` → chấp thuận quyền Administrator → phần mềm hiện **7 tab**:

| # | Tab | Chức năng |
|---|---|---|
| 1 | **KIỂM TRA KẾT NỐI** | Chẩn đoán 4 bước, tra cứu 130 đơn vị, xuất báo cáo |
| 2 | **USB AN TOÀN 2.6** | Tạo USB an toàn cho MiAV (không bị chặn ở tầng kernel) |
| 3 | **CẤU HÌNH IP MỘT CHẠM** | Đặt IP tĩnh LAN đúng dải đơn vị, có rollback |
| 4 | **CẤU HÌNH MẠNG** | Cấu hình IP/DNS thủ công |
| 5 | **LÀM SẠCH PC MỘT CHẠM** | Quy trình vệ sinh tự động + quét virus + cài lại MiAV |
| 6 | **HỖ TRỢ KỸ THUẬT TỪ XA** | **MỚI — kết nối/điều khiển máy tính từ xa bằng UltraVNC** |
| 7 | **BẢO MẬT & TIỆN ÍCH** | Chạy KVRT thủ công, xóa Event Viewer, hiện file ẩn |

---

## 4. TAB “HỖ TRỢ KỸ THUẬT TỪ XA”

### 4.1. Nguyên tắc hoạt động

Chức năng dựa trên **UltraVNC 1.4.2.0 Portable** và quy trình chuẩn thiết lập kết nối ngược (reverse connection):

```
        MÁY NHẬN KẾT NỐI                          MÁY CẦN HỖ TRỢ
        (máy kỹ thuật viên)                      (máy quân sự)
        ────────────────────                      ────────────────
        vncviewer.exe -listen 5500        ──►     winvnc.exe -connect
        (lắng nghe, chờ khách gàng gọi)           <ip-máy-KT>::5500
                                                       (mở kết nối ngược)
```

Vì sao dùng kết nối **ngược** (client chủ động gọi về server)?

- Máy quân sự thường **không mở được cổng inbound** do chính sách firewall của đơn vị.
- Máy kỹ thuật viên thường nằm trong mạng LAN nội bộ — mở cổng ở đây dễ hơn nhiều.
- Người dùng cuối chỉ cần **nhập IP**, không phải cấu hình gì.

### 4.2. Giao diện

| Thành phần | Ý nghĩa |
|---|---|
| **MÁY NHẬN KẾT NỐI** | Chọn khi máy này là máy của kỹ thuật viên (sẽ chờ người dùng gọi tới) |
| **MÁY CẦN HỖ TRỢ** | Chọn khi máy này cần được hỗ trợ (sẽ gọi về máy kỹ thuật viên) |
| **IP máy kỹ thuật viên** | Chỉ dùng ở chế độ *Máy cần hỗ trợ* — nhập IP LAN của máy kỹ thuật viên |
| **Cổng Listen** | Mặc định **5500** (cổng chuẩn của chế độ Listen của UltraVNC) |
| **IP máy này (LAN)** | IP tự động dò từ card mạng đang hoạt động — nút **“Chép IP”** để copy nhanh |
| **Bật mã hoá DSM** | Khuyến nghị **BẬT** (mặc định) — dùng `SecureVNCPlugin64.dsm` |
| **Cài WinVNC thành service** | Chỉ ở chế độ *Máy cần hỗ trợ* — để hỗ trợ được cả khi đã đăng xuất Windows |
| **Tạo shortcut trên Desktop** | Chỉ ở chế độ *Máy nhận kết nối* — tạo lối tắt chạy nhanh Viewer |

---

### 4.3. QUY TRÌNH A — Máy NHẬN kết nối (máy kỹ thuật viên)

**Bước 1.** Mở tab **HỖ TRỢ KỸ THUẬT TỪ XA** → chọn **“MÁY NHẬN KẾT NỐI”**.

**Bước 2.** Kiểm tra ô **“IP máy này (LAN)”** — đây là địa chỉ bạn sẽ gửi cho người dùng.
Nhấn **“Chép IP”** để copy vào clipboard.

**Bước 3.** (Tùy chọn) Sửa **Cổng Listen** nếu mạng đơn vị đã dùng 5500 cho mục đích khác.

**Bước 4.** Nhấn **“CHUẨN BỊ KẾT NỐI”**. Phần mềm tự động thực hiện **4 bước**:

```
BƯỚC 1  Mở cổng TCP 5500 trong Windows Defender Firewall
         (rule: "Danny UltraVNC Listen TCP 5500" — inbound, mọi profile)

BƯỚC 2  Cập nhật ultravnc.ini
         [admin]
         UseDSMPlugin=1
         DSMPlugin=SecureVNCPlugin64.dsm
         SocketConnect=1
         AutoPortSelect=0
         PortNumber=5500
         AuthRequired=1

BƯỚC 3  Tạo shortcut trên Desktop:
         "UltraVNC - Lắng nghe (máy nhận kết nối).lnk"
         Target: ...\tools\UltraVNC\x64\vncviewer.exe
         Args  : -listen 5500 -dsmplugin "SecureVNCPlugin64.dsm"

BƯỚC 4  Khởi chạy vncviewer.exe -listen 5500
         → đợi đến khi cổng 5500 thực sự lắng nghe (tối đa 15 giây)
```

**Bước 5.** Chờ thông báo **“ĐÃ SẴN SÀNG NHẬN KẾT NỐI trên cổng 5500”**.

**Bước 6.** Gửi cho người dùng: **IP** của bạn + **cổng 5500**.

> Nếu không nhận được kết nối: nhấn **“DỪNG / Dọn Dẹp”** rồi **“CHUẨN BỊ KẾT NỐI”** lại.

---

### 4.4. QUY TRÌNH B — Máy CẦN hỗ trợ (máy quân sự)

**Bước 1.** Mở tab → chọn **“MÁY CẦN HỖ TRỢ”**.

**Bước 2.** Nhập **IP máy kỹ thuật viên** vào ô bên trái (VD: `192.168.10.55`), giữ nguyên cổng **5500**.

**Bước 3.** Nhấn **“CHUẨN BỊ KẾT NỐI”**. Phần mềm tự động thực hiện **4 bước**:

```
BƯỚC 1  Mở cổng TCP 5500 trong Windows Defender Firewall

BƯỚC 2  Cập nhật ultravnc.ini (kèm dòng cho service):
         service_commandline=-autoreconnect -connect <ip>::5500

BƯỚC 3  Cài WinVNC thành service:
         winvnc.exe -install   →  service tên "winvnc"
         sc start winvnc

BƯỚC 4  Mở kết nối ngược:
         winvnc.exe -run                              (nếu chưa chạy)
         winvnc.exe -autoreconnect -connect <ip>::5500
```

**Bước 4.** Màn hình máy này sẽ hiện trên máy kỹ thuật viên trong vài giây.

> **Lưu ý về cú pháp `-connect`:** UltraVNC dùng **hai dấu hai chấm** `::` để chỉ định đúng cổng.
> Dạng `host:port` sẽ bị **cộng thêm 5900** (VD `:1` → cổng 5901) — phần mềm luôn dùng dạng `::`
> để tránh lỗi này.

---

### 4.5. Xử lý sự cố

| Hiện tượng | Nguyên nhân | Khắc phục |
|---|---|---|
| “Không tìm thấy bộ công cụ UltraVNC” | Thiếu thư mục `tools\UltraVNC` | Chép lại đầy đủ `tools\UltraVNC` từ bộ cài |
| “Cổng 5500 chưa sẵn sàng” | Firewall hoặc viewer chưa bind xong | Nhấn “DỪNG / Dọn Dẹp” → “CHUẨN BỊ KẾT NỐI” lại; kiểm tra Group Policy |
| Máy kia không thấy màn hình | Sai IP / sai cổng | Kiểm tra lại IP máy kỹ thuật viên và cổng ở cả 2 đầu |
| Kết nối bị từ chối | Chưa mở firewall ở máy nhận kết nối | Chạy lại “CHUẨN BỊ KẾT NỐI” ở máy nhận kết nối |
| Phiên không mã hoá | Thiếu plugin DSM | Kiểm tra `tools\UltraVNC\x64\SecureVNCPlugin64.dsm` có tồn tại |
| Không điều khiển được khi đã đăng xuất | Chưa cài service | Bật tùy chọn “Cài WinVNC thành service” |

---

### 4.6. Bảo mật phiên làm việc

- **Luôn bật mã hoá DSM** — kết nối VNC thô không được mã hoá, ai cũng bắt được gói tin trong LAN.
- **Đặt mật khẩu VNC** khác hoàn toàn với mật khẩu Windows của máy (đặt trong `ultravnc.ini`).
- **Chỉ dùng trong mạng nội bộ** của đơn vị; không mở cổng 5500 ra Internet.
- Sau khi hỗ trợ xong, nhấn **“DỪNG / Dọn Dẹp”** để đóng viewer, dừng winvnc và **xoá rule firewall**.
- `SecureVNCPlugin64.dsm` dùng cơ chế RSA — nếu dùng lâu dài nên tạo cặp khóa riêng cho đơn vị.

---

## 5. CLI (chế độ không giao diện)

```
Danny-ver5.5.exe --remote-listen [--port 5500]
    :: Máy nhận kết nối — mở firewall, cấu hình, tạo shortcut, chạy vncviewer listen

Danny-ver5.5.exe --remote-connect --ip 192.168.1.55 [--port 5500] [--no-service]
    :: Máy cần hỗ trợ — cài service WinVNC và mở kết nối ngược
```

| Cờ | Ý nghĩa |
|---|---|
| `--port <số>` | Cổng listen/kết nối (mặc định 5500) |
| `--ip <địa chỉ>` | IP máy kỹ thuật viên (bắt buộc với `--remote-connect`) |
| `--no-service` | Không cài WinVNC thành service (chỉ chạy khi đang đăng nhập) |

Các lệnh CLI khác của bản 5.0 vẫn giữ nguyên:
`--make-safe "X:\"`, `--check "X:\"`, `--diag [--full]`, `--clean`.

---

## 6. Quy trình “Làm sạch PC một chạm” (giữ nguyên từ bản 5.0)

```
 1  Kiểm tra trạng thái Internet            8  Xóa NHÓM B (artifact MiAV)
 2  Kiểm kê dòng Logs type='Internet'       9  Xác minh
 3  Sao lưu AgentFMC                       10  Bật lại 4 service MiAV
 4  Dừng 4 service MiAV                    11  Kaspersky KVRT — quét toàn bộ ổ + khử nhiễm
 5  Dừng tiến trình GUI MiAV               12  ★ Cài lại MiAV (SetupMiAV.exe /VERYSILENT)
 6  Xóa NHÓM A (bảng Logs, policy.*)      13  Báo cáo CSV → Khởi động lại máy
 7  Xóa NHÓM C (browser, SRUM, DNS…)
```

Bước 12 gọi `SetupMiAV.exe` với tham số
`/VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART /LANG=english /LOG="…"`,
rồi xác minh 4 service `MiAVWD` / `MiAVUpdate` / `MiAVProtect` / `Defense` đã được tạo.

---

## 7. Ghi chú kỹ thuật

### 7.1. UltraVNC 1.4.2.0 Portable

| Thành phần | Nguồn |
|---|---|
| `vncviewer.exe`, `winvnc.exe` | Bản phân phối chính thức `UltraVNC_1420.zip` (uvnc.eu) — giấy phép GNU/GPL |
| `SecureVNCPlugin64.dsm` | Bộ `encryptionplugins.zip` chính thức của UltraVNC |

Các tham số dòng lệnh đã được xác minh trực tiếp từ chuỗi nội bộ của `winvnc.exe` / `vncviewer.exe`:

| Lệnh | Ý nghĩa |
|---|---|
| `vncviewer.exe -listen [port]` | Chế độ lắng nghe (chờ khách hàng gọi tới) |
| `vncviewer.exe -dsmplugin <file.dsm>` | Bật plugin mã hoá DSM |
| `winvnc.exe -run` | Chạy WinVNC ở chế độ ứng dụng (phải chạy **trước** khi `-connect`) |
| `winvnc.exe -connect host::port` | Mở kết nối ngược tới đúng cổng `port` |
| `winvnc.exe -autoreconnect` | Tự kết nối lại nếu phiên bị ngắt (phải đặt **trước** `-connect`) |
| `winvnc.exe -install` / `-remove` | Cài / gỡ service WinVNC |
| `winvnc.exe -installdriver` | Cài driver mirror (hỗ trợ chụp màn hình Windows 10/11) |

### 7.2. Cấu hình `ultravnc.ini`

| Khoá | Giá trị | Ý nghĩa |
|---|---|---|
| `UseDSMPlugin` | `1` | Bật mã hoá bằng plugin DSM |
| `DSMPlugin` | `SecureVNCPlugin64.dsm` | Tên file plugin |
| `SocketConnect` | `1` | Phải có socket lắng nghe |
| `AutoPortSelect` | `0` | Không tự dò cổng |
| `PortNumber` | `5500` | Cổng VNC |
| `AuthRequired` | `1` | Yêu cầu mật khẩu |
| `service_commandline` | `-autoreconnect -connect <ip>::5500` | Dòng lệnh cho service |

> Phần mềm **ghi đè** section `[admin]` cũ (xoá hẳn các khoá cũ) để tránh tình trạng
> UltraVNC đọc nhầm giá trị đầu tiên — ví dụ còn sót `PortNumber=5900` bên dưới giá trị mới.

### 7.3. Nhật ký & báo cáo

- Nhật ký thao tác nằm trong ô log màu xanh của tab.
- `ultravnc.ini` được tạo trong `tools\UltraVNC\x64\` (hoặc `x86\`) — có thể mở để kiểm tra.
- Rule firewall do phần mềm tạo có tên `Danny UltraVNC Listen TCP <port>`.

---

## 8. Thông tin liên hệ

| | |
|---|---|
| **Tác giả** | Trung tá Đoàn Danh Quyết — Trợ lý Công nghệ thông tin |
| **Đơn vị** | Bộ Chỉ huy Quân sự tỉnh Lâm Đồng |
| **Điện thoại** | 0366.714.139 |
| **Mã nguồn** | https://github.com/doandanhquyetqk7/Danny |
| **Theo dõi phiên bản** | https://github.com/users/doandanhquyetqk7/projects/1 |
