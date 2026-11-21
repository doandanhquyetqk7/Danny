# DANNY ver5.6 — Hướng dẫn sử dụng

**Trợ lý Công nghệ thông tin**
Phần mềm được viết bởi **Trung tá Đoàn Danh Quyết** — Trợ lý Công nghệ thông tin — Cellphone: 0366.714.139

---

## 0. Nội dung mới của bản 5.6

| # | Thay đổi | Chi tiết |
|---|---|---|
| 1 | **Thay thế UltraVNC bằng RustDesk** | Chức năng “Hỗ trợ kỹ thuật từ xa” chuyển từ **UltraVNC 1.4.2.0** sang **RustDesk 1.5.3** — **gỡ sạch toàn bộ mã nguồn, hằng số và tài nguyên UltraVNC** |
| 2 | **Chế độ Direct IP Access — 100% OFFLINE** | Kết nối **trực tiếp** qua địa chỉ IP nội bộ, **không cần ID Server / Relay Server**, **không cần Internet** |
| 3 | **Cổng chuẩn 21118** | Thay cho cổng 5500 của UltraVNC — cấu hình qua `direct-access-port` |
| 4 | **Whitelist IP theo dải CIDR** | Ô “Whitelist IP (dải CIDR)”, **mặc định `86.134.32.150/24`** (dải IP quản trị), **người dùng sửa tay được** |
| 5 | **Xác nhận an toàn bắt buộc** | `approve-mode = click` — máy cần hỗ trợ phải **bấm “Đồng ý”** mới cho phép kết nối; kèm `use-temporary-password` |
| 6 | **Cài RustDesk thành service (--install-service)** | Có quyền Admin → cài service + thao tác được trên **cửa sổ UAC**; không có quyền → tự lùi về portable + cảnh báo nhẹ |
| 7 | **Tự động mở/đóng Firewall an toàn** | Bật → tạo rule inbound TCP 21118 (**khoá theo RemoteAddress** của whitelist); Dừng → **xoá ngay rule** |
| 8 | **Gỡ bỏ hoàn toàn DSM/UltraVNC** | Không còn `ultravnc.ini`, `winvnc`, `vncviewer`, plugin `.dsm`, cổng 5500/5900 |
| 9 | **Cờ CLI mới `--whitelist`** | `--remote-listen` / `--remote-connect` nay nhận thêm dải IP cho phép |
| 10 | **Ghi log đầy đủ, bọc try/catch** | Mọi thao tác hệ thống (ghi TOML, `netsh`, cài service, khởi tiến trình) đều có log lỗi rõ ràng |

> Bản 5.6 kế thừa toàn bộ tính năng của bản 5.5 và thay **duy nhất** module hỗ trợ từ xa.

---

## 1. Cấu trúc bộ cài đặt

```
Danny-ver5.6/
├── Danny-ver5.6.exe            69,16 MB  ← bản khuyến nghị (chạy được mọi máy)
├── Danny-ver5.6-nethost.exe     1,41 MB  ← bản nhẹ (cần .NET 8 Desktop Runtime)
├── tools\
│   ├── KVRT.exe               116,28 MB  ← Kaspersky Virus Removal Tool
│   └── RustDesk\                          ← bộ công cụ hỗ trợ từ xa
│       ├── rustdesk.exe            25,02 MB  ← RustDesk client 1.5.3 (chế độ Direct IP)
│       └── server\                          ← RustDesk Server tự host (tùy chọn)
│           ├── hbbs.exe             6,77 MB  ← ID server
│           ├── hbbr.exe             2,77 MB  ← Relay server
│           └── rustdesk-utils.exe   0,40 MB  ← sinh cặp khoá server
└── HUONG-DAN-SU-DUNG.md
```

> **Bắt buộc:** giữ nguyên thư mục `tools\` cạnh file `.exe` (đặc biệt `tools\RustDesk\`).
> Tab “Hỗ trợ kỹ thuật từ xa” sẽ báo rõ ràng nếu không tìm thấy `rustdesk.exe`.

| File | Dùng khi nào |
|---|---|
| **Danny-ver5.6.exe** | Máy chưa cài .NET — **khuyến nghị dùng bản này** |
| Danny-ver5.6-nethost.exe | Máy đã có .NET 8 Desktop Runtime (khởi động nhanh hơn ~1 giây) |

---

## 2. Yêu cầu hệ thống

- Windows 10 / Windows 11 (32-bit hoặc 64-bit)
- **Quyền Administrator** — phần mềm tự yêu cầu (biểu tượng UAC)
- Hai máy phải **cùng nằm trong một mạng LAN** (mạng nội bộ đơn vị)
- Dung lượng trống tối thiểu: ~220 MB (Kaspersky 116 MB + RustDesk 25 MB + bản sao lưu)

---

## 3. Mở phần mềm

Nhấp đúp `Danny-ver5.6.exe` → chấp thuận quyền Administrator → phần mềm hiện **7 tab**:

| # | Tab | Chức năng |
|---|---|---|
| 1 | **KIỂM TRA KẾT NỐI** | Chẩn đoán 4 bước, tra cứu 130 đơn vị, xuất báo cáo |
| 2 | **USB AN TOÀN 2.6** | Tạo USB an toàn cho MiAV (không bị chặn ở tầng kernel) |
| 3 | **CẤU HÌNH IP MỘT CHẠM** | Đặt IP tĩnh LAN đúng dải đơn vị, có rollback |
| 4 | **CẤU HÌNH MẠNG** | Cấu hình IP/DNS thủ công |
| 5 | **LÀM SẠCH PC MỘT CHẠM** | Quy trình vệ sinh tự động + quét virus + cài lại MiAV |
| 6 | **HỖ TRỢ KỸ THUẬT TỪ XA** | Kết nối/điều khiển máy tính từ xa bằng **RustDesk Direct IP** |
| 7 | **BẢO MẬT & TIỆN ÍCH** | Chạy KVRT thủ công, xóa Event Viewer, hiện file ẩn |

---

## 4. TAB “HỖ TRỢ KỸ THUẬT TỪ XA”

### 4.1. Nguyên tắc hoạt động — Direct IP Access (100% offline)

Chức năng dựa trên **RustDesk 1.5.3** ở chế độ **Direct IP Access**:

```
        MÁY NHẬN KẾT NỐI                          MÁY CẦN HỖ TRỢ
        (máy kỹ thuật viên)                      (máy quân sự)
        ────────────────────                      ────────────────
        rustdesk.exe --server             ──►     rustdesk.exe --connect
        (mở listener TCP 21118)                    <IP-máy-KT>:21118
                                                  (kết nối TRỰC TIẾP)
```

**Điểm khác biệt quan trọng so với UltraVNC:**

| | UltraVNC (ver5.5) | RustDesk (ver5.6) |
|---|---|---|
| Chế độ | Reverse connection (kết nối ngược) | **Direct IP Access** — kết nối thẳng |
| Cần Internet / ID Server | Không | **Không — 100% offline** |
| Cổng | 5500 | **21118** |
| Xác nhận | Mật khẩu VNC | **Xin phép thủ công (click)** + mật khẩu tạm thời |
| Mã hoá | Plugin DSM (`.dsm`) | **RustDesk mã hoá sẵn (chặt hơn)** |
| Lọc IP theo nguồn | Không | **Whitelist IP/CIDR (khoá firewall)** |

> **Lưu ý:** Trong cửa sổ RustDesk, trạng thái **“Not ready”** hiển thị bằng **chữ đỏ**
> là **BÌNH THƯỜNG** khi chạy offline ở chế độ Direct IP — đây là trạng thái “chưa đăng nhập
> được ID server”, **không phải lỗi**. Phiên kết nối trực tiếp vẫn hoạt động bình thường.

### 4.2. Giao diện

| Thành phần | Ý nghĩa |
|---|---|
| **MÁY NHẬN KẾT NỐI** | Chọn khi máy này là máy của kỹ thuật viên (sẽ chờ người dùng gọi tới) |
| **MÁY CẦN HỖ TRỢ** | Chọn khi máy này cần được hỗ trợ (sẽ gọi tới máy kỹ thuật viên) |
| **IP máy cần hỗ trợ** | Chỉ dùng ở chế độ *Máy cần hỗ trợ* — nhập IP hoặc `IP:Port` của máy kỹ thuật viên |
| **Mật khẩu** | Mật khẩu RustDesk (tạm thời hoặc thường) — để truyền cho lệnh `--connect` |
| **Whitelist IP (dải CIDR)** | Danh sách IP được phép kết nối. **Mặc định `86.134.32.150/24`**, sửa tay được. Để trống = không giới hạn |
| **Cổng Direct IP** | Mặc định **21118** — sửa được nếu trùng cổng |
| **Xin phép thủ công** | Mặc định **BẬT** (`approve-mode=click`) — máy bên kia phải bấm “Đồng ý” |
| **Cài RustDesk thành service** | Để hỗ trợ được cả khi đã đăng xuất Windows + thao tác được cửa sổ UAC |
| **Tạo shortcut trên Desktop** | Tạo lối tắt “RustDesk - Bật hỗ trợ từ xa” |
| **IP máy này (LAN)** | IP tự động dò từ card mạng vật lý (bỏ qua card ảo/loopback/APIPA) — nút **“Chép IP”** |

### 4.3. QUY TRÌNH A — Máy NHẬN kết nối (máy kỹ thuật viên)

**Bước 1.** Mở tab **HỖ TRỢ KỸ THUẬT TỪ XA** → chọn **“MÁY NHẬN KẾT NỐI”**.

**Bước 2.** Kiểm tra ô **“IP máy này (LAN)”** — đây là địa chỉ bạn sẽ gửi cho người dùng.
Nhấn **“Chép IP”** để copy vào clipboard.

**Bước 3.** Kiểm tra ô **“Whitelist IP (dải CIDR)”** — mặc định `86.134.32.150/24`.
Sửa nếu dải IP quản trị của đơn vị khác. Cổng Direct IP mặc định `21118`.

**Bước 4.** Nhấn **“BẬT HỖ TRỢ TỪ XA”**. Phần mềm tự động thực hiện **4 bước**:

```
BƯỚC 1  Mở cổng TCP 21118 trong Windows Defender Firewall
         netsh advfirewall firewall add rule
           name="Danny RustDesk Direct IP TCP 21118"
           dir=in action=allow protocol=TCP localport=21118
           profile=any remoteip=86.134.32.150/24

BƯỚC 2  Ghi cấu hình Direct IP Access vào RustDesk2.toml
         %APPDATA%\RustDesk\config\RustDesk2.toml   (chế độ User)
         C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\
              RustDesk\config\RustDesk2.toml          (chế độ Service)

         [options]
         direct-server = 'Y'
         direct-access-port = '21118'
         enable-lan-discovery = 'N'
         whitelist = '86.134.32.150/24'
         approve-mode = 'click'
         verification-method = 'use-temporary-password'

BƯỚC 3  Tạo shortcut trên Desktop:
         "RustDesk - Bật hỗ trợ từ xa.lnk"
         Target: ...\tools\RustDesk\rustdesk.exe
         Args  : --server

BƯỚC 4  Cài RustDesk thành service + khởi động
         rustdesk.exe --install-service
         (ImagePath được trỏ lại về bản đã giải nén trong %LOCALAPPDATA%\rustdesk\)
         sc start RustDesk
         → đợi đến khi cổng 21118 thực sự lắng nghe (tối đa 15 giây)
```

**Bước 5.** Chờ thông báo **“DA SAN SANG NHAN KET NOI tren cong 21118”**.

**Bước 6.** Gửi cho người dùng: **IP** của bạn + **cổng 21118**.

> Nếu không nhận được kết nối: nhấn **“DỪNG / Dọn DẸP”** rồi **“BẬT HỖ TRỢ TỪ XA”** lại.

### 4.4. QUY TRÌNH B — Máy CẦN hỗ trợ (máy quân sự)

**Bước 1.** Mở tab → chọn **“MÁY CẦN HỖ TRỢ”**.

**Bước 2.** Nhập **IP máy kỹ thuật viên** vào ô bên trái.
Có thể nhập dạng `86.134.32.55` hoặc `86.134.32.55:21118` (nếu máy kia dùng cổng khác).
Nhập **mật khẩu** RustDesk nếu máy kia yêu cầu.

**Bước 3.** Nhấn **“BẬT HỖ TRỢ TỪ XA”**. Phần mềm tự động thực hiện **4 bước**:

```
BƯỚC 1  Mở cổng TCP 21118 trong Windows Defender Firewall

BƯỚC 2  Ghi cấu hình Direct IP Access vào RustDesk2.toml

BƯỚC 3  Cài RustDesk thành service (nếu có quyền Admin):
         rustdesk.exe --install-service
         sc start RustDesk
         (không có quyền Admin → chạy portable + cảnh báo nhẹ)

BƯỚC 4  Mở phiên kết nối trực tiếp:
         rustdesk.exe --connect <IP>:<Port> [--password <mật khẩu>]
```

**Bước 4.** Màn hình máy này sẽ hiện trên máy kỹ thuật viên trong vài giây.

> Nếu máy kia bật “Xin phép thủ công”, người dùng phải **bấm “Đồng ý”** trên cửa sổ
> RustDesk — đây là cơ chế xác nhận an toàn bắt buộc.

### 4.5. Xử lý sự cố

| Hiện tượng | Nguyên nhân | Khắc phục |
|---|---|---|
| “Không tìm thấy rustdesk.exe” | Thiếu thư mục `tools\RustDesk` | Chép lại đầy đủ `tools\RustDesk` từ bộ cài |
| “Cổng 21118 chưa sẵn sàng” | Firewall hoặc RustDesk chưa bind xong | Nhấn “DỪNG / Dọn DẸP” → “BẬT HỖ TRỢ TỪ XA” lại |
| “Không khởi động được service RustDesk” | Bản portable tự giải nén chưa bung xong | Chạy `rustdesk.exe --server` một lần cho nó bung file, rồi thử lại |
| Máy kia không thấy màn hình | Sai IP / sai cổng | Kiểm tra lại IP máy kỹ thuật viên và cổng ở cả 2 đầu |
| Kết nối bị từ chối | IP kỹ thuật viên không nằm trong whitelist | Thêm IP vào ô Whitelist (hoặc để trống) rồi chạy lại |
| RustDesk hiện “Not ready” đỏ | Bình thường khi offline Direct IP | **Không phải lỗi** — kết nối trực tiếp vẫn chạy |
| Không điều khiển được khi đã đăng xuất | Chưa cài service | Bật tùy chọn “Cài RustDesk thành service” |
| Không thao tác được cửa sổ UAC | Chạy Danny không có quyền Admin | Chạy lại Danny với quyền Administrator |

### 4.6. Bảo mật phiên làm việc

- **“Xin phép thủ công” luôn BẬT** — không bao giờ để truy cập tự do không xác nhận.
- **Whitelist IP** giới hạn chỉ IP/CIDR được phép kết nối; rule firewall cũng khoá theo
  `RemoteAddress` tương ứng → IP ngoài danh sách bị chặn ở **tầng firewall**, không vào tới RustDesk.
- **Mật khẩu RustDesk** dùng thay mật khẩu Windows; `verification-method =
  use-temporary-password` dùng mật khẩu tạm thời (đổi mỗi lần khởi động).
- **Chỉ dùng trong mạng nội bộ** của đơn vị; **không** mở cổng 21118 ra Internet / không
  forward cổng trên router.
- Sau khi hỗ trợ xong, nhấn **“DỪNG / Dọn DẸP”** để **dừng tiến trình RustDesk** và
  **xoá rule firewall** → không để hở cổng trên máy trạm.

---

## 5. CLI (chế độ không giao diện)

```
Danny-ver5.6.exe --remote-listen [--port 21118] [--whitelist "86.134.32.150/24"]
    :: Máy nhận kết nối — mở firewall, cấu hình Direct IP, tạo shortcut, chạy RustDesk

Danny-ver5.6.exe --remote-connect --ip 86.134.32.55 [--port 21118] [--whitelist "..."] [--no-service]
    :: Máy cần hỗ trợ — mở firewall, cấu hình Direct IP và mở phiên kết nối trực tiếp
```

| Cờ | Ý nghĩa |
|---|---|
| `--port <số>` | Cổng Direct IP (mặc định **21118**) |
| `--ip <địa chỉ>` | IP máy cần hỗ trợ (bắt buộc với `--remote-connect`) |
| `--whitelist "<dải>"` | Dải IP/CIDR được phép kết nối (mặc định `86.134.32.150/24`) |
| `--no-service` | Không cài RustDesk thành service (chỉ chạy khi đang đăng nhập) |

> **Lưu ý:** Phần CLI in ra **ASCII thuần** (đã bỏ dấu tiếng Việt) để hiển thị đúng
> trên mọi mã trang của Windows Console.

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

---

## 7. Ghi chú kỹ thuật

### 7.1. RustDesk 1.5.3 — thành phần

| Thành phần | Nguồn |
|---|---|
| `rustdesk.exe` | Bản phân phối chính thức `rustdesk-1.5.3-x86_64.exe` — giấy phép AGPL-3.0 |
| `hbbs.exe`, `hbbr.exe`, `rustdesk-utils.exe` | Bản phân phối chính thức `rustdesk-server-windows-x86_64-unsigned.zip` (v1.1.16) |

### 7.2. Cấu hình `RustDesk2.toml` — khối `[options]`

RustDesk tách cấu hình thành **3 file** (`hbb_common/src/config.rs`):

| File | Nội dung | Danny có sửa? |
|---|---|---|
| `RustDesk.toml` | `Config` — khoá, `enc_id` | **Không** |
| `RustDesk2.toml` | `Config2` — **khối `[options]`** | **Có** |
| `RustDesk_local.toml` | `LocalConfig` — giao diện | **Không** |

| Khoá | Giá trị mặc định | Ý nghĩa |
|---|---|---|
| `direct-server` | `Y` | Bật chế độ nhận kết nối trực tiếp qua IP |
| `direct-access-port` | `21118` | Cổng Direct IP Access |
| `enable-lan-discovery` | `N` | Tắt phát hiện trên LAN (chỉ dùng IP trực tiếp) |
| `whitelist` | `86.134.32.150/24` | Dải IP được phép (hỗ trợ CIDR, phân tách bằng dấu phẩy) |
| `approve-mode` | `click` | `click` = phải xin phép thủ công, `password`, `password-click` |
| `verification-method` | `use-temporary-password` | Loại mật khẩu được chấp nhận |

**Thư mục config theo chế độ chạy:**

| Chế độ | Đường dẫn |
|---|---|
| User | `%APPDATA%\RustDesk\config\RustDesk2.toml` |
| Service | `C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml` |

### 7.3. Lệnh dòng lệnh RustDesk đã dùng

| Lệnh | Ý nghĩa |
|---|---|
| `rustdesk.exe --server` | Chạy nền ở chế độ chia sẻ màn hình (mở listener Direct IP) |
| `rustdesk.exe --connect <IP>:<Port>` | Mở phiên kết nối trực tiếp tới IP:Port |
| `rustdesk.exe --connect <IP>:<Port> --password <pw>` | Kết nối kèm mật khẩu |
| `rustdesk.exe --install-service` | Cài Windows Service (tự chạy khi khởi động máy) |
| `rustdesk.exe --uninstall-service` | Gỡ Windows Service |
| `rustdesk-utils.exe genkeypair` | Sinh cặp khoá công khai/riêng cho server tự host |

> **Đã xác minh trong mã nguồn RustDesk** (`hbb_common/src/lib.rs`):
> `is_ipv4_str()` chấp nhận dạng `IP:port`, và `check_port()` giữ nguyên cổng đã chỉ định —
> nên `--connect <IP>:<Port>` là **đúng cú pháp**, không cần ID Server.
> Log xác nhận: `Direct server listening on: Some(Ok(0.0.0.0:21118))` và
> `direct access from <IP>:<ephemeral>`.

### 7.4. Xử lý Windows Service — điểm mấu chốt đã kiểm chứng

Hai điểm dễ sai khi cài RustDesk làm service trên bản portable:

1. **`--install-service` luôn ghi ImagePath là**
   `"C:\Program Files\RustDesk\RustDesk.exe"` kể cả khi chạy bản portable.
   → Danny tự **trỏ lại ImagePath** qua registry
   `HKLM\SYSTEM\CurrentControlSet\Services\RustDesk`.

2. **File `rustdesk.exe` đi kèm Danny là bản portable tự giải nén (25 MB).**
   Khi SCM khởi động nó, tiến trình bung file rồi **thoát ngay** → SCM báo
   **timeout 180 giây** và service không bao giờ chạy.
   → Danny trỏ ImagePath về **bản đã giải nén** (~386 KB) trong
   `%LOCALAPPDATA%\rustdesk\rustdesk.exe` (nơi có `librustdesk.dll` và các plugin).

### 7.5. Nhật ký & báo cáo

- Nhật ký thao tác nằm trong ô log màu xanh của tab.
- Cấu hình RustDesk có thể mở để kiểm tra:
  `%APPDATA%\RustDesk\config\RustDesk2.toml`.
- Rule firewall do phần mềm tạo có tên `Danny RustDesk Direct IP TCP <port>`.
- Log chi tiết của RustDesk: `%APPDATA%\RustDesk\log\server\rustdesk_rCURRENT.log`
  (tìm dòng `Direct server listening` và `direct access from`).

---

## 8. Kịch bản kiểm thử nhanh

```powershell
# 1. Mở/đóng cổng
Test-NetConnection -ComputerName 127.0.0.1 -Port 21118

# 2. Kiểm tra rule firewall
Get-NetFirewallRule -DisplayName "Danny RustDesk*"

# 3. Test tự động dọn rule firewall khi thoát app
#    → bấm "DỪNG / Dọn DẸP" → Get-NetFirewallRule -DisplayName "Danny RustDesk*" phải rỗng

# 4. Test kết nối giữa 2 máy khác phân mạng
#    Máy A (kỹ thuật viên): chọn MÁY NHẬN KẾT NỐI → BẬT HỖ TRỢ TỪ XA → chép IP
#    Máy B (quân sự):       chọn MÁY CẦN HỖ TRỢ → nhập IP của A → BẬT HỖ TRỢ TỪ XA
```

---

## 9. Thông tin liên hệ

| | |
|---|---|
| **Tác giả** | Trung tá Đoàn Danh Quyết — Trợ lý Công nghệ thông tin |
| **Đơn vị** | Bộ Chỉ huy Quân sự tỉnh Lâm Đồng |
| **Điện thoại** | 0366.714.139 |
| **Mã nguồn** | https://github.com/doandanhquyetqk7/Danny |
| **Theo dõi phiên bản** | https://github.com/users/doandanhquyetqk7/projects/1 |