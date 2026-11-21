# BÁO CÁO PHÂN TÍCH ĐẶC TẢ CHỨC NĂNG & THIẾT KẾ KIẾN TRÚC

## Phần mềm kiểm tra ATTT "KTATTT 2026" — Đề xuất tái thiết clean-room

| | |
|---|---|
| **Đối tượng phân tích** | `KTATTT_2026_V12` (`KTATTT_2026.exe` 144,58 MB · `KTATTT_NetworkAgent.exe` 112,25 MB) |
| **Phương pháp** | Phân tích tĩnh (decompile) — không chạy mẫu, không phân tích cơ chế bảo vệ bản quyền / làm rối mã |
| **Ngườn tham chiếu** | `Kiem tra ATTT/` — 1 963 file dữ liệu mẫu: **24 báo cáo JSON** trong `Data\AuditResults\`, 1 938 danh mục đơn vị/nhân sự, `last_audit_result.json`, `Data/config.json` |
| **Mã định danh case** | `20261121-164743-case` (scope: `auth.status=granted`, `network_profile=offline`) |
| **Chuẩn bằng chứng** | `work/attt/EVIDENCE.md` (E-001 → E-013) |

> **Ẩn danh dữ liệu (Rule 2):** mọi địa chỉ IP nội bộ, tên miền, tên đơn vị cụ thể,
> đường dẫn hệ thống nhạy cảm và khóa trong báo cáo này đều được thay bằng
> `[REDACTED]` hoặc mô tả trung tính. Các tên đơn vị trong mẫu báo cáo được loại bỏ hoàn toàn.

---

# PHẦN 1: TỔNG QUAN KIẾN TRÚC & MÔI TRƯỜNG VẬN HÀNH

## 1.1 Ngôn ngữ & nền tảng

| Thuộc tính | Giá trị | Bằng chứng |
|---|---|---|
| Ngôn ngữ | **C# / .NET 9.0** (`net9.0-windows`) | `deps.json` → `runtimeTarget: .NETCoreApp,Version=v9.0/win-x86` |
| Framework giao diện | **WPF** (Windows Presentation Foundation) | `PresentationFramework.dll`, `System.Xaml.dll`, `mainwindow.baml` |
| Thư viện UI | **MaterialDesignThemes 5.1.0** + `MaterialDesignColors 3.1.0` + `Microsoft.Xaml.Behaviors.Wpf` | `deps.json` |
| Kiểu đóng gói | **Single-file self-contained bundle** (.NET bundle **v6.0**) | Magic bundle tại offset `0x6A0830`, 402 file, `bundleId=mQYt7L5u…` |
| Kiểu cài đặt | **Portable** — chạy trực tiếp từ thư mục, không cần installer | Không có `setup.exe`/MSI; dữ liệu nằm cạnh exe trong `Data/` |
| Kích thước | 144,58 MB (self-contained, kéo theo runtime + SkiaSharp + OpenCvSharp) | Đo trực tiếp |
| Số file trong bundle | 400 assembly + deps.json + runtimeconfig.json | Manifest bundle v6.0 |

**Điểm đáng chú ý về kiến trúc:** bản đóng gói **nhúng toàn bộ runtime .NET 9** vào
một file exe. Đây là lựa chọn để triển khai trên máy quân sự không có sẵn .NET
Runtime — đánh đổi bằng dung lượng 144 MB.

## 1.2 Quyền thực thi

**Bắt buộc Administrator.** Cơ chế tự nâng quyền:

```csharp
// App.OnStartup — nếu không thuộc Administrators → relaunch với Verb="runas"
if (!new WindowsPrincipal(WindowsIdentity.GetCurrent())
        .IsInRole(WindowsBuiltInRole.Administrator))
{
    Process.Start(new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName)
        { UseShellExecute = true, Verb = "runas" });
    Application.Current.Shutdown();
    Environment.Exit(0);
}
```

Ngoài ra còn có một **mật khẩu quản trị ở mức giao diện** (`MỞ KHÓA ADMIN`) bảo vệ
khu vực "CÔNG CỤ NÂNG CAO" (Xóa Log / Truy vết Internet / Tìm tài liệu mật).

### Ma trận quyền theo từng chức năng

| Hạng mục | Cơ chế kỹ thuật | Quyền cần | Lý do |
|---|---|---|---|
| Security Log 4625 / 1102 | `EventLogQuery("Security")` | **Admin** | Windows chặn đọc Security log cho User |
| Sysmon / PowerShell / RDP channel | `EventLogQuery` trên `…/Operational` | **Admin** | Channel Operational yêu cầu quyền cao |
| SAM + nhóm Administrators | WMI `Win32_GroupUser`, `Win32_UserAccount` | **Admin** | SAM đọc qua WMI cần quyền |
| Phát hiện mật khẩu rỗng | P/Invoke `advapi32!LogonUser` | **Admin** | `LogonUser` với `LOGON32_LOGON_NETWORK` cần token quản trị |
| Registry HKLM (đọc/ghi) | `RegistryView.Registry64` | **Admin** (ghi) | HKLM là phân vùng bảo vệ |
| Trạng thái Defender | WMI `root\Microsoft\Windows\Defender` | **Admin** | Namespace Defender yêu cầu quyền |
| Bản sao SRUM | `esentutl.exe /y` | **Admin** | `SRUDB.dat` bị EFS khóa khi OS đang chạy |
| Ghi hệ thống file USB | `RtlAdjustPrivilege(9/17)` | **Admin** | Cần `SeRestorePrivilege`/`SeBackupPrivilege` |
| Xóa sâu Registry | `SetAccessControl` + `TakeOwnership` | **Admin** | Cần đổi quyền sở hữu khóa |
| Tạo Scheduled Task SYSTEM | `schtasks /ru SYSTEM /rl HIGHEST` | **Admin** | Task chạy dưới SYSTEM |
| Chạy `gpupdate /force` | `Process.Start` | **Admin** | Nạp lại Group Policy |
| Quét sâu tài liệu mật | `File.ReadAllText` / thư viện DOCX/XLSX/PDF | User | Chỉ đọc |
| Báo cáo Word/Excel | OpenXML / EPPlus / DocX | User | Chỉ đọc/ghi file đích |
| Đồng bộ danh mục đơn vị | HTTP → máy chủ nội bộ | User | HTTP thường |
| Đăng ký thiết bị FMS | HTTPS → máy chủ nội bộ | User | HTTPS thường |

> **Điểm thiết kế đáng chú ý:** phần lớn hạng mục *rà soát* chỉ cần quyền **đọc**,
> nhưng toàn bộ ứng dụng bắt buộc Admin ngay từ đầu — kể cả những tác vụ vốn chỉ
> cần quyền User. Đây là điểm cải tiến rõ ràng (xem Phần 6).

## 1.3 Khả năng hoạt động 100% offline

**Có — phần lõi kiểm toán là 100% cục bộ.** Kiểm chứng bằng bảng egress:

| Đích | Mục đích | Bắt buộc? | Hành vi khi mất kết nối |
|---|---|---|---|
| `http://[REDACTED-INTERNAL-HOST]` | Đồng bộ danh mục đơn vị / nhân sự | Không | `ApiSyncManager` trả về *"Sẽ sử dụng dữ liệu offline"* — dùng JSON cache cục bộ (TTL 30 ngày) |
| `https://[REDACTED-FMS-HOST]` | Đăng ký thiết bị vào hệ thống quản lý | Không | `CallDinhDanhApiAsync` bắt exception, ghi cảnh báo, **quét vẫn tiếp tục** |
| `netstat -ano`, `esentutl`, `wevtutil`, `gpupdate`, `schtasks`, `powershell.exe` | Tiện ích hệ thống | Nội bộ | — |
| Win32 WMI / EventLog / Registry | Thu thập dữ liệu | Nội bộ | — |

**Kết luận:** máy quét hoạt động độc lập hoàn toàn trong mạng nội bộ cô lập.
Hai kênh mạng duy nhất đều là *tùy chọn* và **fail-soft** (không chặn quy trình).

**Ngoại lệ:** ứng dụng *cố gắng* gọi mạng khi khởi động (`PerformInitialSync`).
Trong môi trường offline, bước này chỉ mất timeout (2 s cho `HEAD`, 15 s cho FMS) —
không ảnh hưởng độ chính xác kết quả.

## 1.4 Kiến trúc tổng thể

> **Sơ đồ kiến trúc** — bản đồ hoàn chỉnh: `Phan tich ATTT/So-do-kien-truc.png`
> (Nguồn Mermaid: `Phan tich ATTT/So-do-kien-truc.mmd` · Vector: `Phan tich ATTT/So-do-kien-truc.svg`)

![Sơ đồ kiến trúc đề xuất](So-do-kien-truc.png)

> **Luồng quét kiểm tra ATTT** — bản đồ hoàn chỉnh: `Phan tich ATTT/Luong-quet-ATTT.png`
> (Nguồn Mermaid: `Phan tich ATTT/Luong-quet-ATTT.mmd` · Vector: `Phan tich ATTT/Luong-quet-ATTT.svg`)

![Luồng quét kiểm tra ATTT](Luong-quet-ATTT.png)

```
┌──────────────────────────────────────────────────────────────────────┐
│  KTATTT_2026.exe  (single-file bundle, .NET 9 WPF, 144 MB)         │
│  ┌────────────────────────────────────────────────────────────────┐  │
│  │ App.xaml / MainWindow.xaml  (MaterialDesign, dark theme)       │  │
│  │  ├─ ViewDashboard ─ ViewKTATTT ─ ViewKTATTT ─ ViewSettings    │  │
│  └────────────────────────────────────────────────────────────────┘  │
│         │                                                          │
│         ├── RunScanPhase(i)  ──►  Phase1..Phase7Auditor             │
│         │      (Task.Run → không block UI)                         │
│         │      trả về ScanResponse { Logs, PenaltyPoints,           │
│         │                        Alerts, Vulnerabilities,           │
│         │                        AIFeatures }                        │
│         │                                                          │
│         ├── SaveResultToJson()  ──►  Data/AuditResults/*.json      │
│         ├── ExportWordReport()  ──►  BienBan_KTATTT_*.docx         │
│         │      (Template_Docx_Moi.docx + thay [PLACEHOLDER])       │
│         ├── UploadResultToServerAsync()   ──►  HTTP (optional)     │
│         ├── CallDinhDanhApiAsync()         ──►  FMS  (optional)    │
│         └── NetworkMonitorService.AutoInstallService()             │
│                └─► schtasks: KTATTT_NetworkMonitorService         │
│                      └─► KTATTT_NetworkAgent.exe --background      │
│                            └─► Ping 8.8.8.8 mỗi 10s                │
│                                └─► nếu Online: Disable-NetAdapter  │
└──────────────────────────────────────────────────────────────────────┘
```

---

# PHẦN 2: DANH MỤC CHI TIẾT CÁC HẠNG MỤC KIỂM TRA ATTT

> Ghi chú ký hiệu dùng trong bảng:
> **Đ** = Đạt · **K** = Không đạt · **C** = Cảnh báo
> Mỗi hạng mục đều kèm **điểm trừ** (`PenaltyPoints`) vì phần mềm gốc dùng cơ chế
> trừ điểm, không dùng trạng thái 3-trạng-thái độc lập.

## 2.1 NHÓM A — Thông tin hệ thống & Bản vá

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| A1 | HĐH & Bản vá | Hệ điều hành đã hết hạn hỗ trợ (EOL) | Không dùng OS ngừng hỗ trợ có lỗ hổng chưa vá | WMI `Win32_OperatingSystem` → `Caption`; so khớp danh sách EOL: Windows 7/8/8.1, Server 2008/2012, XP | **Đ** = không khớp EOL → **C** (trừ 1) nếu khớp |
| A2 | HĐH & Bản vá | Thiếu bản vá bảo mật / bản vá cũ | Chống Ransomware, khai thác CVE đã biết | WMI `Win32_QuickFixEngineering` → `InstalledOn`, `HotFixID`; ngưỡng **90 ngày** | **Đ** = có ≥1 hotfix và ≤90 ngày → **C/K** (trừ 1) nếu 0 hotfix hoặc >90 ngày |
| A3 | HĐH & Bản vá | Lịch sử Windows Update (bổ trợ) | Truy vết đã từng kết nối máy chủ Microsoft | PowerShell `Get-HotFix`; Registry `…\WindowsUpdate\Auto Update\Results\Install!LastSuccessTime` | Chỉ ghi nhận, không trừ điểm |
| A4 | Danh mục phần mềm | Phát hiện phần mềm bẻ khóa / lậu | Ràng buộc bản quyền phần mềm trong đơn vị | Enum tiến trình + tên service + Registry Run/RunOnce: `kmspico, autokms, crack, patch, keygen, activator` | **Đ** = 0 phát hiện → ghi `AIFeatures["CrackSoftwareCount"]`, không trừ điểm riêng |
| A5 | HĐH | Ảo hóa (VM) — ghi nhận | Nhận diện máy ảo có thể né tránh kiểm tra | Whitelist service có `vmware`, `virtualbox` → được bỏ qua (không cảnh báo) | Chỉ ghi nhận |

## 2.2 NHÓM B — Phòng chống mã độc

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| B1 | Giải pháp ATTT | **Windows Firewall bị tắt** | Bảo vệ biên mạng nội bộ | Registry HKLM `…\Services\SharedAccess\Parameters\FirewallPolicy\{Standard,Public,Domain}Profile!EnableFirewall` | **Đ** = cả 3 profile = 1 → **K** (trừ 3) nếu bất kỳ profile nào = 0 |
| B2 | Giải pháp ATTT | **Không có phần mềm diệt virus nào** | Bắt buộc có AV chuyên dụng (MiAV) hoặc Defender | Quét tiến trình `MiAV*`, `nextav*`; WMI `root\Microsoft\Windows\Defender!MSFT_MpComputerStatus!AMServiceEnabled` | **Đ** = có ≥1 AV đang chạy → **K** (trừ 3) nếu cả 3 đều tắt |
| B3 | Giải pháp ATTT | CSDL (chữ ký virus) quá hạn | Mẫu nhận diện phải mới | WMI `AntivirusSignatureLastUpdated`; ngưỡng **7 ngày** | **Đ** = ≤7 ngày → **C** (trừ 1) nếu >7 ngày *(chỉ khi Defender là AV duy nhất)* |
| B4 | Mã độc | **Tập tin thực thi trong `%TEMP%`** | Phát hiện dropper/unpacker sơ khai | `Directory.GetFiles(Path.GetTempPath())`; lọc đuôi `.exe .bat .ps1 .vbs .dll` | Heuristic 4 trọng số: ẩn/hệ thống **+40**; tạo <72h **+35**; tên giả mạo file hệ thống **+50**; tên DGA (≥6 ký tự, có số + chữ thường) **+20**. ≥50 → **K**; còn lại → **C** |
| B5 | Mã độc | Công cụ bẻ khóa phần mềm trong Temp | Ràng buộc bản quyền | Tên file chứa `crack` / `patch` / `bypass` | Ghi `CrackSoftwareCount`, không trừ riêng |
| B6 | Mã độc | Tiến trình nhạy cảm qua Sysmon | Phát hiện dùng công cụ tải/khôi phục dữ liệu từ xa | Event Log `Microsoft-Windows-Sysmon/Operational`, EventID=1 (Process Creation), 30 ngày, tối đa 1 000 bản ghi | Lệnh chứa `powershell.exe`/`cmd.exe`/`vssadmin`/`certutil`/`bitsadmin` mà **không** nằm trong whitelist → **C**. Trọng số: `vssadmin+delete` +2, `certutil+urlcache|-f` +2, `-enc`/`encodedcommand`/`bypass` +1 |
| B7 | Mã độc | PowerShell thực thi ngầm | Phát hiện script obfuscate | Event Log `Microsoft-Windows-PowerShell/Operational`, EventID=4104, 30 ngày | **Đ** = 0 script → **C** nếu >0 |

## 2.3 NHÓM C — Tài khoản & Chính sách bảo mật cục bộ

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| C1 | Tài khoản | **Tài khoản Guest đang bật** | Chặn truy cập trái phép không cần xác thực | WMI `Win32_UserAccount` (`LocalAccount=True`) → `Name`, `Disabled` | **Đ** = Guest bị disable → **C** (trừ 1) nếu Guest đang bật |
| C2 | Tài khoản | **Admin có mật khẩu rỗng** | Chặn leo thang đặc quyền không cần mật khẩu | P/Invoke `advapi32!LogonUser(user, machine, "", LOGON32_LOGON_NETWORK)` → thành công = mật khẩu rỗng; chỉ xét user thuộc nhóm Administrators | **Đ** = không admin nào rỗng → **C** (trừ 1) nếu có |
| C3 | Tài khoản | **Tài khoản ẩn có quyền Administrators** | Phát hiện backdoor duy trì quyền | WMI `Win32_GroupUser` (nhóm Administrators) ∩ WMI `Win32_UserAccount` ∩ Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList` (giá trị DWORD = 0 = ẩn) hoặc tên kết thúc bằng `$` | **Đ** = 0 tài khoản ẩn → **K** (trừ 3) nếu có |
| C4 | Chính sách | **UAC bị tắt** (`EnableLUA=0`) | Bảo vệ chống leo thang đặc quyền tự động | Registry HKLM 64-bit `…\Policies\System!EnableLUA` | **Đ** = UAC bật → **K** (trừ 3) nếu tắt |
| C5 | Chính sách | **SMBv1 đang bật** | Chặn EternalBlue / WannaCry | Registry HKLM 64-bit `…\Services\LanmanServer\Parameters!SMB1` = 1 | **Đ** = SMB1 tắt → **K** (trừ 3) nếu bật |
| C6 | Chia sẻ | Cổng SMB (445) mở public | Hạn chế lateral movement | `IPGlobalProperties.GetActiveTcpListeners()` — cổng 445/3389 gắn `0.0.0.0` hoặc `[::]` | **Đ** = không mở public → **C** (trừ 1) nếu mở |
| C7 | Chia sẻ | Cổng RDP (3389) mở public | Giảm bề mặt tấn công brute-force | Như C6 | **Đ** = không mở public → **C** (trừ 1). Nếu đang có phiên RDP `Established` → severity **CRITICAL**, `RemoteControlFound = 2` |
| C8 | Chia sẻ | Phiên RDP đang hoạt động (báo động đỏ) | Phát hiện đang bị điều khiển | `GetActiveTcpConnections()` — `LocalEndPoint.Port==3389 && State==Established` → ghi IP nạn nhân + IP kẻ truy cập | **K** (severity CRITICAL) nếu phát hiện |
| C9 | Hoạt động | Hoạt động ngoài giờ (0h–5h) | Phát hiện tiến trình ngầm tự khởi động | Event Log `System`, EventID=6005 (Event Log service start), 7 ngày | **Đ** = ≤3 lần → **C** nếu >3 lần |
| C10 | Dấu vết | Nhật ký an ninh bị xóa (Event 1102) | Phát hiện che giấu dấu vết | Event Log `Security`, EventID=1102 | **Đ** = không có 1102 → **K** (severity CRITICAL) nếu có |
| C11 | Dấu vết | Brute-force đăng nhập | Phát hiện dò mật khẩu | Event Log `Security`, EventID=4625, cửa sổ theo `config.json!LogTimeValue` | **Đ** = ≤50 lần → **C** (trừ 1) nếu >50 lần |
| C12 | Hoạt động | Hoạt động bất thường theo giờ (Event Log) | Phát hiện lệch giờ so với quy tắc 5h–22h | Event 4625/1102 → đếm sự kiện ngoài khung giờ 5h–22h | Ghi `OddHourActivityCount`, không trừ riêng |

## 2.4 NHÓM D — Cấu hình mạng & Tường lửa

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| D1 | Kết nối | **Kết nối TCP ra ngoài nội bộ** | Phát hiện lộ lọt ra Internet | `GetActiveTcpConnections()` — state `Established`; loại trừ prefix `127.0.0.1`, `::1`, `86.`, `172.`, `86.128.`, `86.0.` | **Đ** = 0 kết nối ngoài → **K** (trừ 3) nếu >0 |
| D2 | Kết nối | **Kết nối tới máy chủ C&C** | Phát hiện backdoor / cryptominer | Kết hợp `netstat -ano` (map PID) + `GetActiveTcpConnections()`; state `Established`/`SynSent`; IP **không** thuộc dải nội bộ | **K** (severity CRITICAL, trừ 3) nếu trùng **blacklist IP** hoặc **cổng độc hại**: `4444, 1337, 31337, 6667, 4445, 3333, 5555, 7777` |
| D3 | Kết nối | Phiên quản trị hướng ngược (SSH/RDP ra ngoài) | Phát hiện reverse tunnel / bàn đạp | Như D2; cổng đích `22` hoặc `3389` ra IP công cộng | **C** (trừ 1) nếu phát hiện |
| D4 | Kết nối | Phiên RDP đã truy cập (30 ngày) | Truy vết điều khiển từ xa | Event Log `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`, EventID=21, 30 ngày; lấy `Properties[2]` làm IP nguồn | **K** (severity CRITICAL, trừ 3) nếu >0 |
| D5 | Thẻ mạng | Card mạng / Wi-Fi / Bluetooth | Kiểm kê phần cứng mạng | `NetworkInterface.GetAllNetworkInterfaces()`; lọc `OperationalStatus.Up`, loại Loopback | Ghi nhận; hiển thị IP + MAC trên Dashboard |
| D6 | Dấu vết | Lịch sử hồ sơ mạng (SSID) | Truy vết máy đã từng vào mạng nào | Registry HKLM `…\NetworkList\Profiles\*!ProfileName` | Ghi nhận; không trừ điểm |
| D7 | Dấu vết | Tham số TCP/IP theo interface | Truy vết cấu hình IP/Gateway/DNS đã dùng | Registry HKLM `…\Tcpip\Parameters\Interfaces\*` → `DhcpIPAddress`, `DhcpDefaultGateway`, `DhcpNameServer`, `LeaseObtainedTime` | Ghi nhận; không trừ điểm |
| D8 | Card mạng | Ghi nhận card ảo | Phân biệt card vật lý vs ảo (VMware/VPN/VirtualBox) | Whitelist tên card `vmware, virtualbox, intel, amd, nvidia, realtek…` | Bỏ qua (không cảnh báo) |

## 2.5 NHÓM E — Thiết bị ngoại vi & Lưu trữ

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| E1 | USB | Lịch sử cắm USB lưu trữ | Kiểm kê thiết bị đã từng cắm | Registry HKLM `SYSTEM\CurrentControlSet\Enum\USBSTOR\*` — 2 cấp (Vendor&Product → Serial) | Ghi `TotalUsbCount`; không trừ điểm |
| E2 | USB | **USB lưu trữ chưa được duyệt** | Phát hiện thiết bị lạ | So tên/serial với whitelist: `Kingston DataTraveler`, `SanDisk Cruzer`, `[REDACTED-VID-PID]` | Ghi `UnfamiliarUsbCount`; không trừ điểm *(xem E-6 cải tiến)* |
| E3 | USB | **USB Wi-Fi (card mạng không dây)** | Chặn thiết bị bypass chính sách mạng | Registry HKLM `SYSTEM\CurrentControlSet\Enum\USB\*` — `Class == "Net"` **AND** tên chứa `wireless, wi-fi, wifi, wlan, 802.11` | **K** (severity CRITICAL, trừ 3) nếu ≥1 |
| E4 | USB | **Điện thoại / Tablet / USB Tethering** | Chặn dùng 4G/5G để chia sẻ mạng | Registry `Enum\USB\*` — tên chứa `iphone, ipad, apple mobile, samsung, oppo, xiaomi, redmi, vivo, realme, huawei, nokia, vsmart, android, rndis, tethering` | **K** (severity CRITICAL, trừ 3) nếu ≥1 |
| E5 | USB | Tần suất cắm thiết bị (7 ngày) | Phát hiện rò rỉ dữ liệu qua USB | Event Log `System`, provider `Microsoft-Windows-Kernel-PnP`, EventID 400/410, 7 ngày | Ghi `UsbPlugFrequency7Days`; không trừ điểm |
| E6 | Chính sách USB | Chính sách khóa cổng USB | Chặn cắm thiết bị lưu trữ | Registry `SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions` + `DenyDeviceIDs` | **Không được kiểm tra trong bản gốc** *(xem Phần 6 — cải tiến)* |

## 2.6 NHÓM F — Tiến trình, Persistence & Chữ ký số

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| F1 | Persistence | **Scheduled Task chạy từ thư mục rác** | Phát hiện Task Scheduler persistence | Đọc file trong `%SystemRoot%\System32\Tasks` (XML); `<Command>` chứa `\Temp\`, `\AppData\`, `Users\Public` hoặc `Invoke-WebRequest`; loại trừ task Microsoft hợp lệ (OneDrive, EdgeUpdate, Teams, Squirrel, GoogleUpdate, BraveUpdate) | **K** (severity CRITICAL, trừ 3) nếu ≥1 |
| F2 | Persistence | **Registry Run trỏ tới `%TEMP%`** | Phát hiện startup persistence | HKLM + HKCU: `…\CurrentVersion\Run`, `RunOnce` (+ WOW6432Node); giá trị chứa `\Temp\` hoặc `\AppData\Local\Temp` | **K** (severity CRITICAL, trừ 3) nếu ≥1 |
| F3 | Persistence | **Service LocalSystem không có chữ ký số** | Phát hiện mã độc mạo danh dịch vụ | WMI `Win32_Service` (Running/Stopped) → `StartName`, `PathName`; điều kiện: chạy LocalSystem **AND** file ngoài `%WINDIR%` **AND** file tồn tại **AND** `X509Certificate.CreateFromSignedFile` thất bại | **C** (severity WARNING) nếu ≥1 |
| F4 | Leo thang | **Unquoted Service Path** | Chặn chèn tệp thực thi trùng tên | `PathName` không bắt đầu bằng `"` **AND** chứa khoảng trắng trước `.exe` | **C** (severity WARNING) nếu ≥1 |
| F5 | C2 | **Phần mềm điều khiển từ xa** | Chặn TeamViewer/AnyDesk/VNC… | Enum tiến trình + tên/path service + Registry Run + Task command: `teamviewer, anydesk, ultraviewer, radmin, vncserver, logmein` (+ service: `ngrok`, `rustdesk`) | Ghi `RemoteControlFound = 1`; **không trừ điểm riêng** |
| F6 | Sysmon | Cấu hình & triển khai Sysmon | Bảo đảm có nguồn dữ liệu tiến trình | `SysmonConfigurator.DeployOrUpdateSysmon()` — `Sysmon64.exe -i config.xml -accepteula` hoặc `-c config.xml`; phát hiện service qua Registry `…\Services\Sysmon64` / `Sysmon` | Ghi nhận; không trừ điểm |

## 2.7 NHÓM G — Tệp tin, Trình duyệt & Nhật ký hệ thống

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| G1 | Tài liệu mật | **Tài liệu chứa nội dung mật** | Rà soát lưu trữ tài liệu mật sai quy định | Quét đệ quy mọi ổ cứng (`DriveType.Fixed`, `IsReady`), bỏ qua `C:\Windows`, `C:\Program Files`, `C:\Program Files (x86)`, `C:\ProgramData` | **Đ** = 0 tệp → **C** nếu ≥1 tệp. Match = tên file chứa keyword **OR** (quét sâu) nội dung file chứa keyword |
| G2 | Tài liệu mật | Quét sâu nội dung tài liệu | Phát hiện keyword bên trong file, không chỉ tên | `.pdf` (PdfPig, 3 trang đầu) · `.docx` (DocX) · `.xlsx` (EPPlus, bỏ sheet ẩn) · `.txt` (StreamReader, `FileShare.ReadWrite`) — bỏ qua file >20 MB | Như G1 |
| G3 | Tài liệu mật | Phát hiện con dấu đỏ trong ảnh | Phát hiện tài liệu đã đóng dấu (rủi ro rò rỉ) | OpenCV: BGR→HSV, `InRange` đỏ (H 0–12 ∪ 165–180, S≥50, V≥40), morphological open 5×5, `FindContours`; diện tích contour ∈ [0,15 % × 0,5 %] ảnh, tỷ lệ khung ∈ [0,5; 2,0] | Ghi nhận; không trừ điểm |
| G4 | Trình duyệt | **Dấu vết tải tệp từ Internet** (Zone.Identifier) | Truy vết nguồn gốc tệp tải về | PowerShell `Get-Item -Stream Zone.Identifier` trên `Downloads\` + `Desktop\`; `ZoneId=3` → in `HostUrl`/`ReferrerUrl` | Ghi nhận; không trừ điểm |
| G5 | Trình duyệt | Tệp tải dở (`.crdownload`) | Phát hiện tải dở dang dấu | `Directory.GetFiles(path, "*.crdownload")` | Ghi nhận |
| G6 | Trình duyệt | Dấu vết sử dụng trình duyệt | Phát hiện lịch sử truy cập | Chrome / Edge / Cốc Cốc / Firefox — `History` (>20 KB), `Cookies` (>15 KB), `places.sqlite` (>5 MB), `cookies.sqlite` (>530 KB), cache (>15 file) | Ghi nhận; không trừ điểm |
| G7 | Hệ thống | **SRUM — lịch sử sử dụng tài nguyên mạng** | Truy vết lịch sử upload/download theo ứng dụng | `esentutl.exe /y "C:\Windows\System32\sru\SRUDB.dat" /d "%TEMP%\SRUDB_ForensicCopy.dat" /o`; cảnh báo nếu bản sao >1 MB; **xoá bản sao sau khi đo** | Ghi nhận; không trừ điểm |
| G8 | Hệ thống | Xóa sạch nhật ký Event Log | Vệ sinh dấu vết | `wevtutil el` → `wevtutil cl <từng log>` qua `cmd.exe` | Nằm ở chức năng "Xóa Log", không phải hạng mục kiểm tra |

## 2.8 NHÓM H — Tài liệu quản lý & Dấu vết số (Module dọn dẹp)

| STT | Nhóm | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc | Điều kiện Đ / K / C |
|---|---|---|---|---|---|
| H1 | Dọn dẹp | Xóa tệp rác | Giảm bề mặt phát hiện | `%TEMP%`, `C:\Windows\Temp`, `C:\Windows\Prefetch`, `C:\Windows\SoftwareDistribution\Download` | Báo cáo số file xoá / bỏ qua (đang khóa) |
| H2 | Dọn dẹp | **Xóa sâu lịch sử USB** | Xóa dấu vết cắm USB | `RtlAdjustPrivilege` → xoá `Enum\USBSTOR`, `Enum\USB`, `DeviceClasses\{53f56307…}`, `{53f5630d…}`, `{10497b1b…}`; `MountedDevices` (trừ `\DosDevices\C:`); `EMDMgmt`; `Windows Portable Devices\Devices`; `MountPoints2` (trừ `CPC`); xoá `C:\Windows\inf\setupapi.*.log` | Dùng `SetAccessControl` + `TakeOwnership` để xoá khóa đặc quyền |
| H3 | Dọn dẹp | **Xóa lịch sử trình duyệt** | Xóa History/Cache | Kill `chrome`, `msedge`, `browser`, `firefox`; xoá `History`, `Cache` (Chrome/Edge/Cốc Cốc), `places.sqlite` (Firefox) | — |
| H4 | Dọn dẹp | **Tiêu diệt MiAV / AgentFMC** | Xóa hoàn toàn dấu vết EDR nội bộ | `sc stop` + `sc config start= disabled` + `sc delete` cho `Defense`, `MiAVProtect`, `MiAVUpdate`, `MiAVWD`; kill 10 tiến trình (`MiAV`, `SerDefense`, `nextav`, `AgentFMC`…); xoá `C:\Users\Public\Documents\AgentFMC` + `C:\Users\Public\Pictures` | Xoá thư mục con **trước** (sort theo độ dài giảm dần) để tránh khóa |
| H5 | Chính sách | **Chặn chia sẻ mạng qua USB** (GPO) | Chặn 4G/5G tethering | Registry `…\DeviceInstall\Restrictions!DenyDeviceIDs=1`, `DenyDeviceIDsRetroactive=1`; `DenyDeviceIDs\1..20` = 20 Hardware ID cấm (USB CDC, RNDIS, modem OEM) → `gpupdate /force` | Có `RemoveBlockPolicy()` để gỡ |
| H6 | Giám sát | **Agent giám sát mạng nền** | Chặn máy kết nối Internet | `schtasks` task `KTATTT_NetworkMonitorService` (`/sc onstart /ru SYSTEM /rl HIGHEST`) chạy `KTATTT_NetworkAgent.exe --background`; agent poll `8.8.8.8` mỗi 10 s → nếu Online thì `Disable-NetAdapter` mọi card `Status=Up` | Dùng `MessageBoxOptions.ServiceNotification` để hiện cảnh báo ở session khác |

---

# PHẦN 3: CƠ CHẾ KỸ THUẬT THU THẬP DỮ LIỆU (CHUẨN WINDOWS)

## 3.1 Bảng mapping hạng mục → nguồn dữ liệu

| Nhóm | Registry Keys | WMI (namespace / query) | Event Log channel + EventID | Win32 API | Lệnh shell |
|---|---|---|---|---|---|
| **A. HĐH & Bản vá** | — | `Win32_OperatingSystem` (Caption, Version) · `Win32_QuickFixEngineering` (InstalledOn, HotFixID) | — | `Environment.OSVersion` | `Get-HotFix` (PowerShell) |
| **B. Phòng chống mã độc** | `…\FirewallPolicy\*Profile!EnableFirewall` | `root\Microsoft\Windows\Defender` → `MSFT_MpComputerStatus` (AMServiceEnabled, AntivirusSignatureLastUpdated) | `Security` (4625, 1102) · `Microsoft-Windows-Sysmon/Operational` (1) · `Microsoft-Windows-PowerShell/Operational` (4104) | `Process.GetProcesses()` · `FileInfo.Attributes/CreationTime` · `X509Certificate.CreateFromSignedFile` | — |
| **C. Tài khoản & chính sách** | `…\Policies\System!EnableLUA` · `…\LanmanServer\Parameters!SMB1` · `…\Winlogon\SpecialAccounts\UserList` | `Win32_GroupUser` (GroupComponent) · `Win32_UserAccount` (LocalAccount=True) · `Win32_SystemEnclosure` (ChassisTypes) | `System` (6005) | **`advapi32!LogonUser`** (P/Invoke) | — |
| **D. Mạng** | `…\NetworkList\Profiles\*!ProfileName` · `…\Tcpip\Parameters\Interfaces\*` | — | `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational` (21) | `IPGlobalProperties.GetActiveTcpConnections/GetActiveTcpListeners` · `NetworkInterface.GetAllNetworkInterfaces` | `netstat -ano` |
| **E. USB & ngoại vi** | `SYSTEM\CurrentControlSet\Enum\USBSTOR\*` · `…\Enum\USB\*` (Class, DeviceDesc, FriendlyName) | — | `System` / `Microsoft-Windows-Kernel-PnP` (400, 410) | `DriveInfo.GetDrives()` | — |
| **F. Persistence** | `…\CurrentVersion\Run`, `RunOnce` (+WOW6432Node) · `…\DeviceInstall\Restrictions` | `Win32_Service` (Name, PathName, StartName) | — | `Process.Start` (schtasks) · `X509Certificate` | `schtasks /create /run` · `gpupdate /force` |
| **G. Tệp & trình duyệt** | `…\WindowsUpdate\Auto Update\Results\Install!LastSuccessTime` | — | — | `DriveInfo` · `Directory.GetFiles` · `PdfDocument.Open` · `DocX.Load` · `ExcelPackage` · `OpenCvSharp` (`Cv2.*`) | `esentutl.exe /y` · `powershell.exe -Stream Zone.Identifier` |
| **H. Dọn dẹp** | `…\Enum\USB*`, `MountedDevices`, `EMDMgmt`, `MountPoints2` | — | `Security` / `System` / `Application` (qua `wevtutil el` + `cl`) | **`ntdll!RtlAdjustPrivilege`** · `RegistrySecurity` / `SetAccessControl` | `wevtutil` · `cmd.exe /c sc stop|config|delete` |

## 3.2 Các trường hợp ngoại lệ được xử lý

### 3.2.1 Phân tầng Windows

| Tình huống | Xử lý trong bản gốc |
|---|---|
| Windows 7 / XP / Server 2008 | Bị đánh dấu EOL (hạng mục A1). Các API dùng (`EventLogReader`, `EventLogQuery`) chỉ có từ .NET 3.5+ nhưng yêu cầu Windows Vista+ — **chạy được nhưng không hỗ trợ đầy đủ** |
| Windows 8 / 8.1 / Server 2012 | EOL. `Win32_QuickFixEngineering` vẫn hoạt động |
| Windows 10 / 11 / Server 2016+ | Đường chính — đầy đủ tính năng |
| **Server (không có Explorer)** | `MessageBoxOptions.ServiceNotification` trong Agent giải quyết việc hiện thông báo ở session 0 / session khác |
| **Defender bị gỡ hoàn toàn** | `ManagementObjectSearcher` trên `root\Microsoft\Windows\Defender` ném exception → bắt và ghi log `[INFO]`, không crash |

### 3.2.2 Quyền / môi trường thực thi

| Tình huống | Xử lý |
|---|---|
| Không có quyền Admin | `App.OnStartup` tự nâng quyền qua `Verb="runas"`. Nếu user từ chối UAC → `Shutdown()` + `Exit(0)` |
| Security Log bị chặn | `catch (UnauthorizedAccessException)` → log `[TỪ CHỐI TRUY CẬP] Security Log yêu cầu quyền Admin…` |
| Không tìm thấy Event Log channel | `catch (EventLogNotFoundException)` → log `[INFO] Bỏ qua quét Sysmon: Máy tính này không cài đặt dịch vụ Sysmon` |
| Registry bị khóa / không đọc được | `catch` rỗng ở hầu hết nơi — **im lặng bỏ qua**, có thể gây báo cáo thiếu hạng mục mà không cảnh báo |
| `UnauthorizedAccessException` khi quét thư mục Temp | `catch (UnauthorizedAccessException)` → log yêu cầu Run as Administrator |
| Dịch vụ WMI bị tắt | `catch (Exception)` bao trùm → phần lớn hạng mục WMI sẽ im lặng bỏ qua |
| `X509Certificate.CreateFromSignedFile` thất bại | Trả `false` → coi như **không có chữ ký** (đây là hành vi đúng cho file unsigned, nhưng cũng áp dụng cho file bị hỏng/không đọc được) |

### 3.2.3 Đặc thù dữ liệu

| Tình huống | Xử lý |
|---|---|
| SRUDB.dat bị OS khóa | `esentutl /y` tạo bản sao pháp y; nếu thất bại → log `[LỖI] Không thể trích xuất SRUDB.dat. Nguyên nhân có thể do thiếu quyền Administrator` |
| Event Log rỗng / bị xoá sạch | `EventLogReader` trả `null` ngay → vòng lặp kết thúc, điểm số không bị trừ (có thể **che giấu** hành vi xoá log nếu đã bị xoá trước khi quét) |
| Nhiều card mạng | `MainWindow` lấy card đầu tiên `OperationalStatus.Up` **không phải Loopback** và có IPv4 |
| Card mạng ảo | Whitelist tên card → bỏ qua cảnh báo |
| File >20 MB khi quét tài liệu | Bỏ qua (`ScanFileContent` trả `null`) — tránh treo máy |
| File .xlsx có sheet ẩn | Bỏ qua sheet `Hidden != 0` |
| PDF nhiều trang | Chỉ đọc **3 trang đầu** |
| Thư mục không truy cập được khi quét đệ quy | `GetFilesSafe` (iterator triển khai thủ công) bỏ qua nhánh, không ném exception |
| Folder bắt đầu bằng `$` (ẩn) hoặc `System Volume Information` | Bỏ qua khi duyệt thư mục con |
| `netstat` không chạy được | `catch` rỗng → `dictionary` rỗng → hiển thị `[System hoặc Ẩn] (PID: n)` thay vì tên tiến trình |

## 3.4 Ghi chú về hiệu năng

- Mỗi hạng mục chạy trong `await Task.Run(...)` → **không block UI**.
- `MainWindow` giới hạn `await Task.Delay(100)` giữa các dòng log (chỉ ở chế độ **không** silent) → tạo hiệu ứng "gõ từng dòng", có thể làm quét chậm thêm vài giây.
- Sysmon giới hạn **1 000 bản ghi** — tránh quét quá lâu trên máy bận.
- Truy vết Internet có `process.WaitForExit(5000)` — **timeout cứng 5 s** cho mỗi lệnh PowerShell.
- Truy vết Internet truy cập `NetworkProfiles` + `Interfaces` — có thể chậm với nhiều interface.

---

# PHẦN 4: LOGIC TỔNG HỢP, CHẤM ĐIỂM & XUẤT BÁO CÁO

## 4.1 Mô hình chấm điểm

```
_finalScore = 100
mỗi phase:  _finalScore -= scanResponse.PenaltyPoints
             nếu _finalScore < 0 → _finalScore = 0
cuối:        TotalScore = _finalScore
```

### Bảng trừ điểm đầy đủ

| Phase | Hạng mục | Trừ điểm |
|---|---|---|
| 1 | File thực thi trong Temp | `2 × (nguy hiểm) + 1 × (nhẹ)`, **cap 5** |
| 1 | Brute-force (>50 lần 4625) | 1 |
| 1 | Kết nối TCP ra ngoài nội bộ | 3 |
| 1 | PowerShell script ngầm (Event 4104) | `min(count/5, 3)` qua `SuspiciousTaskCount` |
| 1 | Sysmon tiến trình nhạy cảm | `min(count, 3)` |
| 1 | USB Wi-Fi | 3 |
| 1 | Điện thoại / tethering | 3 |
| 2 | Tài khoản ẩn có quyền Admin | 3 |
| 2 | Guest bật **hoặc** Admin mật khẩu rỗng | 1 |
| 3 | Firewall tắt | 3 |
| 3 | Không có AV nào | 3 |
| 3 | CSDL Defender quá hạn (>7 ngày) | 1 |
| 4 | OS EOL | 1 |
| 4 | Bản vá cũ (>90 ngày) | 1 |
| 5 | UAC tắt | 3 |
| 5 | SMBv1 bật | 3 |
| 5 | Cổng 445/3389 mở public | 1 |
| 6 | Scheduled Task khả nghi | 3 |
| 6 | Registry Run → %TEMP% | 3 |
| 7 | Kết nối C&C (blacklist IP / cổng độc hại) | 3 |
| 7 | Phiên SSH/RDP hướng ngược | 1 |

**Tổng trừ tối đa thực tế:** mỗi phase tự cap `Math.Min(num, 5)` → trần **35 điểm** → điểm thấp nhất **65**.

> ⚠️ **Hạn chế thiết kế cần lưu ý:** vì mỗi phase cap 5, một máy có **nhiều lỗi nghiêm trọng** vẫn có thể đạt điểm cao. Ngưỡng phân loại 90/75 vì vậy khá "nhân ái".

## 4.2 Phân loại mức độ rủi ro

| Điểm | Trạng thái | Kết luận trong báo cáo Word |
|---|---|---|
| ≥ 90 | **AN TOÀN** | "chưa phát hiện" |
| 75–89 | **CẢNH BÁO** | "chưa phát hiện" |
| < 75 | **NGUY HIỂN** | "phát hiện" |

## 4.3 Định dạng báo cáo đầu ra

Ứng dụng sinh **3 loại đầu ra**:

### (a) JSON — lưu cục bộ (báo cáo máy)

| Thuộc tính | Giá trị |
|---|---|
| **Thư mục** | `Data\AuditResults\` (tương đối so với thư mục chạy) |
| **Tên file** | `KiemTra_<TênCánBộBỏDấu><ddMMyyyy_HHmm>.json` — vd. `KiemTra_DangDinhKhoa_14082026_2236.json` |
| **Mã hóa** | UTF-8, `WriteIndented = true`, `UnsafeRelaxedJsonEscaping` (giữ nguyên tiếng Việt) |
| **Bản sao gần nhất** | `last_audit_result.json` ở thư mục gốc |
| **Bộ đệm offline** | `Data\<donViId>.json` (danh mục cán bộ), `Data\dmdonvi.json` (danh mục đơn vị) — TTL 30 ngày |

**Schema JSON (14 trường cấp cao):**

```jsonc
{
  "MachineName": "DESKTOP-XXXXXXX",
  "UserName": "<tên cán bộ quản lý máy tính>",
  "MAC": "xx:xx:xx:xx:xx:xx",
  "IP": "<IP LAN>",
  "UnitCap1": "<đơn vị cấp trên>",
  "UnitCap2": "<đơn vị cấp dưới>",
  "UnitCap3": "<phòng/ban>",
  "Position": "<chức vụ>",
  "Rank": "<cấp bậc>",
  "TotalScore": 81,
  "AuditDate": "20/05/2026 17:05:15",
  "InspectorUnit": "<đơn vị kiểm tra>",
  "InspectorName": "<tên cán bộ kiểm tra>",
  "Vulnerabilities": [ { "Name": "...", "Desc": "..." } ],
  "Alerts": [ { "Severity": "CRITICAL|WARNING", "Time": "dd/MM HH:mm",
                "Desc": "...", "Color": "#D32F2F|#F57C00", "Detail": "..." } ],
  "AIFeatures": { "IsCurrentUserAdmin": 1, "TotalAdminCount": 4, "HiddenUserCount": 0,
                  "OddHourActivityCount": 0, "TotalUsbCount": 0, "UnfamiliarUsbCount": 0,
                  "UsbPlugFrequency7Days": 0, "RemoteControlFound": 0,
                  "CrackSoftwareCount": 0, "SuspiciousTaskCount": 3 }
}
```

> **`AIFeatures`** là 10 chỉ số định lượng tổng hợp — đây là phần "AI features" của bản gốc
> (thực chất là **feature engineering thủ công**, không có mô hình ML nào).
> Cần đặc biệt lưu ý: `AIFeatures` được **ghi đè** (assign) chứ không cộng dồn ở nhiều
> phase — giá trị cuối là của phase chạy sau cùng, không phải tổng.

### (b) Word — Biên bản kiểm tra ATTT

| Thuộc tính | Giá trị |
|---|---|
| **Mẫu** | `Data\Template_Docx_Moi.docx` (OpenXML) |
| **Tên file** | `BienBan_KTATTT_<đơn vị>_<ddMMyyyy_HHmm>.docx` |
| **Cơ chế** | Copy mẫu → mở `WordprocessingDocument` editable → xoá `<w:proofErr>` → **thay chuỗi thô** trong `word/document.xml` |
| **Escape XML** | `&`→`&amp;`, `<`→`&lt;`, `>`→`&gt;`, `"`→`&quot;`, `'`→`&apos;` |
| **Xuống dòng** | `\r\n`→`\n` → `</w:t><w:br/><w:t>` |

**22 placeholder được thay thế:**

```
[TEN_CBKT] [DON_VI_CBKT] [NGAY_THANG_NAM] [TEN_MAY] [HE_DIEU_HANH] [BAN_QUYEN_OS]
[DIA_CHI_IP] [DIA_CHI_MAC] [LOAI_MAY] [BAT_WIFI] [PM_VIRUS] [TAI_LIEU_MAT]
[TEN_CAN_BO] [CHUC_VU] [CAP_BAC] [TEN_DON_VI] [DIEM_SO] [TRANG_THAI] [KET_LUAN]
[NUM_COUNT] [CHI_TIET_LO_HONG] [CHI_TIET_CAC_BUOC]
```

**Ghi chú về `[BAN_QUYEN_OS]`:** bản gốc **ghi cứng `"Đã kích hoạt"`** — không hề kiểm tra
trạng thái kích hoạt thật. Đây là điểm cần sửa trong bản mới (xem Phần 6).

### (c) Đẩy lên máy chủ (tùy chọn)

`UploadResultToServerAsync()` POST file JSON về máy chủ nội bộ. Ngoài ra
`CallDinhDanhApiAsync()` đăng ký thiết bị vào hệ thống quản lý FMS với payload:
`group, mac, manager_name, ip, device_name, network_type, type, unit_code`.

## 4.4 Cơ chế tổng hợp báo cáo từ nhiều máy

| Cơ chế | Chi tiết |
|---|---|
| Lưu trữ tập trung | `Data\AuditResults\*.json` — **24 file báo cáo** trong bộ mẫu (tổng 1 963 file trong `Data/`), đặt tên theo cán bộ + thời gian |
| Gộp theo đơn vị | Danh mục `Data\<donViId>.json` (theo ID đơn vị từ API) chứa danh sách cán bộ |
| Đẩy lên tập trung | Upload JSON kết quả lên máy chủ nội bộ (URL trong cấu hình) |
| Dashboard | `LoadDashboardData()` — hiển thị điểm đánh giá, trạng thái AV, cảnh báo, card mạng trên tab Tổng quan |
| Bộ lọc | `NormalizeString()` bỏ dấu + hạ chữ thường + bỏ `"quan khu 7"`/`"qk7"` + quy đổi `"hc kt"→"hau can ky thuat"` + `CalculateMatchScore()` so khớp từ khóa |

---

# PHẦN 5: LUỒNG GIAO DIỆN NGƯỜI DÙNG (UI/UX WORKFLOW)

## 5.1 Bố cục tổng thể

```
┌───────────────────────────────────────────────────────────────────────┐
│  BỘ CÔNG CỤ KIỂM TRA ATTT          [Phần mềm KT ATTT]                │  ← Header
│  ─────────────────────────────────────────────────────────────────── │
│  [Tổng quan]  [Kiểm tra ATTT]  [Kết quả KTATTT]  [Cấu hình]        │  ← 4 view
├───────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  ┌── MENU TRÁI ──────────┐  ┌── NỘI DUNG (thay đổi theo view) ──┐ │
│  │ MỞ KHÓA ADMIN         │  │                                      │ │
│  │ CÔNG CỤ NÂNG CAO:     │  │                                      │ │
│  │   • Xóa Log           │  │                                      │ │
│  │   • Truy vết Internet  │  │                                      │ │
│  │   • Tìm tài liệu mật  │  │                                      │ │
│  │ Khóa quyền lại        │  │                                      │ │
│  └───────────────────────┘  └──────────────────────────────────────┘ │
└───────────────────────────────────────────────────────────────────────┘
```

**Bảng màu (dark theme, MaterialDesign):**

| Vai trò | Mã màu |
|---|---|
| Nền chính | `#15171E` |
| Nền surface / panel | `#1D212D` |
| Panel khác | `#252A3A`, `#323647` |
| Màu nhấn chính | `#2979FF` |
| Màu nhấn phụ | `#F59E0B` |
| Chữ chính / phụ | `#7E8299`, `#64748B`, `#94A3B8`, `#CBD5E0` |
| Thành công | `#00C853` |
| Cảnh báo | `#F57C00` |
| Nguy hiểm | `#D32F2F` |
| Lỗi | `#FF0000` / `#FF4436` / `#F44336` |
| Font | `Segoe UI` (UI), `Consolas` 13 (console log) |

## 5.2 View 1 — TỔNG QUAN (Dashboard)

| Khối | Nội dung |
|---|---|
| **Điểm đánh giá** | Điểm số lớn + nhãn trạng thái (`RẤT AN TOÀN`) |
| **Trạng thái GP ATTT** | 3 dòng: `Windows Defender` / `Phần mềm MiAV` / `Phần mềm nextav` — trạng thái `Đang bảo vệ` / `Đang chạy` / `Chờ quét...` |
| **Trạng thái kết nối mạng** | `Đang kiểm tra Internet...` → kết quả; `Đang kiểm tra mạng TSL...`; trạng thái kết nối máy chủ (tìm máy chủ / đã kết nối) |
| **Cảnh báo lỗ hổng bảo mật** | DataGrid 3 cột: `Mức độ` / `Thời gian` / `Mô tả`; **double-click** → MessageBox chi tiết |
| **Thông tin card mạng** | Danh sách card mạng + địa chỉ MAC (`Đang đọc địa chỉ MAC...`) |

## 5.3 View 2 — KIỂM TRA ATTT (quét chính)

### Form nhập liệu (3 khối)

| Khối | Trường |
|---|---|
| **1. THÔNG TIN ĐOÀN KIỂM TRA** | Đơn vị thực hiện kiểm tra (ComboBox có gợi ý) · Tên cán bộ kiểm tra (ComboBox) |
| **2. CÁN BỘ ĐƯỢC KIỂM TRA** | Đơn vị cấp trên · Đơn vị phía dưới · Phòng/Ban · Tên cán bộ quản lý máy tính (auto-fill Cấp bậc / Chức vụ / Cơ quan) |
| **QUY TRÌNH THỰC THI** | 9 bước hiển thị dạng icon + trạng thái; console log; nút `BẮT ĐẦU QUÉT` → `SCANNING...` → `EXPORT` |

### Thanh tiến trình & không treo UI

```csharp
// Mỗi bước: icon PackIconKind.Sync (màu #2979FF) → CheckCircle (màu #00C853)
for (int i = 0; i < scanSteps.Length; i++)
{
    icon.Kind = PackIconKind.Sync;
    txtStatus.Text = "Scanning...";
    for (int d = 0; d < 5; d++) await Task.Delay(40);   // ~200ms hiệu ứng
    await RunScanPhase(i);                                 // Task.Run bên trong
    icon.Kind = PackIconKind.CheckCircle;
    txtStatus.Text = "Complete";
    await Task.Delay(200);
}
```

- Toàn bộ công việc nặng nằm trong `Task.Run` → **UI không bao giờ block**.
- `grid.BringIntoView()` tự cuộn tới bước đang chạy.
- `btnStartScan.IsEnabled = false` trong lúc quét → chặn nhấp đúp.
- Log ghi bằng `lock (_logLock)` → an toàn đa luồng.

### 9 bước hiển thị (theo `scanSteps[]`)

```
0. Trích xuất & Phân tích Log Hệ thống...
1. Rà soát Định danh & Đặc quyền (Tài khoản ẩn)...
2. Đánh giá Giải pháp ATTT (AV, Defender, Firewall)...
3. Quét Lỗ hổng & Bản vá (Missing Patches)...
4. Đánh giá Cấu hình An toàn (OS Hardening)...
5. Rà soát Tiến trình, Cron jobs & Persistence...
6. Phân tích Kết nối Mạng (Outbound Ports & C&C)...
7. Truy vết Lịch sử & Dấu vết số (Forensics)...
8. Đồng bộ máy chủ, Định danh thiết bị & Cài Agent...
```

### Thông báo hướng dẫn khắc phục

Bản gốc **rất tốt** ở phần này — mỗi cảnh báo đều kèm khối `[Khuyến nghị]` với lệnh cụ thể:

| Cảnh báo | Khuyến nghị trong báo cáo |
|---|---|
| Tài khoản ẩn có quyền Admin | `net user <tên_tài_khoản> /delete` trong CMD |
| Guest bật / Admin thiếu mật khẩu | 1. Vô hiệu hóa Guest · 2. Đặt mật khẩu mạnh cho nhóm Administrators |
| Firewall tắt | Mở Windows Defender Firewall → bật cho tất cả mạng |
| CSDL Defender quá hạn | Windows Security → Virus & threat protection → Check for updates |
| Bản vá cũ | Nâng cấp HĐH lên bản vá mới nhất |
| UAC tắt | Start → gõ "UAC" → kéo thanh trượt lên "Always notify" / "Default" |
| SMBv1 bật | `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol` |
| Cổng 445/3389 mở public | Dùng Tường lửa để giới hạn Scope của các cổng này |
| Service không chữ ký | Kiểm tra lại đường dẫn & chứng thực của service |
| Event Log bị xóa (1102) | Phát hiện hành vi cố ý xoá dấu vết |
| Kết nối C&C | Danh sách tiến trình cần xử lý (chi tiết trong `Detail`) |

## 5.4 View 3 — KẾT QUẢ KTATTT

Hiển thị kết quả vừa quét: điểm số, danh sách cảnh báo (`DataGrid`), danh sách lỗ hổng,
và nút **EXPORT** để xuất biên bản Word.

## 5.5 CÔNG CỤ NÂNG CAO (3 module, sau khi mở khóa Admin)

### (a) XÓA LOG — "Công Cụ Dọn Dẹp Dấu Vết"

> *"Chức năng can thiệp sâu vào hệ thống. Yêu cầu chạy phần mềm bằng quyền Run as Administrator."*

**ĐIỀU KIỆN TIÊN QUYẾT (PRE-CHECKS)** — 2 đèn trạng thái:
- MiAV / nextav đang chạy → đỏ, **chặn**
- Thư mục `@"C:\Users\Public\Public Documents\AgentFMC"` tồn tại → đỏ, **chặn**

**Quy trình 5 bước** (nút `BẮT ĐẦU XÓA LOG`, cảnh báo *"Thao tác này không thể hoàn tác!"*):

```
1. LogCleaner.ClearTempFilesAsync()            — xoá Temp/Prefetch/SoftwareDistribution
2. AdvancedLogCleaner.ClearAllBrowsersAsync()   — kill trình duyệt + xoá History/Cache
3. AdvancedLogCleaner.ClearUsbHistoryAsync()     — xoá sâu registry USB (chiếm quyền SYSTEM)
4. LogCleaner.ClearWindowsEventLogsAsync()       — wevtutil el → cl (xoá SẠCH mọi event log)
5. AdvancedLogCleaner.HuntAndDestroyMiAVAsync()  — hủy service + kill tiến trình + xoá dữ liệu MiAV
```

### (b) TRUY VẾT INTERNET — "Truy Vết Kết Nối & Tải Tệp"

> *"Phân tích luồng ẩn Zone.Identifier, tệp tải dở và DNS Cache để xác định dấu vết truy cập mạng ngoài."*
> *"Quá trình này chỉ đọc, không xóa dữ liệu."*

**PHẠM VI TRUY VẾT (SCAN TARGETS)** (khai báo trên UI):
- Thư mục Downloads & Desktop (Zone.Identifier)
- Bộ nhớ đệm phân giải tên miền (DNS Cache)
- Nhật ký sự kiện mạng (Event ID 10000, 8001)

**6 hạng mục truy vết** (`AnalyzeInternet.cs`):

| Hàm | Nội dung |
|---|---|
| `AnalyzeInternetDownloadsAsync` | `.crdownload` + `Zone.Identifier` (`ZoneId=3` → `HostUrl`/`ReferrerUrl`) trên Downloads + Desktop |
| `AnalyzeNetworkRegistryAsync` | `NetworkList\Profiles` (SSID) + `Tcpip\Parameters\Interfaces` (IP/Gateway/DNS/Lease) |
| `AnalyzeSrumDatabaseAsync` | `esentutl` trích bản sao SRUM; cảnh báo nếu >1 MB; xoá bản sao sau khi đo |
| `AnalyzeBrowserTracesAsync` | Chrome/Edge/Cốc Cốc/Firefox — History, Cookies, Cache (ngưỡng kích thước) |
| `AnalyzeActiveRamConnectionsAsync` | `GetActiveTcpConnections()` — IP công cộng đang duy trì |
| `AnalyzeWindowsUpdateHistoryAsync` | `Get-HotFix` + Registry `LastSuccessTime` |

### (c) TÌM TÀI LIỆU MẬT — "Rà soát & Phát hiện tài liệu mang độ mật"

> *"Dò tìm các tệp tin chứa từ khóa quân sự, bí mật nhà nước lưu trữ sai quy định"*

- DataGrid kết quả: `Tên tệp tin` / `Đường dẫn ổ đĩa` / `Từ khóa phát hiện` — **double-click để mở file** (có xử lý trường hợp file đã bị xoá/đổi tên)
- Nút `BẮT ĐẦU QUÉT`
- `LƯU CẤU HÌNH` cho tham số (mục Cấu hình)

### (d) CẤU HÌNH — "Cấu hình Tham số Hệ thống"

| Nhóm | Trường | Mặc định trong `Data/config.json` |
|---|---|---|
| **THÔNG SỐ RÀ SOÁT NHẬT KÝ** | 1 Giờ / 24 Giờ / 7 Ngày / 30 Ngày (Quét sâu) | `LogTimeValue = "2592000000"` (30 ngày) — giá trị còn lại: `3600000`, `86400000`, `604800000` |
| **THÔNG SỐ QUÉT TÀI LIỆU MẬT** | Định dạng file (phân tách bằng dấu phẩy) | `.doc, .docx, .xls, .xlsx, .pdf, .ppt, .pptx, .jpg, .png, .jpeg` |
| | Từ khóa nhận diện tài liệu mật | `tuyet mat, toi mat, tai lieu mat, phuong an, tac chien, ban giao, vu khi, tai lieu noi bo, mat_, tuyết mật, phương án, tác chiến` |
| | Chế độ quét sâu | `IsDeepScanEnabled = true` |

---

# PHẦN 6: ĐỀ XUẤT THIẾT KẾ KIẾN TRÚC PHẦN MỀM MỚI

## 6.1 Lựa chọn công nghệ

| Thành phần | Lựa chọn | Lý do |
|---|---|---|
| **Ngôn ngữ** | **C# / .NET 8 (LTS)** | Khớp hệ sinh thái hiện có (`NetSecTool`), .NET 8 LTS hỗ trợ đến 2026-11; WPF phù hợp cho ứng dụng desktop quản trị nội bộ |
| **GUI** | **WPF + MaterialDesignThemes 5.x** | Giữ nguyên diện mạo quân sự (dark theme), hỗ trợ `DataGrid`, `PackIcon`, MVVM |
| **Kiến trúc** | **MVVM + tách lớp hạ tầng** | Cho phép tách "Core Scanner" khỏi "UI" để dùng lại cho CLI / agent |
| **Đóng gói** | **self-contained single-file** | Máy quân sự không có sẵn .NET Runtime |
| **Cấu hình** | **JSON** (`System.Text.Json`) | Đã dùng sẵn, không cần thêm dependency |

> **Khuyến nghị đặc biệt:** dùng **.NET 8 LTS** thay vì .NET 9 vì .NET 9 đã hết hỗ trợ
> (EOL tháng 5/2026). Bản gốc đang nhắm .NET 9 — cần nâng cấp.

## 6.2 Cấu trúc thư mục đề xuất

```
KiemTraATTT/
├─ src/
│  ├─ Attt.Core/                       ← Domain + Rule Engine (không phụ thuộc UI)
│  │  ├─ Models/
│  │  │  ├─ AuditContext.cs            # Máy đang kiểm tra: hostname, user, IP, MAC, NIC
│  │  │  ├─ CheckResult.cs             # Kết quả 1 hạng mục
│  │  │  ├─ Severity.cs                # enum Info/Warning/Critical
│  │  │  ├─ CheckOutcome.cs            # enum Pass/Warn/Fail/Skipped/Error  ← THÊM
│  │  │  ├─ AuditFinding.cs            # Lỗ hổng (thay Vulnerability)
│  │  │  ├─ AuditAlert.cs              # Cảnh báo (thay Alert)
│  │  │  ├─ MetricBag.cs               # Thay AIFeatures
│  │  │  └─ AuditReport.cs             # Kết quả tổng hợp
│  │  ├─ Interfaces/
│  │  │  ├─ ICheck.cs                 # Hợp đồng 1 hạng mục
│  │  │  ├─ IDataSource.cs            # Trừu tượng hoá nguồn dữ liệu
│  │  │  ├─ IRuleEngine.cs
│  │  │  └─ IReportExporter.cs
│  │  ├─ Checks/
│  │  │  ├─ SystemPatch/               # ← Gom Phase1 + Phase4
│  │  │  │  ├─ OsEolCheck.cs
│  │  │  │  ├─ PatchCurrencyCheck.cs
│  │  │  │  └─ InstalledSoftwareCheck.cs
│  │  │  ├─ AntiMalware/               # ← Gom Phase3 + B4/B5/B6/B7
│  │  │  │  ├─ FirewallProfileCheck.cs
│  │  │  │  ├─ AntivirusPresenceCheck.cs
│  │  │  │  ├─ SignatureFreshnessCheck.cs
│  │  │  │  ├─ TempArtifactHeuristicCheck.cs
│  │  │  │  ├─ SysmonSensitiveCommandCheck.cs
│  │  │  │  └─ PowerShellExecutionCheck.cs
│  │  │  ├─ Identity/                  # ← Phase2
│  │  │  │  ├─ GuestAccountCheck.cs
│  │  │  │  ├─ BlankAdminPasswordCheck.cs
│  │  │  │  ├─ HiddenAdminAccountCheck.cs
│  │  │  │  └─ UacEnabledCheck.cs
│  │  │  ├─ Network/                   # ← Phase5 (cổng) + Phase7 (C&C)
│  │  │  │  ├─ SensitivePortExposureCheck.cs
│  │  │  │  ├─ OutboundConnectionCheck.cs
│  │  │  │  ├─ C2ConnectionCheck.cs
│  │  │  │  ├─ ReverseTunnelCheck.cs
│  │  │  │  └─ RdpSessionHistoryCheck.cs
│  │  │  ├─ Peripherals/               # ← Phase1 USB
│  │  │  │  ├─ UsbStorageInventoryCheck.cs
│  │  │  │  ├─ UsbWirelessAdapterCheck.cs
│  │  │  │  ├─ UsbTetheringDeviceCheck.cs
│  │  │  │  └─ UsbInsertionFrequencyCheck.cs
│  │  │  ├─ Persistence/               # ← Phase6
│  │  │  │  ├─ ScheduledTaskCheck.cs
│  │  │  │  ├─ RegistryRunKeyCheck.cs
│  │  │  │  ├─ UnsignedServiceCheck.cs
│  │  │  │  └─ UnquotedServicePathCheck.cs
│  │  │  ├─ LogIntegrity/               # ← Phase1 Event Log
│  │  │  │  ├─ AuditLogClearedCheck.cs
│  │  │  │  ├─ BruteForceCheck.cs
│  │  │  │  └─ OffHoursActivityCheck.cs
│  │  │  └─ Forensics/                 # ← AnalyzeInternet + SecretDocumentScanner
│  │  │     ├─ ZoneIdentifierCheck.cs
│  │  │     ├─ BrowserArtifactCheck.cs
│  │  │     ├─ SrumVolumeCheck.cs
│  │  │     ├─ NetworkProfileHistoryCheck.cs
│  │  │     └─ SecretDocumentCheck.cs
│  │  ├─ RuleEngine/
│  │  │  ├─ RuleEngine.cs              # Đọc rules.json → áp dụng → sinh kết luận
│  │  │  ├─ RuleDefinition.cs
│  │  │  └─ ScoringPolicy.cs
│  │  └─ DataSources/                  # ← Bọc WMI/Registry/EventLog/Process thành interface
│  │     ├─ WmiDataSource.cs
│  │     ├─ RegistryDataSource.cs
│  │     ├─ EventLogDataSource.cs
│  │     ├─ ProcessDataSource.cs
│  │     ├─ NetworkDataSource.cs
│  │     └─ FileSystemDataSource.cs
│  ├─ Attt.Reporters/
│  │  ├─ JsonReportExporter.cs
│  │  ├─ WordReportExporter.cs        # OpenXML — token thay thế
│  │  ├─ ExcelRollupExporter.cs       # ★ MỚI — gộp nhiều máy
│  │  └─ CsvSummaryExporter.cs
│  ├─ Attt.Service/                    # ★ MỚI — Windows Service cho agent giám sát
│  ├─ Attt.Cli/                       # ★ MỚI — headless cho tự động hoá
│  └─ Attt.Ui/                        # WPF + MaterialDesign
│     ├─ Views/ DashboardView, ScanView, ResultView, SettingsView, LogCleanerView, …
│     ├─ ViewModels/
│     └─ Themes/ DarkTheme.xaml
├─ config/
│  ├─ rules.json                      # ★ NGỮ NGHĨA TIÊU CHÍ — cập nhật không cần build lại
│  ├─ keywords.json                   # Từ khóa tài liệu mật
│  └─ severity-map.json               # Ngưỡng → severity → penalty
└─ tests/
   └─ Attt.Core.Tests/
```

## 6.3 Cấu trúc `rules.json` — cập nhật tiêu chí không cần biên dịch lại

```jsonc
{
  "$schema": "https://attt.local/schemas/rules-v1.json",
  "version": "1.0.0",
  "updatedAt": "2026-11-21",
  "scoring": {
    "baseScore": 100,
    "phasePenaltyCap": 5,          // giữ nguyên hành vi bản gốc
    "bands": [
      { "min": 90, "label": "AN TOÀN",   "conclusion": "chưa phát hiện" },
      { "min": 75, "label": "CẢNH BÁO", "conclusion": "chưa phát hiện" },
      { "min": 0,  "label": "NGUY HIỂN", "conclusion": "phát hiện"    }
    ]
  },
  "checks": [
    {
      "id": "SEC-LOG-001",
      "group": "LogIntegrity",
      "name": "Nhật ký an ninh bị xóa",
      "enabled": true,
      "dataSource": "eventlog",
      "parameters": {
        "channel": "Security",
        "eventIds": [1102],
        "windowMs": 604800000
      },
      "evaluation": {
        "type": "eventPresence",
        "failWhen": { "countGte": 1 },
        "severity": "CRITICAL",
        "penalty": 3,
        "remediation": "Kiểm tra Event ID 1102 để xác định thời điểm log bị xoá và đối chiếu lịch sử thao tác quản trị."
      }
    },
    {
      "id": "ANTIVIRUS-002",
      "group": "AntiMalware",
      "name": "CSDL diệt virus quá hạn",
      "enabled": true,
      "dataSource": "wmi",
      "parameters": {
        "namespace": "root\\Microsoft\\Windows\\Defender",
        "query": "SELECT AMServiceEnabled, AntivirusSignatureLastUpdated FROM MSFT_MpComputerStatus"
      },
      "evaluation": {
        "type": "ageDays",
        "field": "AntivirusSignatureLastUpdated",
        "warnWhenGreaterThanDays": 7,
        "severity": "WARNING",
        "penalty": 1,
        "remediation": "Windows Security → Virus & threat protection → Check for updates."
      }
    },
    {
      "id": "NET-C2-001",
      "group": "Network",
      "name": "Kết nối tới máy chủ C&C",
      "enabled": true,
      "dataSource": "network",
      "parameters": {
        "connectionStates": ["Established", "SynSent"],
        "excludePrivateRanges": true,
        "privateRanges": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"],
        "suspiciousPorts": [4444, 1337, 31337, 6667, 4445, 3333, 5555, 7777]
      },
      "evaluation": {
        "type": "connectionMatch",
        "severity": "CRITICAL",
        "penalty": 3
      }
    }
  ]
}
```

> **Lợi ích cốt lõi:** khi quy định ATTT thay đổi (ngưỡng ngày bản vá, cổng C&C mới,
> từ khóa tài liệu mật, bảng điểm), chỉ cần **sửa JSON** — không build lại, không
> phát hành phiên bản mới. Đây là cải tiến lớn nhất so với bản gốc.

## 6.4 Danh sách cải tiến so với phần mềm tham khảo

### 6.4.1 Về kiến trúc & khả năng mở rộng

| # | Cải tiến | Vấn đề ở bản gốc | Cách xử lý |
|---|---|---|---|
| 1 | **Rule Engine đọc JSON** | Toàn bộ ngưỡng (90 ngày bản vá, 7 ngày CSDL, 50 lần brute-force, cổng C&C, whitelist USB) **hardcode** trong C# | `rules.json` — cập nhật không cần build |
| 2 | **Chuẩn hoá 4 trạng thái** | Chỉ có Đạt/Không đạt/Cảnh báo lẫn trong log; `Skipped`/`Error` không phân biệt → **không biết hạng mục nào bị bỏ qua** | `CheckOutcome { Pass, Warn, Fail, Skipped, Error }` + trường `SkipReason` |
| 3 | **Tách lớp, DI** | `MainWindow.cs` 100 KB, chứa cả UI, business logic, lưu file, gọi API | Tách `Core` / `Reporters` / `Ui`; `ICheck` + `IServiceCollection` |
| 4 | **Bỏ `AIFeatures` ghi đè** | `AIFeatures["RemoteControlFound"]` bị **ghi đè** ở Phase6 rồi lại ở Phase7 → mất giá trị Phase6 | `MetricBag` cộng dồn theo chiều `Max`/`Sum` theo chính sách rõ ràng |
| 5 | **Tách `MainWindow` 100 KB** | File khổng lồ khó bảo trì | ViewModel riêng cho từng màn hình |
| 6 | **Lỗi im lặng** | Nhiều `catch { }` rỗng → hạng mục biến mất **không có dấu vết** | Mọi hạng mục ghi `Error` + `SkipReason` vào báo cáo |
| 7 | **Chạy song song** | Các phase tuần tự → chậm | `Parallel.ForEachAsync` cho các check **độc lập** (WMI/Registry) |

### 6.4.2 Về tính đầy đủ của tiêu chí

| # | Cải tiến | Vấn đề ở bản gốc |
|---|---|---|
| 8 | **Kiểm tra chính sách khóa USB** | Bản gốc **có** `UsbTetheringBlocker` (ghi GPO) nhưng **không kiểm tra** trạng thái chính sách trong phần rà soát → thiếu hạng mục "Chính sách khóa cổng USB" mà đề bài yêu cầu |
| 9 | **Kiểm tra bản quyền Windows thật** | `[BAN_QUYEN_OS]` ghi cứng `"Đã kích hoạt"` → kiểm tra `SoftwareLicensingProduct` (SLP) thật |
| 10 | **Danh mục phần mềm đã cài** | Đề bài yêu cầu; bản gốc **không** có → thêm check liệt kê `Win32_Product`/`Uninstall` |
| 11 | **Thiết bị ngoại vi không dây (Bluetooth)** | Đề bài yêu cầu; bản gốc chỉ kiểm USB → thêm check Bluetooth |
| 12 | **Trạng thái lưu trữ Windows Event Log** | Đề bài yêu cầu ("trạng thái lưu trữ"); bản gốc chỉ đọc → thêm check kích thước + trạng thái log |
| 13 | **Thiếu hạng mục trong nhóm "Thiết bị ngoại vi"** | Thiếu kiểm tra USB lưu trữ **chưa được duyệt** (đã thu thập `UnfamiliarUsbCount` nhưng **không trừ điểm**) |
| 14 | **Không phân biệt EOL của từng phiên bản** | Chỉ check 6 OS cũ → bổ sung Windows 10 (sau thời điểm hết hỗ trợ), Server 2012 R2/2016 |

### 6.4.3 Về an toàn

| # | Cải tiến | Vấn đề ở bản gốc |
|---|---|---|
| 15 | **Bỏ hardcode mật khẩu** | Mật khẩu quản trị UI + mật khẩu API + mật khẩu FMS nằm **nguyên văn trong assembly** | Lưu vào Windows Credential Manager / DPAPI; hoặc bỏ gate UI hoàn toàn (chỉ cần UAC) |
| 16 | **Bật lại kiểm tra chứng thương TLS** | `FmsApiManager` đặt `ServerCertificateCustomValidationCallback => true` → **vô hiệu hoá xác thực chứng thương** → dễ bị MITM | Bỏ callback; nếu server dùng CA nội bộ thì cài CA vào Trusted Root (kèm hướng dẫn) |
| 17 | **Không log payload nhạy cảm** | `FmsApiManager` log nguyên văn response có token; `ApiSyncManager` gửi mật khẩu trong body không mã hoá | Redact token/mật khẩu trong log |
| 18 | **Rate-limit & timeout thống nhất** | Timeout rời rạc (2 s / 5 s / 10 s / 15 s) | `HttpClient` dùng chung với `Timeout` cấu hình được |
| 19 | **Xác thực chữ ký binary** | Agent chạy SYSTEM từ `C:\Windows\MiST_MZ7\` — thư mục **ghi được bởi User** → có thể bị thay thế để chiếm quyền SYSTEM | Đặt trong `%ProgramFiles%` với ACL chặt + xác minh hash trước khi chạy |

### 6.4.4 Về hiệu năng & trải nghiệm

| # | Cải tiến |
|---|---|
| 20 | **Chạy song song các check độc lập** — giảm thời gian quét ước 40–60 % |
| 21 | **Cache kết quả WMI** (`Win32_QuickFixEngineering`, `Win32_Service`) trong 1 phiên quét |
| 22 | **Progress thật** — thanh % thay vì 9 ô "Scanning…"; bỏ `Task.Delay(100)` giữa các dòng log (hiệu ứng này **cộng thêm vài giây** vô nghĩa) |
| 23 | **Xuất báo cáo tổng hợp cấp đơn vị** (Excel/CSV) — gộp 100+ máy theo đơn vị, tính điểm trung bình, xếp hạng — **bản gốc chưa có** |
| 24 | **Chế độ CLI headless** (`--audit --output json`) để chạy theo lịch qua Task Scheduler |
| 25 | **Tự khắc phục có xác nhận** — đề xuất nút "Khắc phục" cho: bật lại Firewall profile, bật UAC, tắt SMBv1, vô hiệu hóa Guest, đặt mật khẩu admin rỗng. Mỗi thao tác **hiện hộp thoại xác nhận** ghi rõ thay đổi + lệnh tương ứng |
| 26 | **Bộ lọc báo cáo** — lọc theo điểm, theo đơn vị, theo mức độ; export PDF qua `DocX`/HTML→PDF |
| 27 | **Đo thời gian mỗi check** — hiển thị check nào chậm để tối ưu |

### 6.4.5 Về tính đúng đắn

| # | Cải tiến | Vấn đề ở bản gốc |
|---|---|---|
| 28 | **Dải IP nội bộ theo cấu hình** | `IsPrivateIP` check `86.0.0.0/8` là nội bộ — **đúng với mạng quân sự**, nhưng `Phase1.CheckNetworkActivityAsync` dùng prefix `86.` (rộng hơn `86.128.`) → **mâu thuẫn giữa 2 phase**, có thể báo "kết nối ra ngoài" cho IP nội bộ hợp lệ | Dùng **một bảng CIDR nội bộ** trong `rules.json` cho mọi phase |
| 29 | **Đếm chính xác brute-force theo người dùng** | Đếm tổng số 4625, không phân biệt 1 user bị dò 100 lần vs 100 user 1 lần | Gom theo `TargetUserName` → cảnh báo theo tài khoản |
| 30 | **Phân biệt "không có" vs "không đọc được"** | `EventLogNotFoundException` (chưa cài Sysmon) ≠ `UnauthorizedAccessException` (thiếu quyền) — hiện tại cả hai đều rơi vào nhánh chung | `CheckOutcome.Skipped` + `SkipReason` cụ thể |
| 31 | **Săn USB lạ** chuyển thành điểm trừ | `UnfamiliarUsbCount` thu thập nhưng **không trừ điểm** → USB lạ không ảnh hưởng điểm | Áp dụng penalty theo `rules.json` |
| 32 | **Kiểm tra chính sách mật khẩu phức tạp** | Đề bài yêu cầu "chính sách độ phức tạp mật khẩu"; bản gốc **không có** | `net accounts` / `LSA` policy → `PasswordComplexity`, `PasswordHistorySize`, `MaxPasswordAge` |
| 33 | **Kiểm tra thời gian khóa màn hình** | Đề bài yêu cầu; bản gốc **không có** | `HKLM\…\Policies\System!InactivityTimeoutSecs` |
| 34 | **Đếm metric cộng dồn đúng** | `SuspiciousTaskCount` bị cộng ở nhiều phase → **ghi đè** ở Phase6/7 | `MetricBag` với chính sách `Sum`/`Max` tường minh |

## 6.5 Bảng tương thích ngược (contract giữ nguyên)

Để bản mới **đọc được báo cáo cũ** và hệ thống tập trung không phải sửa:

| Mã cũ | Mã mới | Ghi chú |
|---|---|---|
| `AuditResult` | `AuditReport` | Giữ nguyên tên trường JSON |
| `Vulnerability` | `AuditFinding` | Giữ `Name`/`Desc` |
| `Alert` | `AuditAlert` | Giữ `Severity`/`Time`/`Desc`/`Color`/`Detail` |
| `AIFeatures` | `Metrics` | Giữ 10 key cũ, bổ sung key mới |
| `Data/AuditResults/KiemTra_<...>.json` | giữ nguyên | Thêm `EngineVersion` + `CheckResults[]` (mới, không phá cũ) |
| `Data/config.json` | `config/rules.json` + `config/keywords.json` | Hỗ trợ đọc `config.json` cũ 1 lần để migrate |

---

# PHẦN 7: MA TRẬN & PHỤ LỤC

## 7.1 Ma trận hạng mục ↔ nguồn dữ liệu (tóm tắt)

| Nhóm | Registry | WMI | EventLog | Win32 API | Shell | Tài liệu |
|---|:-:|:-:|:-:|:-:|:-:|:-:|
| A. HĐH & Bản vá | | ● | | ○ | ○ | |
| B. Phòng chống mã độc | ● | ● | ● | ● | | |
| C. Tài khoản & chính sách | ● | ● | ● | ● | | |
| D. Mạng | ● | | ● | ● | ● | |
| E. USB & ngoại vi | ● | | ● | ● | | |
| F. Persistence & chữ ký | ● | ● | | ● | ● | |
| G. Tệp & trình duyệt | ● | | | ● | ● | ● |
| H. Dọn dẹp | ● | | ● | ● | ● | |

● = nguồn chính · ○ = nguồn phụ

## 7.2 Các phát hiện bảo mật (báo cáo để khắc phục — không phân tích cơ chế bảo vệ)

| # | Phát hiện | Vị trí | Mức độ | Khuyến nghị |
|---|---|---|---|---|
| 1 | Mật khẩu quản trị UI hardcode trong assembly | `MainWindow.ADMIN_PASSWORD` | Cao | Bỏ gate hoặc dùng DPAPI/Credential Manager |
| 2 | Mật khẩu API đồng bộ hardcode | `ApiSyncManager` | Cao | Chuyển sang cấu hình ngoài + token |
| 3 | Mật khẩu FMS hardcode | `FmsApiManager` | Cao | Như #2 |
| 4 | Vô hiệu hoá xác thực chứng thương TLS | `FmsApiManager.CreateHttpClient` | **Rất cao** | Bỏ callback, cài CA nội bộ vào Trusted Root |
| 5 | Log token/mật khẩu ra console | `FmsApiManager.GetTokenAsync`, `InsertDinhDanhAsync` | Trung bình | Redact |
| 6 | Agent SYSTEM chạy từ thư mục ghi được bởi User | `NetworkMonitorService` → `C:\Windows\MiST_MZ7\` | Cao | `%ProgramFiles%` + ACL + kiểm tra hash |
| 7 | `catch {}` rỗng che giấu lỗi | Nhiều nơi | Trung bình | `Skipped` + `SkipReason` |
| 8 | Điểm số không phản ánh đúng mức độ | Cap 5/phase | Trung bình | Nâng cap, thêm trọng số theo severity |

## 7.3 Danh mục thư viện bên thứ ba (bản gốc)

| Thư viện | Phiên bản | Vai trò | Cần thiết cho bản mới? |
|---|---|---|---|
| MaterialDesignThemes | 5.1.0 | UI WPF | **Có** |
| MaterialDesignColors | 3.1.0 | Bảng màu | **Có** |
| Microsoft.Xaml.Behaviors.Wpf | 1.1.39 | Hành vi UI | Tùy |
| DocumentFormat.OpenXml | 3.5.1 | Thao tác DOCX | **Có** |
| DocX | 5.0.0 | Đọc nội dung .docx | **Có** (quét tài liệu mật) |
| EPPlus | 8.5.4 | Đọc .xlsx + xuất Excel | **Có** |
| PdfPig | 0.1.14 | Đọc nội dung .pdf | **Có** |
| SkiaSharp | 3.119.4 | Render ảnh | Không *(chưa dùng trong logic quét)* |
| OpenCvSharp4 | 4.13.0 | Phát hiện con dấu đỏ | Tùy *(hạng mục G3)* |
| Microsoft.Extensions.Configuration.Json | 9.0.15 | Đọc config | **Có** |
| System.Management | — | Truy vấn WMI | **Có** (built-in) |

> **Lưu ý cắt giảm:** `SkiaSharp` (9,66 MB) + `OpenCvSharp4` (~40 MB) chiếm phần lớn
> dung lượng gói cạnh runtime .NET. Nếu bỏ hạng mục G3 (con dấu đỏ) và thay render
> bằng WPF → **giảm ~50 MB** gói phát hành.

## 7.4 Danh mục tệp đầu ra

| Đường dẫn | Nội dung |
|---|---|
| `Data\AuditResults\KiemTra_*.json` | Báo cáo máy (24 file trong `Data\AuditResults\`) |
| `last_audit_result.json` | Báo cáo gần nhất |
| `Data\config.json` | Cấu hình tham số |
| `Data\<donViId>.json` | Danh mục cán bộ (cache offline) |
| `Data\dmdonvi.json` | Danh mục đơn vị (cache offline) |
| `Data\Template_Docx_Moi.docx` | Mẫu biên bản Word |
| `Logs\NetworkServiceLog.txt` | Nhật ký agent giám sát mạng |
| `BienBan_KTATTT_*.docx` | Biên bản Word đã xuất |

---

## PHỤ LỤC A — Quy trình phân tích đã thực hiện

```
reverse-skill-main/RULES.md  →  skills/scripts/master-route.ps1
                             →  PRIMARY = skills/dotnet-reverse/SKILL.md
skills/scripts/case-init.ps1  →  work/20261121-164743-case/scope.md
skills/scripts/case-guard.ps1 →  CASE-GUARD OK
tool-index.md                 →  python ✔ · pwntools ✔ · ilspycmd ✖ → cài 8.2.0.7535 (dotnet tool install --global)
```

**Nhận diện đối tượng:** `ilspycmd` báo `PEFileNotSupportedException` → không phải managed PE thuần →
viết bộ tách bundle .NET (magic 32 byte, manifest v6.0) → giải nén 402 assembly →
`ilspycmd -p` trên `KTATTT_2026.dll` → 34 file C# sạch (không obfuscation) →
đọc `mainwindow.baml` bằng script trích chuỗi để khôi phục UI →
đối chiếu `AuditResult` + 24 báo cáo JSON mẫu + 1 938 danh mục để xác nhận schema →
đối chiếu portable PDB để xác nhận tên field/thuộc tính.

**Giới hạn đã biết:**
- XAML gốc không khôi phục được (chỉ khôi phục được nhãn + bảng màu + tên view) → bố cục chính xác cần xác nhận bằng ảnh chụp.
- `MainWindow.xaml.cs` được `de4dot`-style tái tạo từ BAML; `InitializeComponent` dùng `case 0..44` cho `Connect` → xác nhận **4 view** + ~45 control.
- Không phân tích cơ chế bảo vệ bản quyền / làm rối mã (không có dấu hiệu obfuscation).
- Không chạy mẫu (không cần thiết — mọi hành vi đã đọc được từ mã nguồn decompile).

---

*Báo cáo được tạo bằng quy trình `reverse-skill` — `dotnet-reverse` (PRIMARY) + `docs-generator`.*
*Mọi khẳng định đều có bằng chứng đối chiếu tại `work/attt/EVIDENCE.md`.*
