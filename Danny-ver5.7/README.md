# Danny — Trợ lý Công nghệ Thông tin

**Phần mềm được viết bởi Trung tá Đoàn Danh Quyết — Trợ lý Công nghệ Thông tin — Cellphone: 0366.714.139**

Ứng dụng Windows C# / .NET 8 WinForms dành cho đơn vị quân sự: chẩn đoán mạng nội bộ,
cấu hình IP một chạm, tạo USB an toàn (chống MiAV chặn ở tầng kernel), làm sạch dấu vết
truy cận Internet, hỗ trợ kỹ thuật từ xa, sao lưu máy tính và điều tra chứng cứ số (DFIR).

---

## Phiên bản

| Phiên bản | Ngày | Ghi chú |
|---|---|---|
| **5.7.0** | 22/11/2026 | Forensic DFIR · KVRT updater · Uncover files · Dọn dẹp 4 bước · PC Backup |
| 5.6.0 | — | Thay UltraVNC bằng RustDesk (Direct IP) |
| 5.5.0 | — | Hỗ trợ kỹ thuật từ xa |
| 5.0.0 | — | Làm sạch PC một chạm · USB an toàn |

→ Chi tiết thay đổi: [`CHANGELOG.md`](CHANGELOG.md)
→ Hướng dẫn sử dụng: [`HUONG-DAN-SU-DUNG.md`](HUONG-DAN-SU-DUNG.md)

---

## Tải về

| Bản | Link |
|---|---|
| Gói đầy đủ (self-contained) | <https://github.com/doandanhquyetqk7/Danny/releases> |
| Mã nguồn | `git clone https://github.com/doandanhquyetqk7/Danny.git` |

Bản phát hành gồm 2 file `.exe`:

- **`Danny-ver5.7.exe`** — self-contained, single-file, chạy được trên mọi máy Windows 10/11 **không cần cài .NET**
- **`Danny-ver5.7-nethost.exe`** — framework-dependent, ~1,4 MB, cần .NET 8 Desktop Runtime

> **Bắt buộc:** giữ nguyên thư mục `tools\` cạnh file `.exe`.

---

## Build từ mã nguồn

```powershell
git clone https://github.com/doandanhquyetqk7/Danny.git
cd Danny
.\build_and_publish.ps1 -SkipPublish
```

Yêu cầu: **.NET 8 SDK** + Windows 10/11.

---

## Cấu trúc mã nguồn

```
NetSecTool/
├── Program.cs                     Điểm vào + CLI headless
├── Form1.cs                       Form chính (partial)
├── Form1.NewTabs.cs               Tab HIỆN FILE/FOLDER ẨN
├── Form1.BackupTab.cs             Tab SAO LƯU MÁY TÍNH
├── Form1.ForensicTab.cs           Tab KIỂM TRA AN TOÀN THÔNG TIN
├── NetDiagnostics.cs              Chẩn đoán mạng / tra cứu đơn vị
├── IpOneClick.cs                  Cấu hình IP một chạm
├── UsbSafeBuilder.cs              Tạo USB an toàn 2.6
├── PcCleanerV57.cs                Quy trình làm sạch PC 4 bước
├── BackupService.cs               Engine sao lưu (Acronis + robocopy)
├── UncoverFiles.cs                Gỡ thuộc tính ẩn
├── KvrtUpdater.cs                 Tự cập nhật Kaspersky KVRT
├── RemoteSupport.cs               RustDesk Direct IP
├── Forensic/                      Module Forensic DFIR
│   ├── ForensicModels.cs
│   ├── EvidenceCollector.cs
│   ├── RuleEngine.cs
│   ├── TimelineEngine.cs
│   ├── ReportWriter.cs
│   └── ForensicEngine.cs
└── Resources/
    ├── KVRT.exe                   Kaspersky Virus Removal Tool
    ├── SetupMiAV.exe              Trình cài đặt MiAV 4.1.1.2 (BTL86)
    ├── RustDesk/                  RustDesk 1.5.3 + server (hbbs/hbbr)
    └── rules/forensic-rules.json  Bộ quy tắc Forensic (sửa ngoài, không cần build lại)
```

---

## Chức năng chính

| Nhóm | Mô tả |
|---|---|
| **Mạng** | Chẩn đoán LAN/WAN, tra cứu đơn vị (có dấu / không dấu), cấu hình IP tĩnh một chạm |
| **USB an toàn** | Tạo USB 2.6 với `inf.bin` hợp lệ — vượt qua cơ chế chặn ở tầng kernel của MiAV |
| **Làm sạch dấu vết** | 4 bước: tệp rác → trình duyệt → USB sâu → Event Log; kèm KVRT + cài lại MiAV |
| **Sao lưu** | Ảnh hệ thống (Acronis) + dữ liệu người dùng (robocopy), chỉ ổ di động ≥ 1 TB |
| **Forensic DFIR** | Thu thập chỉ đọc + rule engine + timeline tương quan + báo cáo SHA-256 |
| **Hỗ trợ từ xa** | RustDesk Direct IP — 100% offline, whitelist CIDR, cổng 21118 |

---

## CLI headless

```powershell
Danny-ver5.7.exe --kvrt-update
Danny-ver5.7.exe --uncover "D:\Data" [--no-recursive] [--dry-run]
Danny-ver5.7.exe --backup --target I: [--no-system-image] [--no-user-data] [--dry-run]
Danny-ver5.7.exe --forensic [--out "C:\Bao-cao"]
```

---

## Bản quyền & phụ thuộc bên thứ ba

- **Acronis CLI** (`acrocmd.exe`) — **không** đóng gói vì bản quyền. Người dùng tải và đặt vào `tools\acronis\`.
- `KVRT.exe`, `SetupMiAV.exe`, `RustDesk` — giữ nguyên bản gốc của nhà sản xuất.

---

## Lưu ý an toàn

Phần mềm thực hiện các thao tác can thiệp sâu vào hệ thống (xóa log, thay đổi ACL Registry,
chiếm quyền sở hữu khóa Registry, định dạng USB). **Luôn sao lưu dữ liệu trước khi chạy
"Chức năng làm sạch PC một chạm"** — thao tác này không thể hoàn tác.

Chế độ Forensic là **chỉ đọc** và không sửa đổi bất kỳ dữ liệu nào trên máy đích.

---

## Giấy phép

MIT
