---
date: 2026-11-21
scenario: .NET 9 WPF single-file bundle → clean-room functional specification extraction
primary_skill: dotnet-reverse
case: 20261121-164743-case
tags: [dotnet, wpf, single-file-bundle, ilspycmd, eventlog, wmi, registry, ATTT-audit, vietnamese-software]
---

# .NET 9 WPF single-file bundle → trích xuất đặc tả chức năng (KTATTT 2026)

## Tình huống

Người dùng (Trung tá phụ trách CNTT đơn vị) cung cấp gói phần mềm kiểm tra ATTT
`KTATTT_2026` (144 MB exe + 112 MB agent) và yêu cầu **đặc tả chức năng + thiết kế
kiến trúc clean-room** để xây mới. Yêu cầu kèm quy tắc: chỉ phân tích nghiệp vụ,
ẩn danh dữ liệu nhạy cảm, không phân tích cơ chế bảo vệ bản quyền / obfuscation.

## Vấn đề then chốt: `ilspycmd` báo "PE file does not contain any managed metadata"

Không phải lỗi tool. Đây là dấu hiệu **.NET single-file bundle**: file exe bên ngoài
chỉ là host stub, managed payload được nhúng dạng bundle.

### Giải pháp: tự viết bộ tách bundle

Không cần công cụ ngoài. Format do `dotnet/corefx` định nghĩa:

- Magic 32 byte: `8b 12 02 b9 6a 61 20 38 72 7b 93 02 14 d7 a0 32 13 f5 b9 e6 ef ae 33 18 ee 3b 2d ce 24 b3 6a ae`
- Ngay trước magic: `int64 manifestOffset`
- Manifest header: `int32 major, int32 minor, int32 fileCount, string bundleId`
  - major ≥ 2: thêm `depsJsonOffset/Size`, `runtimeConfigOffset/Size` (4×int64) + `uint64 flags`
  - major ≥ 6: mỗi entry có thêm `int64 compressedSize` (0 = không nén)
- Mỗi entry: `int64 offset, int64 size, [int64 compressedSize], byte type, string relativePath`
- Chuỗi trong manifest: **7-bit encoded length prefix** (không phải UTF-16 như .NET BinaryReader!)
- `type`: 0=Unknown, 1=Assembly, 2=NativeBinary, 3=DepsJson, 4=RuntimeConfigJson, 5=Symbols
- Nén: `zlib.decompress(blob, -15)` (raw deflate, không header zlib)

Script dùng lại được: `work/attt/extract_bundle.py` (~130 dòng Python, chỉ stdlib).

**Kết quả mẫu:** magic tại `0x6A0830`, manifest **v6.0**, **402 file** (400 Assembly +
DepsJson + RuntimeConfigJson), bundleId `mQYt7L5uE+BFSEBH6FQ2+J5Hhi9+9BA=`.

Sau khi tách, `ilspycmd` trên `KTATTT_2026.dll` (537 KB) cho ra project C# **34 file,
không obfuscation** — tên class/method thật, `async`/`await` nguyên vẹn.

## Trích xuất UI từ BAML khi không có XAML gốc

`ilspycmd -p` xuất `.baml` (compiled XAML), **không** xuất `.xaml`. Muốn biết cấu trúc
giao diện mà không cần dnSpy GUI:

- Chuỗi trong BAML lưu dạng **length-prefixed UTF-8** → quét byte, thử mọi offset,
  giữ chuỗi printable hợp lệ
- Bộ lọc bỏ: markup thuần (`{...}`, `xmlns=...`), identifier đơn giản (`Foo.Bar`)
- Kết quả: **100 chuỗi tiếng Việt** → tái dựng được tên view, nhãn nút, bảng màu
  (`#2979FF`, `#15171E`, `#1D212D`, `#F59E0B`, `#D32F2F`…), cấu trúc form 3 khối,
  và cả **9 bước quét** (mảng `scanSteps`)

Script: `work/attt/baml_strings.py`.

### Bổ sung: portable PDB

File `.pdb` đi kèm là **portable PDB** (`BSJB` magic). Trích chuỗi ASCII ra được
tên field mà decompile không lộ (`isBadIP`, `remoteKeywords_`, `crackKeywords_`,
`whitelistedServices_`, `minSealArea`, `maxSealArea`, `contourArea`) → xác nhận chéo
với tên biến trong code.

## Nhận diện chức năng từ mã: mẫu lặp lại

Ứng dụng .NET WPF kiểm tra ATTT dùng mẫu rất đặc trưng:

| Mẫu | Ý nghĩa |
|---|---|
| `Phase1Auditor` … `Phase7Auditor`, mỗi phase là `static async Task<ScanResponse> XxxAsync()` | mỗi phase trả về cùng một DTO |
| `ScanResponse { Logs, PenaltyPoints, Alerts, Vulnerabilities, AIFeatures }` | DTO chuẩn — dùng để suy ra toàn bộ mô hình chấm điểm |
| `response.PenaltyPoints += Math.Min(num, 5)` | **cap 5/phase** → trần thực tế 35 điểm → điểm thấp nhất 65. Điểm yếu thiết kế đáng nêu |
| `AIFeatures` là `Dictionary<string,int>` | "AI features" thực chất là feature engineering thủ công |
| Dựng UI động trong code thay vì XAML | `panelSteps.Children.Add(new Grid{...})` — dễ bỏ sót khi đọc XAML |

### Bẫy logic cần đối chiếu

1. **`AIFeatures` bị GHI ĐÈ chứ không cộng dồn**: `RemoteControlFound` set ở Phase6
   rồi lại set ở Phase7 → mất giá trị. `MetricBag` với chính sách Sum/Max tường minh là fix.
2. **Dải IP nội bộ mâu thuẫn giữa 2 phase**: `Phase7.IsPrivateIP` coi `86.0.0.0/8`
   là nội bộ, nhưng `Phase1.CheckNetworkActivityAsync` dùng prefix `"86."` rộng hơn
   `86.128.` → có thể báo "kết nối ra ngoài" cho IP nội bộ hợp lệ.
3. **`[BAN_QUYEN_OS]` ghi cứng `"Đã kích hoạt"`** trong báo cáo Word — không hề kiểm tra
   trạng thái kích hoạt thật.
4. **`catch { }` rỗng ở nhiều nơi** → hạng mục biến mất khỏi báo cáo mà không có dấu vết.
5. **`EventLogNotFoundException` (chưa cài Sysmon) ≠ `UnauthorizedAccessException`
   (thiếu quyền)** — cần `CheckOutcome.Skipped` + `SkipReason`.

## Cơ chế xuất báo cáo Word: thay chuỗi thô trong OpenXML

Không dùng template engine. Cách làm:
1. `File.Copy(template, output)`
2. `WordprocessingDocument.Open(output, isEditable: true)`
3. Đọc `word/document.xml` thành **string**
4. Xoá `<w:proofErr ...>` (rác từ Word spell-check)
5. `.Replace("[PLACEHOLDER]", value)` cho từng token, sau khi escape XML và
   đổi `\n` → `</w:t><w:br/><w:t>`
6. Ghi lại stream

Placeholder ở bản này: 22 token (`[TEN_CBKT]`, `[DIEM_SO]`, `[TRANG_THAI]`, `[KET_LUAN]`…).
**Lưu ý:** token có thể bị Word **tách run** khi lưu → replace thẳng sẽ hụt.
Bản mới nên dùng `OpenXmlWriter` hoặc `DocumentFormat.OpenXml` DOM API thay vì string replace.

## Xác minh đầu ra bằng dữ liệu mẫu (rất hiệu quả)

Bộ mẫu có **1 962 file JSON** trong `Data/AuditResults/` + `last_audit_result.json`.
Đối chiếu `AuditResult` model với file thật cho phép:
- xác nhận schema 16 trường cấp cao (14 + 2 mảng/dict)
- xác nhận **quy tắc đặt tên file**: `KiemTra_<TênBỏDấu><ddMMyyyy_HHmm>.json`
- xác nhận `WriteIndented=true` + `UnsafeRelaxedJsonEscaping` (tiếng Việt giữ nguyên)
- xác nhận **ngưỡng phân loại** 90/75 từ mẫu điểm 81 / 91
- phát hiện `AIFeatures` trong file thật **không có** `IsCurrentUserAdmin` ở
  `last_audit_result.json` (field được cũ) → schema drift theo thời gian

## Bảo mật: phát hiện đáng chú ý (báo cáo để khắc phục, KHÔNG phân tích sâu)

| Phát hiện | Vị trí |
|---|---|
| Vô hiệu hoá xác thực chứng thương TLS | `HttpClientHandler.ServerCertificateCustomValidationCallback = (…) => true` |
| Mật khẩu hardcode ×3 | admin UI / API đồng bộ / FMS |
| Log nguyên văn token ra console | `FmsApiManager` |
| Agent SYSTEM chạy từ `C:\Windows\MiST_MZ7\` (thư mục User ghi được) | `NetworkMonitorService` |

## Bài học (không phân tích sâu theo yêu cầu, nhưng đáng ghi)

- Route `dotnet-reverse` là đúng cho task này — nhưng SKILL.md giả định target là
  **assembly .NET độc lập**. Với **single-file bundle** phải thêm bước tách bundle
  trước. → Nên bổ sung một `references/` cho .NET single-file bundle trong
  `skills/dotnet-reverse/`.
- `tool-index.md` không liệt kê `ilspycmd` (chỉ có `dotnet` SDK). Cài được bằng
  `dotnet tool install --global ilspycmd` — nên thêm vào `bootstrap-manifest.json`.
- Portable PDB đi kèm là nguồn đối chiếu **rẻ và mạnh** — luôn đọc trước khi decompile
  sâu.

## Công cụ đã dùng (đường dẫn đầy đủ)

| Công cụ | Đường dẫn | Ghi chú |
|---|---|---|
| Python | `C:\Users\doand\AppData\Local\Programs\Python\Python313\python.exe` | có sẵn trong tool-index |
| ilspycmd 8.2.0.7535 | `%USERPROFILE%\.dotnet\tools\ilspycmd.exe` | cài mới — chưa có trong tool-index |
| .NET SDK | `10.0.201` | có sẵn |

## Bài học tái sử dụng

Khi gặp "PE file does not contain any managed metadata": **đừng** kết luận native /
obfuscated. Kiểm tra bundle magic 32 byte trước. Tách bundle bằng Python stdlib
mất ~15 phút, thay vì cài công cụ bundle riêng.

Khi cần đặc tả chức năng từ phần mềm đóng gói: **decompile + đọc mẫu output thật +
đọc BAML + đọc portable PDB** — bốn nguồn bổ sung cho nhau, cùng độ tin cậy.
