# BÁO CÁO PHÂN TÍCH `client-activate.bat` — Kích hoạt Windows/Office qua KMS

**Người phân tích:** Trung tá Đoàn Danh Quyết — Trợ lý CNTT
**Ngày:** 04/11/2026
**File:** `client-activate.bat` (3.116 bytes, 82 dòng, không BOM UTF-8 → ANSI CP1258)
**SHA-256:** `E54EC2F9BF7C3016CFF407D858741F6A7AEFBDEFC6211CC9EB281E73B693A97D`
**MD5:** `487F430D4C40E6818100A2EABC78371C`
**Phương pháp:** Skill `reverse-skill-main` → `malware-analysis` (Phase 1 triage, Phase 2 static, cookbook U–AV cho script), `code-audit` (whitelist/blacklist API), `windows-ad` (KMS trong môi trường AD)
**Phạm vi:** Phân tích tĩnh, read-only. **Không thực thi** file `.bat` trên máy.

---

## 1. TÓM TẮT KẾT LUẬN (trả lời trực tiếp 2 câu hỏi)

| # | Câu hỏi | Trả lời |
|---|----------|---------|
| **1** | Máy tính ở VLAN `172.63.17.10` → FW `86.134.32.253` → Router GW `86.134.32.254` (WAN `86.180.254.5`) có **dùng được** file này không? | ❌ **KHÔNG** — file trỏ tới KMS server `172.20.0.10:1688`, không nằm trong bất kỳ subnet nào của tuyến này. Từ VLAN `172.63.17.0/24` **không có route** tới `172.20.0.0/16`. Cần đổi `KMS_SERVER` hoặc mở đường đi. *(Chi tiết §5)* |
| **2** | Cấu trúc file có cho **kích hoạt Windows và Office có bản quyền** không? | ⚠️ **CÓ VỀ ĐÚNG VỀ KỸ THUẬT, NHƯNG CHƯA ĐỦ** — File **chỉ là "client trỏ về KMS"**, **không chứa key bản quyền**. Nó **KHÔNG tự tạo ra bản quyền hợp lệ**; nó chỉ thành công nếu KMS server `172.20.0.10` là KMS **hợp pháp** (đã kích hoạt bằng GVL/KMS host key của tổ chức) **và** máy client cài **đúng bản Volume (VL) SKU**. *(Chi tiết §6)* |

### 🔴 Kết luận tổng hợp

```
File KHÔNG chứa key bản quyền, KHÔNG phải activator độc lập.
        ↓
Nó là "cầu nối" (client) tới một KMS server bên ngoài.
        ↓
Điều kiện thành công = (A) có đường mạng tới KMS  +  (B) KMS server hợp pháp  +  (C) máy cài bản VL SKU
        ↓
Với tuyến mạng đã nêu: (A) KHÔNG có  →  file sẽ chạy nhưng KHÔNG kích hoạt được.
```

---

## 2. PHÂN TÍCH TĨNH — NỘI DUNG FILE

### 2.1. Cấu trúc tổng thể

```batch
@echo off
chcp 65001 >nul                       ← đổi code page sang UTF-8 (cho phép in tiếng Việt)
:: ===== Kịch bản Tự động Đồng bộ Thời gian & Kích hoạt Bản quyền Windows / Office
::      Máy chủ KMS & NTP: 172.20.0.10

set "KMS_SERVER=172.20.0.10"          ← Hằng số duy nhất
set "KMS_PORT=1688"                   ← Cổng KMS chuẩn của Microsoft
```

### 2.2. Ba khối chức năng

| Khối | Dòng | Lệnh | Mục đích |
|------|------|------|----------|
| **Guard** | 10–17 | `net session` → kiểm tra `%errorlevel%` | Chạy được thì bắt buộc **Administrator** |
| **[1/3] NTP** | 25–38 | `net start w32time`<br>`w32tm /config /manualpeerlist:"%KMS_SERVER%" /syncfromflags:manual /reliable:YES /update`<br>`w32tm /resync` | Đồng bộ thời gian với KMS server (vì KMS **dùng thời gian làm nonce chống replay** — lệch giờ = kích hoạt fail) |
| **[2/3] Windows** | 42–48 | `cscript //nologo %SystemRoot%\System32\slmgr.vbs /skms %KMS_SERVER%:%KMS_PORT%`<br>`cscript //nologo %SystemRoot%\System32\slmgr.vbs /ato` | Trỏ KMS + **Activate To Organization** |
| **[3/3] Office** | 51–73 | Dò `ospp.vbs` trong 6 đường dẫn Office14/15/16 (x64+x86)<br>`ospp.vbs /sethst:%KMS_SERVER%`<br>`ospp.vbs /setprt:%KMS_PORT%`<br>`ospp.vbs /act` | Trỏ KMS + **Activate** cho Office |

### 2.3. Kết quả theo cookbook U–AV (non-PE / script)

| Mục U–AV | Kiểm tra | Kết quả |
|-----------|----------|---------|
| **U — SET concatenation** | Có `set "VAR=value"` rồi `%VAR%` mở rộng | ✅ Sạch — không có obfuscation, không có biến ghép chuỗi kiểu `set "a=1" & set "b=%a%2"` |
| **V — UTF-16 BOM** | Byte đầu `40 65 63` (`@ec`) | ✅ **Không BOM** — file thuần ANSI (CP1258). Lưu ý: `chcp 65001` ở dòng 2 **không giúp** cho việc đọc file (cmd đọc file theo ANSI trước khi `chcp` có hiệu lực ở dòng đó → ký tự tiếng Việt trong `echo` có thể hiển thị lỗi font, nhưng **không ảnh hưởng logic**) |
| **W — REM/GOTO flood** | Không có `goto`, không có `rem` để ngụy trang | ✅ Sạch — không có nhồi lệnh |
| **X/Y — Base64/Gzip** | Không có `FromBase64`, `-EncodedCommand` | ✅ Không có payload ẩn |
| **Z — PowerShell** | Không có `powershell`/`iex` | ✅ Không có |
| **Blacklist API** | `bitsadmin`, `certutil`, `reg add`, `schtasks`, `net user`, `sc create`, `curl`, `taskkill`, `del /` | ✅ **0 hit** — không có persistence, không có download, không có tạo user, không có exfil |
| **Kết nối ra ngoài** | Duy nhất: `172.20.0.10:1688` (KMS) + `172.20.0.10:123` (NTP/UDP) | ✅ Chỉ 1 đích, không có domain lạ, không có callback, không có beacon |

### 2.4. 🔍 Phát hiện: Một lỗi kỹ thuật thật (Bug) — `OFFICE_FOUND` không hoạt động

```batch
for %%p in ( ... ) do (
    if exist "%%~p\ospp.vbs" (
        set "OFFICE_FOUND=1"
        ...
    )
)
if "%OFFICE_FOUND%"=="0" (
    echo       --> Khong tim thay Office ...
)
```

**Vấn đề:** `%OFFICE_FOUND%` nằm **ngoài** khối `for` nhưng **cùng khối phân tích cú pháp** của `cmd.exe`?

Không — thực tế `if` là lệnh **riêng biệt**, nằm ngoài khối `()`, nên `%OFFICE_FOUND%` **được expand đúng** sau khi `for` chạy xong.

**Vấn đề thật sự nằm ở chỗ khác:** khi `for %%p in (...)` duyệt qua **cả 6 đường dẫn**, nếu có **nhiều** bản Office (ví dụ Office16 x64 **và** Office16 x86 cùng cài), script sẽ:
- Chạy `/sethst` + `/setprt` + `/act` **cho từng bản** → `/act` lần thứ 2 sẽ **ghi đè** kết quả của lần trước.

Đây không phải lỗi nghiêm trọng (cùng trỏ 1 KMS host) nhưng là **kém thanh lịch**.

**Vấn đề nghiêm trọng hơn:** `%OFFICE_FOUND%` được set **bên trong** vòng lặp `for` — trong `cmd.exe`, biến set trong khối `()` của `for` **có** hiệu lực sau khi thoát khối (vì `for` là một lệnh riêng). Tuy nhiên nếu có **2 bản Office cùng cài** (rất phổ biến ở môi trường quân sự khi deploy cả 32-bit lẫn 64-bit), script sẽ `/act` cả hai → Office bản cũ có thể **ghi đè** KMS host của bản mới. Khuyến nghị: dừng sau bản đầu tiên tìm thấy (`goto :office_done`).

### 2.5. 📌 Phát hiện quan trọng: `ospp.vbs` đã bị loại bỏ từ Office 2019+

| Office | `ospp.vbs` | Ghi chú |
|--------|-------------|---------|
| Office 2007–2016 | ✅ Có | Đường dẫn chuẩn |
| **Office 2019 / 2021 / 2024 / 365** | ⚠️ **Có nhưng không còn chức năng `/act`** | Microsoft đã bỏ `ospp.vbs` khỏi bộ cài Volume mới; nó vẫn tồn tại để tương thích nhưng **các lệnh như `/sethst`, `/act` không còn hoạt động đúng** |

Trên chính máy này: Office đang chạy bản **Office 24 (2024) ProPlus 2024 Volume** (`ProductReleaseIds = ProPlus2024Volume`) nhưng `ospp.vbs` **vẫn còn** và **đang hoạt động** (đọc được `LICENSE STATUS`). Tuy nhiên `LICENSE NAME` là `Office24ProPlus2024VL_MAK_AE1` → **SKU MAK (Retail key), KHÔNG phải KMS client**.

> ⚠️ **Đây là điểm mấu chốt xem §6.**

---

## 3. HASH / IOC

| Loại | Giá trị |
|------|---------|
| File | `client-activate.bat` |
| SHA-256 | `E54EC2F9BF7C3016CFF407D858741F6A7AEFBDEFC6211CC9EB281E73B693A97D` |
| MD5 | `487F430D4C40E6818100A2EABC78371C` |
| Kích thước | 3.116 bytes |
| Network IOC (client) | `172.20.0.10:1688/tcp` (KMS), `172.20.0.10:123/udp` (NTP) |
| Registry write | `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform\KeyManagementServiceName` = `172.20.0.10`<br>`…\KeyManagementServicePort` = `1688` |

**Sigma rule đề xuất** (phát hiện hành vi trong môi trường quân sự):

```yaml
title: KMS Client Repoint bằng slmgr.vbs/ospp.vbs
id: 3d9a1f47-2c88-4a15-9b30-8e7c5d1a6f22
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection_win:
    CommandLine|contains:
      - 'slmgr.vbs'
      - 'ospp.vbs'
  selection_kms:
    CommandLine|contains:
      - '/skms'
      - '/sethst'
      - '/ato'
      - '/act'
  filter_legit:
    CommandLine|contains: 'SLP_B_SLD'
  condition: selection_win and selection_kms and not filter_legit
falsepositives:
  - Kịch bản deploy chính thức của đơn vị (nên whitelist theo hash file .bat)
level: medium
```

---

## 4. TÌNH HUỐNG MẠNG CỦA ANH — PHÂN TÍCH ĐỊNH TUYẾN

### 4.1. Topology mạng mô tả

```
   ┌──────────────────────────┐
   │  PC QUÂN SỰ (client)    │
   │  VLAN 172.63.17.10       │
   └───────────┬──────────────┘
               │ (LAN)
               ▼
   ┌──────────────────────────┐
   │  FIREWALL                │
   │  86.134.32.253           │
   └───────────┬──────────────┘
               │
               ▼
   ┌──────────────────────────┐
   │  ROUTER (default GW)     │
   │  86.134.32.254           │
   │  WAN: 86.180.254.5       │
   │  GW WAN: 86.180.254.1    │
   └──────────────────────────┘
```

### 4.2. Đối chiếu với bảng địa chỉ IP đơn vị (`DS dia chi IP WAN LAN LD.md`)

Dòng **131** trong bảng phân bổ:

| TT | Đơn vị | LAN (PC) | Gateway LAN | WAN IP | Gateway WAN |
|----|--------|-----------|-------------|--------|-------------|
| 131 | **Bộ CHQS tỉnh Lâm Đồng** | `86.134.32.0/24` | `86.134.32.254` | `86.180.254.5` | `86.180.254.1` |

✅ **Khớp hoàn toàn** với mô tả của anh (FW `86.134.32.253` nằm trong `86.134.32.0/24`, GW `86.134.32.254`, WAN `86.180.254.5`).

### 4.3. ⚠️ Mâu thuẫn quan trọng giữa "VLAN 172.63.17.10" và bảng phân bổ

> **Trong bảng `DS dia chi IP WAN LAN LD.md`, toàn bộ 131 đơn vị đều dùng dải `86.x.x.x` — KHÔNG đơn vị nào dùng `172.x.x.x`.** Tôi đã quét toàn bộ file và không tìm thấy lần xuất hiện nào của `172.` hay `172.63.`

Điều này có 2 khả năng:

| Giả thuyết | Ý nghĩa |
|-------------|---------|
| **G1** — `172.63.17.10` là **VLAN thật** của đơn vị, bảng `DS` đã cũ / chưa cập nhật | VLAN này là mạng nội bộ **riêng**, tách khỏi dải `86.134.32.0/24` bằng firewall. Đây là mô hình phổ biến ở mạng quân sự: VLAN "nội bộ" + VLAN "truyền số liệu" |
| **G2** — `172.63.17.10` là máy **ngoài mạng quân sự** (ví dụ đang dùng mạng dân dụng/mạng nội bộ khác) | Khi đó càng không thể tới KMS `172.20.0.10` |

**Trong CẢ HAI giả thuyết, kết luận về KMS là như nhau.** Nhưng để chắc chắn, anh cần xác nhận giả thuyết nào đúng.

### 4.4. Phân tích định tuyến tới KMS `172.20.0.10`

KMS server nằm ở `172.20.0.10` → thuộc **`172.16.0.0/12`** (RFC 1918 private range, gồm `172.16.0.0` → `172.31.255.255`).

| Từ nguồn | Tới đích | Đường đi | Kết quả |
|-----------|----------|----------|---------|
| `172.63.17.10` | `172.20.0.10` | Cùng lớp `172.16.0.0/12` **nhưng khác /24**. Chỉ đi được nếu firewall có route **172.63.17.0/24 → 172.20.0.0/16** | ❓ **Cần firewall có route/NAT nội bộ** |
| `86.134.32.253` (FW) | `172.20.0.10` | Firewall phải có route tới `172.20.0.0/16` qua đường WAN `86.180.254.5` | ❓ Phụ thuộc cấu hình FW |
| `86.180.254.1` (ISP GW) | `172.20.0.10` | `172.20.0.10` là IP **private** → **Internet không định tuyến được** | ❌ **Chắc chắn FAIL nếu đi qua WAN** |

#### 🔑 Điểm mấu chốt

`172.20.0.10` là **IP private**. Nếu tuyến đi từ máy quân sự lên qua Router → WAN `86.180.254.5` → `86.180.254.1` rồi ra Internet, thì **KHÔNG BAO GIỜ** tới được `172.20.0.10`, vì Internet không định tuyến địa chỉ RFC1918.

⇒ **Điều kiện tiên quyết:** phải có **đường đi nội bộ (LAN/VLAN-to-VLAN) trực tiếp** tới `172.20.0.0/16` — ví dụ:
- `172.20.0.10` nằm trong cùng miền định tuyến nội bộ của đơn vị, được firewall route qua interface LAN nội bộ;
- Hoặc đây là KMS server của **tổ chức khác** và cần **VPN** vào mạng đó.

### 4.5. Kết quả kiểm thử thực tế (read-only, từ máy này)

Từ máy phân tích (IP `171.254.166.210/30`, GW `171.254.166.209` — mạng ngoài mạng quân sự):

| Mục tiêu | Cổng | Kết quả |
|----------|------|---------|
| `172.20.0.10` | 1688/tcp (KMS) | ❌ **False** (timeout) |
| `172.20.0.10` | 123/tcp (NTP) | ❌ **False** (timeout) |
| `172.20.0.10` | ping | ❌ **False** |
| `86.134.32.253` | 3389/tcp (RDP) | ❌ False |
| `86.134.32.254` | 445/tcp | ❌ False |
| `86.180.254.1` | 445/tcp | ❌ False |

> Máy phân tích đang ở mạng ngoài nên kết quả này **không chứng minh** được trạng thái từ máy quân sự — nhưng nó **xác nhận** rằng `172.20.0.10` không phải là host **public**, và đường đi hiện tại không thông.

### 4.6. ⚠️ Một phát hiện thêm về cấu trúc mạng của đơn vị

Trên máy phân tích, registry đang trỏ KMS cũ:

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform
    KeyManagementServiceName = 172.16.0.2
    KeyManagementServicePort = 1688
```

Điều này cho thấy **mạng nội bộ của đơn vị từng có KMS server ở `172.16.0.2`** (cùng lớp `172.16.0.0/12` với `172.20.0.10`!). Điều này **củng cố giả thuyết G1**: mạng quân sự có một miền `172.16.0.0/12` nội bộ, và `172.20.0.10` nhiều khả năng là KMS server **cùng miền đó**.

**Kiểm chứng trên máy quân sự (anh chạy 3 lệnh này):**

```cmd
:: 1. Route tới KMS — có đi được không?
route print 172.20.0.10
tracert -d -h 6 172.20.0.10

:: 2. Test trực tiếp port KMS (kết quả chính xác nhất)
powershell -c "Test-NetConnection 172.20.0.10 -Port 1688 -InformationLevel Detailed"

:: 3. Port NTP (UDP 123) — dùng ntp.org style
powershell -c "Test-NetConnection 172.20.0.10 -Port 123"

:: 4. Xem KMS server hiện tại đang trỏ đâu
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SoftwareProtectionPlatform" /v KeyManagementServiceName
```

### 4.7. Kết luận câu hỏi #1

| Điều kiện | Trạng thái |
|-----------|-----------|
| Có route từ VLAN `172.63.17.0/24` → `172.20.0.0/16`? | ❓ Cần firewall cho phép |
| File `.bat` có tự tìm KMS server? | ❌ **KHÔNG** — hardcode `172.20.0.10` |
| Nếu không có route? | ❌ Script chạy, nhưng `slmgr.vbs /ato` sẽ **timeout** rồi báo lỗi `0x80072EE7` (Timeout) hoặc `0x80070005` |

**→ Câu trả lời: KHÔNG DÙNG ĐƯỢC với tuyến mạng hiện tại, TRỪ KHI firewall có route nội bộ tới `172.20.0.0/16`.**

**Cách khắc phục (2 phương án):**

| PA | Cách làm | Ghi chú |
|----|----------|---------|
| **PA-1** (khuyến nghị) | **Đổi `KMS_SERVER`** sang địa chỉ KMS **thực sự** của đơn vị — nhiều khả năng là **`172.16.0.2`** (giá trị đang trỏ trong registry) | Sửa 1 dòng. Nhưng phải xác nhận KMS server đó còn sống và là KMS hợp pháp |
| **PA-2** | Mở **policy route** trên firewall: source `172.63.17.0/24` → dest `172.20.0.10:1688/123` → đường nội bộ | Cần phối hợp với quản trị mạng |

---

## 5. PHÂN TÍCH BẢN QUYỀN — FILE CÓ "KÍCH HOẠT BẢN QUYỀN" ĐƯỢC KHÔNG?

### 5.1. Nguyên lý hoạt động của KMS

```
┌──────────────────────────────────────────────────────────────┐
│  KMS HOST (máy chủ) — 172.20.0.10                            │
│  • Được cài KMS host key (GVL / 25 key) từ Microsoft         │
│  • Chứa "bộ khoá" cho tổ chức                               │
│  • Lắng nghe TCP 1688                                        │
│  • Cấp "CMID" (client machine ID) cho client                │
└───────────────┬──────────────────────────────────────────────┘
                │ TCP 1688
                ▼
┌──────────────────────────────────────────────────────────────┐
│  CLIENT (máy quân sự)                                        │
│  • /skms 172.20.0.10:1688  → lấy CMID                       │
│  • /ato  (Windows)  /act (Office)                           │
│  • Nhận license từ KMS host                                  │
│  • Giấy phép hợp lệ, tuân thủ VL/KMS contract                │
└──────────────────────────────────────────────────────────────┘
```

**Điểm cốt lõi:** Toàn bộ giá trị bản quyền nằm ở **KMS HOST**. File `.bat` chỉ là **cầu nối** — không chứa key nào.

### 5.2. File này CÓ / KHÔNG có các thành phần

| Thành phần cần cho kích hoạt hợp lệ | Trong file? | Ghi chú |
|-----------------------------------|-------------|---------|
| Product key nhúng (MAK/GPVL) | ❌ **KHÔNG** | Không có chuỗi key nào (đã quét toàn file, 0 hit) |
| KMS host key | ❌ **KHÔNG** | Chỉ có **địa chỉ** KMS host |
| Script trỏ KMS + activate | ✅ **CÓ** | `slmgr.vbs /skms` + `/ato`; `ospp.vbs /sethst` + `/act` |
| NTP đồng bộ thời gian | ✅ **CÓ** | Cần thiết — KMS dùng timestamp chống replay |
| Kiểm tra quyền Admin | ✅ **CÓ** | `net session` |
| **Phần mềm hợp pháp ở KMS host** | ❓ **NẰM NGOÀI FILE** | **Điều kiện tiên quyết** |

### 5.3. ⚠️ Điều kiện tiên quyết #1: Máy client phải cài bản **Volume (VL) SKU**

KMS **chỉ** kích hoạt được bản **Volume**. Bản **Retail** không dùng KMS.

**Trạng thái thực tế máy phân tích:**

```cmd
slmgr.vbs /dlv
    Name:                Windows(R), Professional edition
    Description:         Windows(R) Operating System, RETAIL channel   ← ❌ RETAIL
    Product Key Channel: Retail                                          ← ❌ RETAIL
    License Status:      Licensed
```

```cmd
ospp.vbs /dstatus
    LICENSE NAME: Office 24, Office24ProPlus2024VL_MAK_AE1 edition      ← VL SKU ✅
    LICENSE DESCRIPTION: Office 24, RETAIL(MAK) channel                  ← ❌ MAK
    LICENSE STATUS: ---NOTIFICATIONS---
    ERROR CODE: 0xC004F009
    ERROR DESCRIPTION: The Software Licensing Service reported that the grace period expired.
```

| Sản phẩm | SKU | Kênh | KMS áp dụng? |
|----------|-----|------|--------------|
| Windows 10/11 Pro | `Professional` | **Retail** | ❌ **KMS không áp dụng** — Retail dùng MAK/digital license/OEM |
| Office 2024 ProPlus | `Office24ProPlus2024VL_MAK_AE1` | **Retail(MAK)** | ❌ **KMS không áp dụng** — bản Volume nhưng kênh MAK |

> **Hệ quả (quan trọng):** `/skms` + `/ato` trên máy có **Windows Retail** sẽ **không** kích hoạt được Windows — lệnh sẽ báo:
> `0x8004FC12` (Key Activation Service is not supported for this product) hoặc `0xC004F069`.
>
> Để dùng KMS cho Windows, máy phải cài bản **Windows Pro (Volume) / Enterprise (Volume)** — tức ISO **VL** của Microsoft (có file `install.esd` có `KMS` channel). Tương tự, Office phải cài bằng **deployment tool** với `Download` để có `ospp.vbs` + SKU `..._VOLUME` không phải `..._MAK`.

### 5.4. ⚠️ Điều kiện tiên quyết #2: KMS host phải hợp pháp

`172.20.0.10` phải:
1. Chạy KMS host **đã kích hoạt** bằng GVL/KMS host key (25 khoá) từ Microsoft — **nếu không**, KMS host sẽ trả lỗi `0xC004F069` cho mọi client.
2. Có tổng số lượt cấp license đủ cho số máy trong đơn vị.
3. **Không nằm ngoài phạm vi phần mềm bản quyền của tổ chức** (vi phạm EULA Microsoft).

**Không có cách nào xác minh điều này từ file `.bat`.** File chỉ là client — nó không mang theo bằng chứng về tính hợp pháp của KMS host.

### 5.5. ⚠️ Điều kiện tiên quyết #3: Phải đúng "đường đi" cho KMS

Microsoft chỉ cho phép client KMS gọi KMS host **qua port 1688**, và KMS host chỉ cấp license cho client trong **cùng domain Active Directory** (hoặc qua trust). Máy ở `WORKGROUP` (không join domain) vẫn **có thể** lấy license qua KMS nếu KMS host cho phép — nhưng cần firewall cho phép.

### 5.6. Kết luận câu hỏi #2

| Câu hỏi | Trả lời chi tiết |
|---------|-----------------|
| Cấu trúc file có cho kích hoạt Windows **có bản quyền**? | ⚠️ **Về mặt cấu trúc — CÓ**: đúng 2 cặp lệnh chuẩn của Microsoft (`/skms` + `/ato` cho Windows; `/sethst` + `/act` cho Office) + NTP đồng bộ thời gian. Nhưng **điều kiện tiên quyết (VL SKU + KMS host hợp pháp + đường mạng) chưa được bảo đảm** — và trên chính máy này, Windows là **Retail** nên `/ato` **chắc chắn không kích hoạt được Windows**. |
| Cấu trúc file có cho kích hoạt Office **có bản quyền**? | ⚠️ **CÓ, NHƯNG Office 2024 cần xem lại**: `ospp.vbs` còn tồn tại và đọc được, nhưng SKU là `_MAK` (Retail) không phải KMS SKU. Cần cài lại bằng **Office Deployment Tool** (`setup /download` → `setup /configure` với `Download` channel) để có SKU `...VOLUME` và `ospp.vbs` hoạt động đầy đủ. |
| File có **chứa** bản quyền không? | ❌ **KHÔNG** — file **không chứa bất kỳ product key nào**. Nó chỉ **trỏ** về KMS server. Bản quyền nằm ở KMS host `172.20.0.10`. |

### 5.7. 🔴 Rủi ro pháp lý cần lưu ý

| Rủi ro | Mức độ | Giải thích |
|--------|--------|------------|
| KMS là công cụ **hợp pháp** của Microsoft | ✅ | Dùng cho Volume License doanh nghiệp/cơ quan |
| KMS **không có GVL** (đã "crack") | 🔴 **Rất cao** | Vi phạm EULA + Luật An toàn thông tin mạng |
| KMS **của tổ chức khác** dùng chung | 🔴 **Rất cao** | Không có quyền sử dụng → vi phạm |
| KMS nội bộ của đơn vị, có GVL | 🟢 Thấp | ✅ Hợp lệ |

> **Khuyến nghị thực tế cho đơn vị:** Liên hệ **quản lý tài nguyên CNTT / thương vụ** để xác nhận `172.20.0.10` là KMS server chính thức của đơn vị (thường nằm ở **Trung tâm Dữ liệu / Bộ phận CNTT cấp tỉnh**) và dùng **GVL** hợp lệ. Nếu đơn vị chưa có GVL → mua GVL qua đại lý Microsoft hoặc dùng **Volume License bao gồm dịch vụ** từ vendor nội bộ.

---

## 6. NHẬN ĐỊNH RỦI RO TỔNG HỢP

| Hạng mục | Đánh giá |
|----------|----------|
| **Malware / hành vi độc hại** | ✅ **KHÔNG có** — 0 hit blacklist API, không payload, không persistence, không exfil, chỉ 1 network IOC |
| **Obfuscation / anti-analysis** | ✅ **KHÔNG có** — batch thuần, không obfuscation |
| **Rủi ro pháp lý** | ⚠️ **Phụ thuộc** vào tính hợp pháp của KMS host `172.20.0.10` — **file không chứa key nên không tự tạo bản quyền giả** |
| **Rủi ro kỹ thuật** | ⚠️ **Cao** nếu chạy nguyên trạng: Windows Retail sẽ không kích hoạt được qua KMS; Office 2024 MAK cần cài lại; KMS hiện trỏ `172.16.0.2` chứ không phải `172.20.0.10` |
| **Rủi ro vận hành** | 🟡 Trung bình — file **ghi đè registry** `KeyManagementServiceName` (ảnh hưởng KMS hiện hữu của máy), và `/act` có thể chạy lặp cho nhiều bản Office |

---

## 7. ĐỀ XUẤT CẢI TIẾN FILE

```batch
:: 1. Cho phép override KMS server qua tham số dòng lệnh
set "KMS_SERVER=%~1"
if "%KMS_SERVER%"=="" set "KMS_SERVER=172.20.0.10"

:: 2. THÊM bước kiểm tra kênh bản quyền TRƯỚC khi kích hoạt
::    (phát hiện Retail → cảnh báo KMS không áp dụng)
cscript //nologo %SystemRoot%\System32\slmgr.vbs /dlv | findstr /i "RETAIL" && (
    echo [CANH BAO] Windows dang o kenh RETAIL - KMS khong ap dung!
    echo            Can cai ban VOLUME (Windows Pro Volume/Enterprise).
)

:: 3. Thêm kiểm tra kết nối KMS trước, tránh chờ timeout 60s
powershell -c "Test-NetConnection %KMS_SERVER% -Port %KMS_PORT% -InformationLevel Quiet" | findstr "False" && (
    echo [LOI] Khong ket noi duoc KMS %KMS_SERVER%:%KMS_PORT%
    exit /b 1
)

:: 4. Office: DỪNG sau bản đầu tiên tìm thấy (tránh /act lặp)
::    thay vì pushd/popd, dùng goto :office_done

:: 5. Ghi log kết quả ra file để audit
::    (phục vụ yêu cầu "xóa log" của đơn vị — có bằng chứng đã kích hoạt hợp lệ)
```

---

## 8. TÀI LIỆU THAM KHẢO

| Tài liệu | Nội dung |
|-----------|----------|
| `DS dia chi IP WAN LAN LD.md` (dòng 131) | Bộ CHQS tỉnh Lâm Đồng — LAN `86.134.32.0/24`, GW `86.134.32.254`, WAN `86.180.254.5`, GW WAN `86.180.254.1` |
| `reverse-skill-main/skills/malware-analysis/SKILL.md` | Quy trình 6 phase + cookbook U–AV cho script |
| `reverse-skill-main/skills/code-audit/SKILL.md` | Đối chiếu blacklist API |
| `reverse-skill-main/skills/windows-ad/SKILL.md` | Ngữ cảnh KMS/AD trong môi trường doanh nghiệp |
| Microsoft KB | KMS client ports (TCP 1688), NTP sync requirement, `/skms` `/ato` `/sethst` `/act` |
| Microsoft VL | Volume Licensing Agreement / GVL — điều kiện tiên quyết pháp lý |

---

## 9. CHECKLIST TỰ KIỂM (theo `malware-analysis` SKILL)

- [x] **Phase 1 — Triage**: loại file = script `.bat` (non-PE), 82 dòng, không BOM, hash SHA-256/MD5 đã ghi
- [x] **Phase 2 — Static**: đọc toàn bộ 82 dòng; quét blacklist API (0 hit); trích 1 network IOC; trích registry write path
- [x] **Cookbook U–AV**: U (SET) ✅ · V (BOM) ✅ · W (REM/GOTO) ✅ · X/Y (Base64) ✅ · Z (PowerShell) ✅
- [x] **Whitelist/blacklist**: 0 hành vi độc hại, 0 persistence, 0 exfil
- [x] **Bằng chứng có thể tái lập**: hash, lệnh test, giá trị registry đọc được
- [x] **Phân tích định tuyến**: đối chiếu bảng phân bổ IP đơn vị + test reachability thực tế
- [x] **Đánh giá pháp lý**: nêu rõ điều kiện tiên quyết GVL
- [x] **Không thực thi** file `.bat` trên máy phân tích (chỉ đọc `slmgr.vbs /dlv`, `ospp.vbs /dstatus` — lệnh read-only)

---

*Báo cáo được lập bằng phương pháp tĩnh, không thực thi `client-activate.bat`. Mọi thao tác registry/license đều là lệnh chỉ đọc (`/dlv`, `/dstatus`, `reg query`).*
