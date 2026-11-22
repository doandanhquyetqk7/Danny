Bạn là Kiến trúc sư Phần mềm Windows (C# / .NET / Python), Chuyên gia An ninh mạng – Điều tra Chứng cứ số (DFIR) cấp cao và Kỹ sư DevOps. Hãy đọc và phân tích toàn bộ mã nguồn dự án **Danny-ver5.6** hiện tại cùng hai tài liệu đặc tả đi kèm là `Bo sung chuc nang don dep.md` và `Chuc nang Forensic.md`, sau đó thực hiện nâng cấp, đóng gói sản phẩm và tự động đẩy lên một nhánh (Branch) mới trên GitHub theo đúng các yêu cầu chi tiết dưới đây.

---

### QUY TRÌNH LÀM VIỆC BẮT BUỘC (KHẢO SÁT TRƯỚC KHI SỬA CODE)
Trước khi chỉnh sửa bất kỳ tệp nào, hãy quét toàn bộ mã nguồn `Danny-ver5.6` và báo cáo ngắn gọn:
1. Ngôn ngữ lập trình, framework giao diện (WinForms/WPF/PyQt...), kiến trúc thư mục, cấu trúc nhánh Git hiện tại và cơ chế đóng gói (bao gồm thư mục `tools/`).
2. Vị trí chính xác các tệp mã nguồn, control UI, sự kiện (event handlers) liên quan tới từng hạng mục cần Xóa / Điều chỉnh / Thêm mới.
3. Kế hoạch triển khai chi tiết (tệp nào xóa, tệp nào sửa, tệp nào tạo mới, phương án tích hợp Acronis CLI, module Forensic, tên phiên bản mới và tên Branch GitHub dự kiến). Chờ tôi xác nhận kế hoạch rồi mới bắt đầu viết code.

---

### PHẦN 1: CÁC CHỨC NĂNG CẦN XÓA KHỎI DANNY-VER5.6
1. **Trong tab `BẢO MẬT & TIỆN ÍCH`:**
   - Xóa hoàn toàn chức năng và giao diện của **“Xóa nhật ký Event Viewer”** (việc xóa Event Log sẽ được tích hợp vào tab `LÀM SẠCH PC MỘT CHẠM` ở Phần 2).
   - Xóa hoàn toàn nút bấm và giao diện của **“Chạy Kaspersky (KVRT)”**. *(Lưu ý quan trọng: chỉ gỡ khỏi tab `BẢO MẬT & TIỆN ÍCH`; giữ lại tệp KVRT trong thư mục `tools/` và không làm hỏng lời gọi KVRT nếu các tab/quy trình khác vẫn đang dùng).*
2. **Xóa hoàn toàn tab `CẤU HÌNH MẠNG`:**
   - Gỡ bỏ tab trên thanh điều hướng chính, xóa các form/user control, event handler, lớp xử lý và hằng số không còn được tham chiếu ở nơi khác để mã nguồn sạch sẽ.

---

### PHẦN 2: CÁC CHỨC NĂNG CẦN ĐIỀU CHỈNH & BỔ SUNG

#### 2.1. Tính năng tự động cập nhật Kaspersky Virus Removal Tool (KVRT)
- **Mục tiêu:** Tự động cập nhật bản mới nhất của *Kaspersky Virus Removal Tool for Windows®* (nhằm cập nhật Digital Signatures và CSDL nhận diện mã độc mới nhất) và chép đè vào bản sẵn có trong thư mục `tools/` khi máy tính có kết nối Internet.
- **Yêu cầu kỹ thuật:**
  - Chạy kiểm tra kết nối Internet ở luồng nền bất đồng bộ (async, không chặn UI). Nếu máy đang ở mạng cô lập/offline, **bỏ qua âm thầm** (fail-soft, chỉ ghi log trạng thái offline, không bật hộp thoại lỗi gây phiền).
  - Khi có Internet, truy cập `https://www.kaspersky.com/downloads/free-virus-removal-tool` (phân tích liên kết tải trực tiếp *Kaspersky Virus Removal Tool for Windows®* hoặc gọi đúng endpoint tải bản mới nhất của Kaspersky) để kiểm tra và tải xuống.
  - **Cơ chế thay thế an toàn (Atomic Replace):**
    1. Tải tệp mới về tệp tạm (`tools\KVRT_update.tmp`), hiển thị tiến độ/trạng thái cập nhật nhẹ trên thanh trạng thái.
    2. Xác thực tệp tải về: kiểm tra tệp không rỗng, đúng định dạng PE (`.exe`), và kiểm tra chữ ký số Authenticode hợp lệ thuộc Kaspersky trước khi thay thế.
    3. Sao lưu tạm tệp hiện có thành `.bak`, chép đè tệp mới vào đúng đường dẫn tệp KVRT sẵn có trong `tools/`, sau đó xóa `.bak` (nếu ghi đè thất bại thì tự khôi phục `.bak`).
  - Bổ sung tùy chọn bật/tắt tự động cập nhật hoặc nút "Kiểm tra cập nhật KVRT ngay" để kỹ thuật viên chủ động sử dụng.

#### 2.2. Tách chức năng “Hiện File/Folder ẩn” thành một Tab riêng
- Tách toàn bộ chức năng **“Hiện File/Folder ẩn”** từ vị trí cũ trong `Danny-ver5.6` đưa lên thành một **Tab độc lập** trên thanh điều hướng chính.
- Giữ nguyên toàn bộ logic xử lý đang hoạt động ổn định, đồng thời tối ưu lại bố cục UI cho gọn gàng: chọn ổ đĩa/thư mục đích, tùy chọn quét đệ quy, hiển thị tiến trình và bảng/log danh sách tệp/thư mục đã khôi phục thuộc tính ẩn (`attrib -h -s` hoặc tương đương).

#### 2.3. Nâng cấp tab “LÀM SẠCH PC MỘT CHẠM” (theo `Bo sung chuc nang don dep.md`)
Đọc kỹ nội dung `Bo sung chuc nang don dep.md` và bổ sung đầy đủ các hạng mục dọn dẹp vào tab **“LÀM SẠCH PC MỘT CHẠM”** theo đúng trình tự 4 bước chuẩn sau:
- **Yêu cầu quyền & Cảnh báo vận hành:**
  - Kiểm tra quyền `Administrator` trước khi chạy.
  - Hiển thị hộp thoại xác nhận rõ ràng trước khi thực thi: *"Chức năng can thiệp sâu vào hệ thống. Yêu cầu chạy phần mềm bằng quyền Run as Administrator. Thao tác này không thể hoàn tác!"*
- **Trình tự thực thi 4 bước (chạy bất đồng bộ, hiển thị log chi tiết từng bước):**
  1. **Bước 1 — Xóa tệp rác (`LogCleaner.ClearTempFilesAsync` — H1):**
     - Dọn dẹp các tệp tin trong `%TEMP%`, `C:\Windows\Temp`, `C:\Windows\Prefetch`, và `C:\Windows\SoftwareDistribution\Download`. Thống kê số tệp đã xóa và số tệp bỏ qua (đang bị tiến trình khác khóa).
  2. **Bước 2 — Xóa lịch sử trình duyệt (`AdvancedLogCleaner.ClearAllBrowsersAsync` — H3):**
     - Tắt triệt để các tiến trình trình duyệt đang chạy: `chrome`, `msedge`, `browser` (Cốc Cốc), `firefox`.
     - Xóa tệp `History`, `Cache` (Chrome, Edge, Cốc Cốc) và `places.sqlite` (Firefox).
  3. **Bước 3 — Xóa sâu lịch sử USB (`AdvancedLogCleaner.ClearUsbHistoryAsync` — H2):**
     - Gọi Win32 Native API `ntdll!RtlAdjustPrivilege` bật đặc quyền `SeBackupPrivilege` / `SeRestorePrivilege`.
     - Sử dụng `RegistrySecurity` / `SetAccessControl` + `TakeOwnership` chiếm quyền sở hữu các khóa Registry được bảo vệ, sau đó xóa:
       - `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\*`
       - `HKLM\SYSTEM\CurrentControlSet\Enum\USB\*`
       - Các nhánh `DeviceClasses\{53f56307…}`, `{53f5630d…}`, `{10497b1b…}`
       - `HKLM\SYSTEM\MountedDevices` (**bắt buộc loại trừ `\DosDevices\C:`** để không làm lỗi khởi động hệ điều hành)
       - `EMDMgmt`
       - `HKLM\SOFTWARE\Microsoft\Windows Portable Devices\Devices`
       - `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2` (**bắt buộc loại trừ `CPC`**)
     - Xóa nhật ký cài đặt thiết bị: `C:\Windows\inf\setupapi.*.log`.
  4. **Bước 4 — Xóa sạch Nhật ký Event Log (`LogCleaner.ClearWindowsEventLogsAsync` — G8):**
     - Thực thi `wevtutil.exe el` lấy danh sách toàn bộ kênh nhật ký (`Security`, `System`, `Application`, `Operational`...) và gọi `wevtutil.exe cl <từng_log>` qua `cmd.exe`.
- **Yêu cầu chuẩn hóa kiến trúc (bắt buộc):**
  - Chuẩn hóa kết quả từng tác vụ bằng enum `CheckOutcome { Pass, Warn, Fail, Skipped, Error }` kèm trường `SkipReason` chi tiết; **cấm dùng khối `catch {}` rỗng** làm mất dấu vết lỗi.
  - Kiểm tra ACL chặt chẽ trước khi thao tác tệp/thư mục; tách biệt rõ module dọn rác hệ thống thông thường với module can thiệp Registry sâu.
  - Cho phép người dùng tích chọn từng hạng mục (hoặc chọn tất cả 1 chạm) nhưng vẫn giữ mặc định đúng thứ tự 4 bước trên.

#### 2.4. Thêm tab chức năng mới: “SAO LƯU MÁY TÍNH”
Xây dựng một tab mới chuyên dụng để sao lưu hệ thống và dữ liệu người dùng với các ràng buộc nghiêm ngặt:
- **Ràng buộc ổ cứng đích (BẮT BUỘC KIỂM TRA TRƯỚC KHI CHO PHÉP CHẠY):**
  - Tự động quét danh sách ổ đĩa vật lý qua WMI (`Win32_DiskDrive` → `Win32_DiskPartition` → `Win32_LogicalDisk`).
  - **Chỉ chấp nhận ổ cứng di động gắn ngoài (USB / External Drive)** có tổng dung lượng danh định **tối thiểu 1 TB** *(lưu ý kỹ thuật: ổ cứng 1 TB thực tế trên Windows hiển thị khoảng ~931 GiB, nên dùng ngưỡng kiểm tra vật lý `Size >= 930 GiB` hoặc `>= 1,000,000,000,000 bytes` để không chặn nhầm ổ 1 TB thật)*.
  - **Tuyệt đối không cho phép lưu bản sao lưu vào bất kỳ phân vùng nào thuộc ổ cứng gắn trong (internal disk).** Nếu chưa cắm ổ cứng di động ≥ 1 TB, khóa nút "Bắt đầu sao lưu" và hiển thị cảnh báo đỏ rõ ràng hướng dẫn người dùng cắm đúng ổ cứng di động tối thiểu 1 TB.
  - Kiểm tra dung lượng trống còn lại trên ổ di động so với tổng dung lượng cần sao lưu trước khi bắt đầu.
- **Chức năng 1 — Sao lưu Hệ thống Windows (Full Disk / System Image) bằng Acronis Engine:**
  - Tích hợp gọi engine dòng lệnh của Acronis (ví dụ `acrocmd.exe` / Acronis True Image CLI đặt trong `tools\acronis\` hoặc đường dẫn cài đặt Acronis trên máy; nếu chưa có tệp engine thì thông báo rõ đường dẫn cần đặt và cho phép người dùng chọn đường dẫn engine).
  - Thiết lập tham số sao lưu **Full Disk / System Image** cho ổ đĩa chứa Windows: bắt buộc sao lưu trọn vẹn **EFI System Partition (ESP)**, **MSR (Microsoft Reserved Partition)**, **Recovery Partition**, phân vùng hệ điều hành (`C:\`) và **cấu trúc bảng phân vùng (GPT/MBR)** nhằm đảm bảo khôi phục được trên phần cứng mới hoặc ổ cứng mới.
  - Đặt tên thư mục/tệp ảnh hệ thống theo cấu trúc `<TenMay>_<yyyyMMdd_HHmmss>\SystemImage\`.
- **Chức năng 2 — Sao lưu Dữ liệu người dùng bằng Robocopy Engine:**
  - Tự động phát hiện và liệt kê các phân vùng dữ liệu gắn trong (`D:\`, `E:\`, ... — tự động loại trừ phân vùng hệ thống `C:\` và ổ cứng di động đích), cho phép người dùng tích chọn phân vùng/thư mục cần sao lưu.
  - Gọi `robocopy.exe` của Windows với bộ tham số an toàn, tối ưu tốc độ và tránh vòng lặp junction: `/E /COPY:DAT /DCOPY:T /R:2 /W:3 /MT:8 /XJ /XD "$RECYCLE.BIN" "System Volume Information" /UNILOG+:<file_log>` (lưu vào `<O_Di_Dong>\<TenMay>_<yyyyMMdd_HHmmss>\UserData\Drive_D\`, `Drive_E\`, ...).
- **Giao diện & Quản lý tiến trình:**
  - Cho phép chạy riêng từng phần (chỉ System Image hoặc chỉ User Data) hoặc chạy nối tiếp cả hai.
  - Hiển thị thanh tiến trình, dung lượng đã sao lưu, log thời gian thực (stdout/stderr của Acronis CLI & Robocopy), nút Hủy an toàn và thông báo tổng kết sau khi hoàn tất.

#### 2.5. Thêm tab chức năng mới: “KIỂM TRA AN TOÀN THÔNG TIN” (theo `Chuc nang Forensic.md`)
Đọc toàn bộ đặc tả trong `Chuc nang Forensic.md` và xây dựng thành một tab điều tra chứng cứ số (DFIR) chuyên sâu, **tách biệt hoàn toàn** với tab Dọn dẹp:
- **Mục tiêu điều tra 2 nhóm sự cố:**
  1. Dấu hiệu kết nối ra Internet trái phép trên máy mạng nội bộ/đặc thù (dual-homed, rogue Wi-Fi/hotspot, USB tethering, proxy/VPN/tunneling, DNS tunneling, thay đổi route/gateway/DNS).
  2. Dấu hiệu lộ lọt tài liệu ra ngoài Internet (web upload, email web, cloud drive, FTP/SFTP/SCP, messaging apps, nén/mã hóa/chia nhỏ file trước khi gửi, hoặc sao chép qua thiết bị lưu trữ trung gian).
- **Nguyên tắc Forensic bắt buộc:**
  - **Chế độ Read-Only / Minimal Footprint:** tuyệt đối không sửa đổi, ghi đè hoặc xóa dữ liệu trên máy đích; ưu tiên đọc trực tiếp raw artifacts / VSS / Event Logs / Registry Hives / bảng mạng.
  - **Bảo toàn tính toàn vẹn chứng cứ:** tự động tính mã băm **SHA-256** cho mọi artifact thu thập được; ghi nhận đồng thời **UTC + Local time**, thông tin máy thu thập, phiên bản công cụ và xuất tệp **`manifest.sha256`** chống sửa đổi.
  - Hỗ trợ chế độ chạy cục bộ trên máy trạm, tùy chọn thu thập từ xa qua WinRM/SSH (nếu người dùng cấu hình), và chế độ **Dry-run / Test trên dữ liệu mẫu**.
- **Triển khai đầy đủ 4 phân hệ:**
  1. **Evidence Collector (Thu thập chứng cứ):**
     - *Mạng & kết nối:* bảng định tuyến (routing table), ARP cache, DNS cache, danh sách interface/adapter (card mạng ảo, Wi-Fi, Bluetooth, RNDIS/USB tethering), cấu hình proxy/PAC/WinHTTP, kết nối đang mở và lịch sử kết nối (ETW / NetSession / Firewall logs).
     - *Dấu vết truy cập & lộ lọt tài liệu:* NTFS `$UsnJrnl`, ShellBags, JumpLists, RecentFiles, LNK files, Prefetch; dấu vết nén/mã hóa/tập hợp tài liệu bất thường (`7z`, `rar`, `zip`, `tar`, thư mục tạm/staging); dấu vết thiết bị lưu trữ gắn ngoài & đồng bộ (`USBSTOR`, `SetupAPI logs`, volume serials, cloud sync folders); lịch sử trình duyệt & ứng dụng mạng (Chrome/Edge/Firefox history, downloads, cookies/session liên quan dịch vụ lưu trữ/gửi file, cache/log ứng dụng chat/mail nếu có).
     - *Hệ thống & tiến trình:* tiến trình đang chạy, dịch vụ, scheduled tasks, autorun/persistence, Windows Event Logs (`Security`, `System`, `PowerShell`, `Defender/EDR`, `Firewall`) liên quan thay đổi mạng, đăng nhập, truy cập file và kết nối ngoài.
  2. **Forensic Analyzer & Rule Engine (Phân tích & Phát hiện bất thường):**
     - Bộ quy tắc cấu hình ngoài (JSON/YAML) phát hiện kết nối Internet trái phép (default gateway lạ, DNS ngoài vùng cho phép, lưu lượng bất thường theo cổng/giao thức, kết nối qua interface ngoài dải IP nội bộ chuẩn, công cụ tunneling/remote/proxy).
     - Bộ quy tắc phát hiện rò rỉ tài liệu (truy cập hàng loạt tài liệu nhạy cảm trong thời gian ngắn, tạo file nén lớn ngay trước khi có kết nối ngoài, gửi/upload dữ liệu dung lượng lớn bất thường, dấu hiệu anti-forensics như xóa log/xóa lịch sử trình duyệt).
     - Chấm điểm **Risk/Severity Scoring** kèm giải thích bằng chứng cụ thể (quy tắc nào kích hoạt, căn cứ từ artifact nào).
  3. **Timeline & Correlation Engine (Dòng thời gian & Tương quan):**
     - Hợp nhất sự kiện từ nhiều nguồn về một trục thời gian chuẩn hóa (giây/mili-giây).
     - Tự động lọc và làm nổi bật chuỗi tương quan hành vi: `[Truy cập/sửa tài liệu]` → `[Đóng gói/nén/đổi tên]` → `[Thiết lập kết nối ra ngoài]` → `[Truyền dữ liệu đi]`.
  4. **Reporting & Evidence Packager (Xuất báo cáo & Đóng gói chứng cứ):**
     - Xuất báo cáo chi tiết (hỗ trợ **HTML / Markdown / PDF** và dữ liệu **JSON / CSV**) gồm: Executive Summary & mức độ nghi ngờ lộ lọt; hồ sơ máy tính & môi trường mạng; danh sách IOCs/Artifacts kèm đường dẫn gốc, thời gian, SHA-256; dòng thời gian trọng yếu & chuỗi tương quan; khuyến nghị xử lý tiếp theo (cô lập máy, thu giữ ảnh đĩa, rà soát máy lân cận) và nêu rõ các hạn chế kỹ thuật (mất volatile data khi tắt máy, file xóa vĩnh viễn, mã hóa đầu-cuối).
     - Đóng gói toàn bộ dữ liệu thô + báo cáo + tệp `manifest.sha256` vào một thư mục/gói chứng cứ duy nhất.
- **Lưu ý tích hợp kỹ thuật:** Đề xuất phương án tích hợp sạch nhất với ngôn ngữ gốc của `Danny-ver5.6` (viết native theo ngôn ngữ chính của dự án hoặc xây dựng engine Python 3.11+ có cấu trúc module rõ ràng gọi từ UI qua tiến trình nền, hỗ trợ chạy hoàn toàn offline trên Windows).

---

### PHẦN 3: TỰ ĐỘNG ĐÓNG GÓI SẢN PHẨM & UPLOAD LÊN GITHUB (BRANCH MỚI)
Sau khi hoàn thiện toàn bộ mã nguồn và kiểm tra biên dịch không lỗi, hãy xây dựng kịch bản tự động hóa (`build_and_publish.ps1`) **và thực thi ngay quy trình đóng gói + đẩy lên GitHub**:

1. **Cấu hình Repository đích & Quản lý nhánh (Branch):**
   - Repository đích: `https://github.com/doandanhquyetqk7/Danny`
   - Kiểm tra `git remote -v` (nếu chưa cấu hình `origin` thì thiết lập trỏ đúng tới `https://github.com/doandanhquyetqk7/Danny.git`), thực hiện `git fetch origin` để đồng bộ trạng thái mới nhất.
   - **Tạo một Branch mới hoàn toàn** xuất phát từ nhánh hiện tại/nhánh chính (đặt tên rõ ràng để dễ theo dõi phiên bản, ví dụ: `release/Danny-ver5.7-yyyyMMdd` hoặc `Danny-ver6.0` tùy theo quy ước đặt tên hiện có của repo). **Tuyệt đối không push trực tiếp hay force-push đè lên nhánh `main`.**

2. **Đóng gói sản phẩm (Build & Package):**
   - Biên dịch bản phát hành sạch (Release build) vào thư mục phiên bản mới (ví dụ `Danny-ver5.7/` hoặc thư mục `dist/` đồng bộ với cách tổ chức các bản `Danny-ver5.5`, `Danny-ver5.6` trước đó).
   - Tạo tệp `CHANGELOG.md` ghi rõ toàn bộ các thay đổi so với `Danny-ver5.6` (những gì đã xóa, đã điều chỉnh, đã bổ sung) và tạo tệp `SHA256SUMS.txt` cho tệp thực thi/gói nén phát hành.

3. **Kiểm tra an toàn & Xử lý giới hạn dung lượng GitHub (100 MB):**
   - Rà soát `.gitignore` để **không commit** thư mục build tạm (`obj/`, `bin/Debug/`, `__pycache__/`), file log chạy thử, dữ liệu Forensic mẫu nhạy cảm, hay bất kỳ khóa/mật khẩu/token nào.
   - Sử dụng thông tin xác thực Git sẵn có trên máy (Git Credential Manager, SSH Key, hoặc GitHub CLI `gh`); **không hardcode Personal Access Token** vào mã nguồn hay script.
   - **Kiểm tra tự động kích thước từng tệp trước khi commit:**
     - Nếu toàn bộ tệp đóng gói đều `< 95 MB`: thực hiện `git add`, `git commit` (message chuẩn theo Conventional Commits mô tả chi tiết thay đổi) và `git push -u origin <ten-branch-moi>`.
     - Nếu tệp đóng gói (`.exe` / `.zip`) hoặc tệp trong `tools/` vượt quá `95 MB` (tránh lỗi `GH001: Large files detected` của GitHub): tự động xử lý bằng một trong hai cơ chế (ưu tiên theo công cụ sẵn có trên máy):
       - **Cách 1 (Ưu tiên):** Đẩy toàn bộ mã nguồn + `CHANGELOG.md` + `SHA256SUMS.txt` lên Branch mới, đồng thời dùng GitHub CLI (`gh release create`) đính kèm gói sản phẩm đóng gói (`.zip`/`.exe`) vào bản Release gắn tag trên đúng Branch mới đó.
       - **Cách 2:** Cấu hình **Git LFS** (`git lfs track`) cho tệp thực thi/nén lớn rồi push lên Branch mới.
       - Nếu cả `gh` và `git-lfs` đều chưa cài đặt, tự động tách tệp đóng gói lớn khỏi commit, push thành công toàn bộ mã nguồn lên Branch mới và in ra chính xác lệnh để tôi hoàn tất upload gói binary.

4. **Xác nhận sau khi đẩy lên GitHub:**
   - Sau khi `git push` thành công, hiển thị đầy đủ: tên Branch mới đã tạo, mã Commit SHA, đường dẫn trực tiếp tới Branch trên GitHub (`https://github.com/doandanhquyetqk7/Danny/tree/<ten-branch-moi>`), và đường dẫn tạo Pull Request (nếu cần gộp về `main` sau này).

---

### PHẦN 4: YÊU CẦU CHẤT LƯỢNG & BÀN GIAO
1. Giữ đồng nhất giao diện, font chữ, bảng màu và phong cách điều hướng hiện có của `Danny-ver5.6`; mọi tác vụ nặng đều chạy bất đồng bộ để không treo UI.
2. Đảm bảo phần mềm biên dịch/đóng gói sạch, không lỗi, không còn mã rác từ các chức năng đã xóa.
3. Sau khi hoàn thành, bàn giao:
   - Danh sách các tệp đã xóa / sửa / thêm mới.
   - Hướng dẫn cấu trúc thư mục `tools/` (vị trí đặt `KVRT.exe`, engine `Acronis CLI`, và file cấu hình rule Forensic).
   - Hướng dẫn chạy lại kịch bản `build_and_publish.ps1` cho các lần cập nhật phiên bản sau.
   - Kịch bản kiểm thử nhanh cho từng tab mới (test cập nhật KVRT online/offline, test chặn ổ cứng gắn trong & ổ < 1 TB ở tab Sao lưu, test dry-run Forensic và kiểm tra `manifest.sha256`).