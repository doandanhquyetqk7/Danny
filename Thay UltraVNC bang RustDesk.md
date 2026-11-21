Bạn là kỹ sư phần mềm Windows và an toàn thông tin mạng nội bộ. Hãy đọc và phân tích toàn bộ mã nguồn trong thư mục dự án `Danny-ver5.5` hiện tại.

### 1\. Mục tiêu

Thay thế hoàn toàn chức năng **Hỗ trợ kỹ thuật từ xa** hiện đang dùng **UltraVNC** bằng phần mềm **RustDesk** hoạt động ở chế độ **Direct IP Access** (kết nối trực tiếp qua địa chỉ IP nội bộ, **100% offline**, không sử dụng ID/Relay Server trung gian) để phục vụ hỗ trợ kỹ thuật trên mạng nội bộ cô lập.

### 2\. Yêu cầu khảo sát trước khi sửa code (Bắt buộc)

Trước khi chỉnh sửa bất kỳ tệp nào, hãy quét toàn bộ dự án và báo cáo ngắn gọn:

1. Ngôn ngữ lập trình, framework giao diện và cách đóng gói hiện tại của `Danny-ver5.5`.
2. Danh sách toàn bộ tệp mã nguồn, tài nguyên nhúng (embedded resources), tệp cấu hình, script và thành phần UI đang liên quan đến UltraVNC (ví dụ: `winvnc.exe`, `vncviewer.exe`, plugin `.dsm`, cổng `5500`/`5900`, rule Firewall cũ...).
3. Đề xuất kế hoạch thay thế chi tiết (tệp nào sửa, tệp nào thêm, tệp nào xóa) và chờ tôi xác nhận trước khi viết code.

### 3\. Yêu cầu kỹ thuật cho module RustDesk (Direct IP Access)

Sau khi tôi xác nhận kế hoạch, hãy triển khai module mới đáp ứng đầy đủ các tiêu chí sau:

* **Quản lý tệp thực thi RustDesk:**

  * Thay thế bộ tệp UltraVNC bằng tệp thực thi `rustdesk.exe` (giữ đúng cơ chế đóng gói/giải nén hoặc gọi file ngoài mà `Danny-ver5.5` đang áp dụng).
  * Kiểm tra tồn tại tệp `rustdesk.exe` trước khi chạy và thông báo lỗi rõ ràng nếu thiếu.
* **Cấu hình tự động Direct IP Access (100% Offline):**

  * Tự động khởi tạo/cập nhật tệp cấu hình `RustDesk2.toml` (xử lý đúng đường dẫn tương ứng với chế độ chạy: `%APPDATA%\\RustDesk\\config\\RustDesk2.toml` cho chế độ User và `C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Roaming\\RustDesk\\config\\RustDesk2.toml` nếu chạy dạng Windows Service).
  * Thiết lập trong mục `\[options]`:

    * `direct-server = 'Y'`
    * `direct-access-port = '21118'` (cho phép tùy chỉnh cổng trên giao diện nếu cần, mặc định `21118`)
    * `whitelist = '<IP hoặc dải CIDR máy kỹ thuật viên>'` (nếu người dùng nhập IP/dải IP được phép kết nối, nếu để trống thì không giới hạn)
    * `enable-lan-discovery = 'N'`
    * Bắt buộc cơ chế xác nhận an toàn: ưu tiên bật chế độ xin phép thủ công khi có kết nối tới hoặc dùng mật khẩu tạm thời (không để truy cập tự do không mật khẩu).
* **Xử lý quyền UAC \& Chế độ chạy (Phía máy cần hỗ trợ):**

  * Thiết kế nút **Bật hỗ trợ từ xa** và **Dừng hỗ trợ từ xa**.
  * Nếu phần mềm đang chạy với quyền Administrator, cung cấp tùy chọn cài/khởi chạy dịch vụ tạm thời của RustDesk (`--install-service`) để kỹ thuật viên thao tác được trên cửa sổ UAC; nếu không có quyền Admin thì tự động lùi về chế độ portable thông thường và cảnh báo nhẹ trên giao diện.
  * Tự động dò và hiển thị rõ trên UI: **Địa chỉ IPv4 nội bộ hiện tại** (lọc bỏ card ảo loopback/APIPA), **Cổng đang mở (21118)**, và nút **Sao chép IP** để người dùng đọc nhanh cho kỹ thuật viên.
  * Hiển thị ghi chú nhỏ trên UI: trạng thái "Not ready" màu đỏ bên trong cửa sổ RustDesk là bình thường khi chạy offline ở chế độ Direct IP, không phải lỗi.
* **Phía máy kỹ thuật viên (nếu `Danny-ver5.5` có sẵn chức năng Viewer/Điều khiển):**

  * Giữ bố cục tương đương tính năng kết nối cũ: ô nhập `IP` (hoặc `IP:Port`) máy cần hỗ trợ và nút **Kết nối**, khởi chạy RustDesk kết nối trực tiếp tới địa chỉ IP đó (`rustdesk.exe --connect <IP>:<Port>`).
* **Tự động đóng/mở Windows Firewall an toàn:**

  * Khi bấm **Bật hỗ trợ từ xa**: tự động tạo rule Windows Firewall cho phép **Inbound TCP cổng 21118** (nếu có nhập IP Whitelist thì khóa chặt tham số `RemoteAddress` theo đúng IP/dải IP đó).
  * Khi bấm **Dừng hỗ trợ từ xa** hoặc **đóng phần mềm `Danny-ver5.5`**: bắt buộc dừng tiến trình/dịch vụ RustDesk đang chạy và **xóa ngay rule Firewall vừa tạo** để không để hở cổng trên máy trạm.
* **Tính toàn vẹn \& Dọn dẹp mã nguồn:**

  * Gỡ bỏ sạch mã nguồn, tài nguyên, hằng số và chuỗi văn bản còn sót của UltraVNC để tránh phình dung lượng file đóng gói.
  * Không làm thay đổi giao diện tổng thể, phong cách viết code và các chức năng khác đang hoạt động ổn định trong `Danny-ver5.5`.
  * Bọc `try/catch` và ghi log lỗi rõ ràng cho mọi thao tác hệ thống (ghi file config, chạy `netsh`/PowerShell tạo rule Firewall, khởi tạo tiến trình).

### 4\. Đầu ra cần bàn giao sau khi hoàn thành

1. Mã nguồn đã cập nhật hoàn chỉnh và biên dịch sạch không lỗi/cảnh báo.
2. Hướng dẫn nơi đặt tệp `rustdesk.exe` trước khi build bản phát hành mới.
3. Danh sách kịch bản kiểm thử nhanh (test mở/đóng cổng bằng `Test-NetConnection`, test kết nối giữa 2 máy khác phân mạng, test tự động dọn rule Firewall khi thoát app).
4. Chức năng hỗ trợ kỹ thuật từ xa dùng chung cho cả máy kỹ thuật viên và máy cần hỗ trợ (có thêm ô nhập IP để điều khiển máy khác)
5. Dải IP Whitelist mặc định: Ví dụ "Điền sẵn mặc định dải IP quản trị 86.134.32.150/24 vào ô Whitelist nhưng vẫn cho phép người dùng sửa tay trên giao diện."
6. Sau khi hoàn thành đóng gói lại phần mềm thành phiên bản Danny-ver5.6 và tự động upload lên github của tôi tại đường dẫn https://github.com/doandanhquyetqk7 để tôi thuận tiện theo dõi thay đổi chức năng trong các phiên bản

