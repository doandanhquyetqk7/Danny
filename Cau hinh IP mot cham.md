# Xây dựng phần mềm "Cấu hình IP 1-chạm" cho môi trường quân sự

Xây dựng một phần mềm "Cấu hình IP 1-chạm" cho môi trường quân sự đòi hỏi sự kết hợp giữa kỹ thuật phân tích mạng (network sniffing/scanning) và thao tác hệ thống cấp thấp. Tiêu chí cốt lõi là sự tự động hóa hoàn toàn để người dùng không cần can thiệp kỹ thuật.

## 1. Cơ chế hoạt động cốt lõi (Workflow)

* **Nhận diện kết nối vật lý:** Phần mềm tự động kiểm tra các cổng mạng (Network Interfaces) trên máy tính. Nó sẽ bỏ qua các cổng ảo (VMware, VirtualBox) và chỉ chọn cổng LAN vật lý đang có trạng thái kết nối cáp (Link Up) nhưng chưa có IP hợp lệ (đang trống hoặc nhận IP lỗi `169.254.x.x`).
* **Lắng nghe thụ động (Passive Sniffing):** Thay vì quét mạng rải rác (Ping Sweep) có thể làm kích hoạt hệ thống báo động giám sát mạng quân sự (IDS/IPS), phần mềm dùng thư viện bắt gói tin để lắng nghe mạng. Bằng cách phân tích các gói tin ARP và UDP Broadcast đang bay trong LAN, nó có thể xác định được dải mạng (Subnet Mask) mà hệ thống đang sử dụng.
* **Xác định Default Gateway:** Phần mềm tìm địa chỉ MAC thực hiện trả lời nhiều truy vấn ARP nhất, hoặc các địa chỉ đang định tuyến dữ liệu ra ngoài dải mạng cục bộ. Thông thường, thuật toán có thể ưu tiên kiểm tra tĩnh các IP như `x.x.x.1` hoặc `x.x.x.254` dựa trên dải mạng vừa tìm được.
* **Thuật toán chọn IP an toàn:** Tránh các IP thường dùng cho máy chủ hoặc thiết bị mạng (từ `.1` đến `.50` hoặc `.250` đến `.254`). Phần mềm sẽ chọn ngẫu nhiên một IP ở khoảng giữa (ví dụ `.150` đến `.200`). Sau đó, nó gửi một gói ARP Probe vô danh; nếu sau 1-2 giây không có phản hồi, IP đó được xác nhận là đang trống và an toàn để sử dụng.

## 2. Kiến trúc các Module

* **Module Network Analyzer (Lõi phân tích):** Khuyến nghị sử dụng ngôn ngữ C/C++ hoặc Python (với thư viện Scapy) để xử lý gói tin thô. Module này chịu trách nhiệm trích xuất chính xác 3 thông số: IP đề xuất, Subnet Mask, và Gateway.
* **Module Executor (Thực thi cấu hình):** Tự động gọi API của hệ điều hành để áp dụng thông số mà không cần mở giao diện cài đặt mạng.
  * **Trên Windows:** Gọi ngầm dòng lệnh `netsh interface ip set address name="Ethernet" static [IP] [Subnet] [Gateway]`.
  * **Trên Linux:** Chạy ngầm lệnh `ip addr add` và `ip route add default`, hoặc tương tác qua `nmcli`.
* **Module UI (Giao diện One-Click):** Giao diện cực kỳ tối giản với một nút bấm duy nhất: "Kết nối mạng". Dưới nút bấm có thanh tiến trình hiển thị: *Đang phân tích mạng -> Đang tìm IP trống -> Hoàn tất*.

## 3. Tiêu chuẩn đặc thù cho Môi trường Quân sự

* **Hoạt động Độc lập (Standalone):** Đóng gói phần mềm thành một file thực thi duy nhất (Portable). Không yêu cầu kết nối Internet, không gửi telemetry, và không phụ thuộc vào các thư viện phải tải thêm.
* **Vượt quyền UAC / Admin:** Cấu hình IP yêu cầu quyền quản trị (Administrator/Root). Cần thiết lập phần mềm chạy dưới quyền System Services, hoặc cấu hình Windows Group Policy để cho phép người dùng thông thường chạy ứng dụng này với đặc quyền cao mà không bị hỏi mật khẩu.
* **Cơ chế Hoàn tác (Rollback):** Trước khi áp dụng, tự động sao lưu cấu hình cũ. Nếu IP mới áp dụng không thể ping được tới Gateway trong vòng 5 giây, phần mềm tự động khôi phục cấu hình cũ để tránh máy tính bị mất kết nối hoàn toàn.