# Tích hợp chức năng kiểm tra kết nối vào NetSecTool

## 1. Kiến trúc và Quy trình Chẩn đoán (Diagnostic Pipeline)

Phần mềm nên được thiết kế theo cơ chế tuần tự từ thấp lên cao (Bottom-Up). Nếu một bước thất bại, phần mềm có thể dừng lại hoặc đưa ra cảnh báo cụ thể tại lớp đó mà không cần chạy tiếp các bước trên.

### Bước 1: Kiểm tra Cổng mạng Vật lý & Trạng thái Liên kết (Layer 1 - Physical & Link)
* **Mục tiêu:** Xác định cáp mạng đã cắm chưa, cổng Switch/NIC có đang "Link Up" không, tốc độ kết nối (Link Speed) là bao nhiêu.
* **Cách thực thi kỹ thuật:**
  * Truy vấn trạng thái giao diện mạng thông qua API hệ thống hoặc lệnh PowerShell/WMI.
  * Kiểm tra các thông số: Media Connected, Link Speed (ví dụ: 1 Gbps / 100 Mbps), Duplex.
* **Gợi ý mã lệnh (Python/PowerShell):** Sử dụng thư viện `psutil` hoặc lệnh `netsh interface show interface`.

---

### Bước 2: Kiểm tra Driver và Trạng thái Card mạng (Driver & Interface Health)
* **Mục tiêu:** Phát hiện lỗi driver, card mạng bị vô hiệu hóa (Disabled), xung đột phần cứng hoặc lỗi mã nguồn thiết bị (Device Error Code).
* **Cách thực thi kỹ thuật:**
  * Kiểm tra trạng thái hoạt động của `Win32_NetworkAdapter` (xem có đang bị disable hay lỗi driver Config Manager ErrorCode).
  * Lấy thông tin phiên bản Driver, địa chỉ MAC, và cấu hình IP hiện tại (DHCP hay Static, có bị xung đột IP hay không).

---

### Bước 3: Kiểm tra Kết nối Cục bộ & Cổng Gateway / Modem (Layer 2 & 3 - Local Connectivity)
* **Mục tiêu:** Kiểm tra card mạng có liên lạc được với thiết bị mạng gần nhất không (Default Gateway / Địa chỉ WAN của modem).
* **Cách thực thi kỹ thuật:**
  * Tự động phát hiện Default Gateway hiện tại của máy tính.
  * Thực hiện lệnh `ping` tới Default Gateway hoặc địa chỉ WAN của modem.
  * Đo độ trễ (latency) và tỷ lệ mất gói tin (packet loss).

#### Bảng địa chỉ WAN modem của các đơn vị trực thuộc Bộ CHQS tỉnh Lâm Đồng

| Tên đơn vị | Địa chỉ WAN Modem |
| :--- | :--- |
| Bộ CHQS tỉnh Lâm Đồng | 86.180.254.5 |
| Trường TSQMN phân hiệu 1 | 86.134.240.57 |
| Trung đoàn 40 | 86.68.252.151 |
| Ban CHQS xã Bảo Lâm 1 | 86.134.240.121 |
| Ban CHQS Phường La Gi | 86.134.240.5 |
| Trung đoàn 812 cơ sở 2 | 86.128.255.138 |
| Trung đoàn 994A | 86.64.240.73 |
| Trung đoàn 994B | 86.146.240.57 |
| Trung đoàn 812 | 86.146.240.12 |
| Ban CHQS phường Xuân Hương | 86.250.220.1 |
| Ban CHQS phường Cam Ly | 86.250.220.3 |
| Ban CHQS phường Lang BiAng | 86.250.220.5 |
| Ban CHQS phường Xuân Trường | 86.250.220.7 |
| Ban CHQS phường Lâm Viên | 86.250.220.9 |
| Ban CHQS xã Lạc Dương | 86.250.220.11 |
| Ban CHQS xã Hiệp Thạnh | 86.250.220.13 |
| Ban CHQS xã Đức Trọng | 86.250.220.15 |
| Ban CHQS xã Tân Hội | 86.250.220.17 |
| Ban CHQS xã Ninh Gia | 86.250.220.19 |
| Ban CHQS xã Tà Hine | 86.250.220.21 |
| Ban CHQS xã Tà Năng | 86.250.220.23 |
| Ban CHQS xã Đơn Dương | 86.250.220.25 |
| Ban CHQS xã Ka Đô | 86.250.220.27 |
| Ban CHQS xã Quảng Lập | 86.250.220.29 |
| Ban CHQS xã Dran | 86.250.220.31 |
| Ban CHQS xã Đình Văn | 86.250.220.33 |
| Ban CHQS xã Nam Ban | 86.250.220.35 |
| Ban CHQS xã Phúc Thọ | 86.250.220.37 |
| Ban CHQS xã Nam Hà | 86.250.220.39 |
| Ban CHQS xã Phú Sơn | 86.250.220.41 |
| Ban CHQS xã Tân Hà | 86.250.220.43 |
| Ban CHQS xã Đam Rông 1 | 86.250.220.45 |
| Ban CHQS xã Đam Rông 2 | 86.250.220.47 |
| Ban CHQS xã Đam Rông 3 | 86.250.220.49 |
| Ban CHQS xã Đam Rông 4 | 86.250.220.51 |
| Ban CHQS xã Di Linh | 86.250.220.53 |
| Ban CHQS xã Đinh Trang Thượng | 86.250.220.55 |
| Ban CHQS xã Sơn Điền | 86.250.220.57 |
| Ban CHQS xã Bảo Thuận | 86.250.220.59 |
| Ban CHQS xã Gia Hiệp | 86.250.220.61 |
| Ban CHQS xã Hoà Ninh | 86.250.220.63 |
| Ban CHQS xã Hoà Bắc | 86.250.220.65 |
| Ban CHQS phường 1 | 86.250.220.67 |
| Ban CHQS phường 2 | 86.250.220.69 |
| Ban CHQS phường 3 | 86.250.220.71 |
| Ban CHQS phường BLao | 86.250.220.73 |
| Ban CHQS xã Bảo Lâm 2 | 86.250.220.77 |
| Ban CHQS xã Bảo Lâm 3 | 86.250.220.79 |
| Ban CHQS xã Bảo Lâm 4 | 86.250.220.81 |
| Ban CHQS xã Bảo Lâm 5 | 86.250.220.83 |
| Ban CHQS xã Đạ Huoai | 86.250.220.85 |
| Ban CHQS xã Đạ Huoai 2 | 86.250.220.87 |
| Ban CHQS xã Đạ Huoai 3 | 86.250.220.89 |
| Ban CHQS xã Đạ Tẻh | 86.250.220.91 |
| Ban CHQS xã Đạ Tẻh 2 | 86.250.220.93 |
| Ban CHQS xã Đạ Tẻh 3 | 86.250.220.95 |
| Ban CHQS xã Cát Tiên | 86.250.220.97 |
| Ban CHQS xã Cát Tiên 2 | 86.250.220.99 |
| Ban CHQS xã Cát Tiên 3 | 86.250.220.101 |
| Ban CHQS xã Kiến Đức | 86.250.220.103 |
| Ban CHQS xã Nhân Cơ | 86.250.220.105 |
| Ban CHQS xã Quảng Tín | 86.250.220.107 |
| Ban CHQS xã Tà Đùng | 86.250.220.109 |
| Ban CHQS xã Quảng Khê | 86.250.220.111 |
| Ban CHQS xã Quảng Hoà | 86.250.220.113 |
| Ban CHQS xã Đắk Wil | 86.250.220.115 |
| Ban CHQS xã Nam Dong | 86.250.220.117 |
| Ban CHQS xã Cư Jút | 86.250.220.119 |
| Ban CHQS xã Thuận An | 86.250.220.121 |
| Ban CHQS xã Đức Lập | 86.250.220.123 |
| Ban CHQS xã Đắk Mil | 86.250.220.125 |
| Ban CHQS xã Đắk Săn | 86.250.220.127 |
| Ban CHQS xã Nam Đà | 86.250.220.129 |
| Ban CHQS xã Krông Nô | 86.250.220.131 |
| Ban CHQS xã Nậm Nung | 86.250.220.133 |
| Ban CHQS xã Quảng Phú | 86.250.220.135 |
| Ban CHQS xã Đắk Song | 86.250.220.137 |
| Ban CHQS xã Đức An | 86.250.220.139 |
| Ban CHQS xã Thuận Hạnh | 86.250.220.141 |
| Ban CHQS xã Trường Xuân | 86.250.220.143 |
| Ban CHQS xã Quảng Sơn | 86.250.220.145 |
| Ban CHQS Phường Bắc Gia Nghĩa | 86.250.220.147 |
| Ban CHQS Phường Đông Gia Nghĩa | 86.250.220.149 |
| Ban CHQS Phường Nam Gia Nghĩa | 86.250.220.151 |
| Ban CHQS xã Quảng Trực | 86.250.220.153 |
| Ban CHQS xã Quảng Tân | 86.250.220.155 |
| Ban CHQS xã Tuy Đức | 86.250.220.157 |
| Ban CHQS xã Hàm Thạnh | 86.250.220.159 |
| Ban CHQS xã Hàm Kiệm | 86.250.220.161 |
| Ban CHQS xã Tân Thành | 86.250.220.163 |
| Ban CHQS xã Hàm Thuận Nam | 86.250.220.165 |
| Ban CHQS xã Tân Lập | 86.250.220.167 |
| Ban CHQS xã Tân Minh | 86.250.220.169 |
| Ban CHQS xã Hàm Tân | 86.250.220.171 |
| Ban CHQS xã Sơn Mỹ | 86.250.220.173 |
| Ban CHQS Phường Phước Hội | 86.250.220.177 |
| Ban CHQS xã Tân Hải | 86.250.220.179 |
| Ban CHQS xã Nghị Đức | 86.250.220.181 |
| Ban CHQS xã Bắc Ruộng | 86.250.220.183 |
| Ban CHQS xã Đồng Kho | 86.250.220.185 |
| Ban CHQS xã Tánh Linh | 86.250.220.187 |
| Ban CHQS xã Suối Kiết | 86.250.220.189 |
| Ban CHQS xã Nam Thành | 86.250.220.191 |
| Ban CHQS xã Đức Linh | 86.250.220.193 |
| Ban CHQS xã Hoài Đức | 86.250.220.195 |
| Ban CHQS xã Trà Tân | 86.250.220.197 |
| Ban CHQS xã Vĩnh Hảo | 86.250.220.199 |
| Ban CHQS xã Liên Hương | 86.250.220.201 |
| Ban CHQS xã Tuy Phong | 86.250.220.203 |
| Ban CHQS xã Phan Rí Cửa | 86.250.220.205 |
| Ban CHQS xã Bắc Bình | 86.250.220.207 |
| Ban CHQS xã Hồng Thái | 86.250.220.209 |
| Ban CHQS xã Hải Ninh | 86.250.220.211 |
| Ban CHQS xã Phan Sơn | 86.250.220.213 |
| Ban CHQS xã Sông Luy | 86.250.220.215 |
| Ban CHQS xã Lương Sơn | 86.250.220.217 |
| Ban CHQS xã Hoà Thắng | 86.250.220.219 |
| Ban CHQS xã Đông Giang | 86.250.220.221 |
| Ban CHQS xã La Dạ | 86.250.220.223 |
| Ban CHQS xã Hàm Thuận Bắc | 86.250.220.225 |
| Ban CHQS xã Hàm Thuận | 86.250.220.227 |
| Ban CHQS xã Hồng Sơn | 86.250.220.229 |
| Ban CHQS xã Hàm Liêm | 86.250.220.231 |
| Ban CHQS Phường Hàm Thắng | 86.250.220.233 |
| Ban CHQS Phường Bình Thuận | 86.250.220.235 |
| Ban CHQS Phường Mũi Né | 86.250.220.237 |
| Ban CHQS Phường Phú Thuỷ | 86.250.220.239 |
| Ban CHQS Phường Phan Thiết | 86.250.220.241 |
| Ban CHQS Phường Tiến Thành | 86.250.220.243 |
| Ban CHQS xã Tuyên Quang | 86.250.220.245 |
| Ban CHQS Đặc Khu Phú Quý | 86.250.220.247 |

---

### Bước 4: Kiểm tra Định tuyến & Phân giải Tên miền (Routing & DNS Tracert)
* **Mục tiêu:** Đánh giá chất lượng đường truyền đến hệ thống mạng nội bộ quân sự và DNS server.
* **Cách thực thi kỹ thuật:**
  * Thực hiện lệnh `tracert` (hoặc phân tích từng hop bằng ICMP/TCP traceroute) tới địa chỉ DNS quân sự cố định có địa chỉ IP: **`86.0.188.1`**
  * Kiểm tra thời gian đáp ứng (RTT) qua từng chặng để định vị chính xác nút mạng nào đang bị nghẽn hoặc đứt quãng.

---

## 2. Gợi ý Công nghệ & Đóng gói Phần mềm

Để phần mềm dễ triển khai trên các máy trạm quân sự (thường có tính bảo mật cao, hạn chế cài đặt phần mềm phức tạp):

* **Ngôn ngữ lập trình đề xuất:**
  * **Python:** Cực kỳ phù hợp nhờ hệ sinh thái thư viện phong phú (`psutil`, `subprocess`, `tkinter` hoặc `PyQt` cho giao diện). Bạn có thể dùng `PyInstaller` để đóng gói toàn bộ thành một file thực thi duy nhất (`.exe`) chạy ngay mà không cần cài Python trên máy đích.
  * **C# (.NET/WPF hoặc Windows Forms):** Tận dụng tối đa các API gốc của Windows (`System.Net.NetworkInformation`, `WMI`) cho hiệu năng cao và giao diện trực quan.
* **Tính năng Báo cáo (Reporting):**
  * Tích hợp tính năng xuất log ra file **`"Báo cáo kết nối.txt"`** hoặc `.json` sau mỗi lần chạy chẩn đoán, giúp người dùng dễ dàng chụp màn hình hoặc gửi file báo cáo cho bộ phận quản trị mạng tại Bộ Chỉ huy quân sự tỉnh Lâm Đồng.
* **Giao diện (UI):**
  * Thiết kế dạng bảng điều khiển (Dashboard) đơn giản với các đèn trạng thái (Xanh: OK, Đỏ: Lỗi) cho từng bước từ Cổng vật lý $\rightarrow$ Driver $\rightarrow$ Gateway $\rightarrow$ DNS/Tracert.