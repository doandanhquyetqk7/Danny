Bạn là Kiến trúc sư phần mềm Windows và Chuyên gia An toàn thông tin (ATTT) hệ thống mạng nội bộ cô lập (offline). Hãy đọc toàn bộ mã nguồn/tệp dự án tôi cung cấp và lập một **Báo cáo Phân tích Đặc tả Chức năng & Thiết kế Kiến trúc** thật chi tiết, có hệ thống để làm cơ sở xây dựng mới hoàn toàn (clean-room) một phần mềm kiểm tra ATTT chạy độc lập trên Windows.

### Quy tắc bắt buộc trong quá trình phân tích
1. **Chỉ phân tích nghiệp vụ và chức năng:** Tập trung trích xuất logic kiểm tra ATTT, luồng xử lý, giao diện và mẫu báo cáo đầu ra.
2. **Bảo mật & Ẩn danh dữ liệu:** Tự động ẩn/thay thế bằng ký hiệu `[REDACTED]` mọi chuỗi cấu hình nhạy cảm nếu xuất hiện (địa chỉ IP nội bộ, tên miền, khóa mã hóa, thông tin xác thực, tên đơn vị cụ thể). Không trích xuất hay phân tích các cơ chế bảo vệ bản quyền, làm rối mã (obfuscation) hoặc tìm kiếm lỗ hổng phần mềm.
3. **Thiết kế sạch (Clean-room):** Không sao chép nguyên văn mã nguồn cũ sang phần đề xuất thiết kế mới; chỉ mô tả yêu cầu chức năng, tiêu chí đánh giá và các API chuẩn của Windows cần dùng.

### Cấu trúc Báo cáo chi tiết cần xuất ra

#### Phần 1: Tổng quan kiến trúc & Môi trường vận hành
- Ngôn ngữ lập trình, nền tảng/framework giao diện và cách đóng gói (portable hay cài đặt, các thư viện phụ thuộc).
- Yêu cầu quyền thực thi (User thường hay bắt buộc Administrator/UAC) và lý do từng chức năng cần quyền đó.
- Khả năng hoạt động 100% offline (có gọi tài nguyên mạng hay dịch vụ ngoài nào không).

#### Phần 2: Danh mục chi tiết các hạng mục kiểm tra ATTT
Lập bảng tổng hợp toàn bộ các bài kiểm tra (checks) mà phần mềm thực hiện, phân theo từng nhóm nghiệp vụ. Với mỗi hạng mục, trình bày rõ:
| STT | Nhóm kiểm tra | Tên hạng mục | Mục tiêu ATTT | Dữ liệu đầu vào / Nguồn đọc trên Windows | Điều kiện Đạt / Không đạt / Cảnh báo |
|---|---|---|---|---|---|

Đảm bảo rà soát đầy đủ (nếu có trong mã) các nhóm sau:
1. **Thông tin hệ thống & Bản vá:** Phiên bản Windows, trạng thái bản quyền/cập nhật, dịch vụ hệ thống đang chạy, danh mục phần mềm đã cài đặt.
2. **Phòng chống mã độc:** Trạng thái cài đặt, hoạt động và thời gian cập nhật mẫu nhận diện của phần mềm diệt virus.
3. **Tài khoản & Chính sách bảo mật cục bộ:** Tài khoản Administrator/Guest, chính sách độ phức tạp mật khẩu, thời gian khóa màn hình, quyền chia sẻ thư mục (SMB/Share).
4. **Cấu hình mạng & Tường lửa:** Trạng thái Windows Firewall, card mạng (Wi-Fi/Bluetooth/Ethernet/card ảo), bảng định tuyến, kết nối đáng ngờ, cổng đang mở (`LISTENING`), dấu hiệu kết nối mạng ngoài quy định.
5. **Thiết bị ngoại vi & Lưu trữ:** Chính sách khóa cổng USB, lịch sử thiết bị lưu trữ gắn ngoài (`USBSTOR`), thiết bị ngoại vi không dây.
6. **Tệp tin, Trình duyệt & Nhật ký hệ thống:** Rà soát tệp tin/phần mềm thuộc danh mục hạn chế hoặc không rõ nguồn gốc, cấu hình trình duyệt, kiểm tra trạng thái lưu trữ Windows Event Log.

#### Phần 3: Cơ chế kỹ thuật thu thập dữ liệu (Chuẩn Windows)
- Liệt kê các cơ chế Windows chuẩn được sử dụng tương ứng với từng nhóm kiểm tra (ví dụ: truy vấn WMI/CIM, đọc Registry Keys cụ thể, gọi lệnh PowerShell/CMD, Windows API, phân tích Event Viewer).
- Chỉ rõ các trường hợp xử lý ngoại lệ (máy chạy Windows 7/10/11 khác nhau, thiếu quyền Admin, dịch vụ WMI bị tắt).

#### Phần 4: Logic tổng hợp, chấm điểm & Xuất báo cáo
- Cách phần mềm phân loại mức độ rủi ro hoặc tính điểm tuân thủ ATTT cho một máy tính.
- Định dạng tệp báo cáo đầu ra (Word, Excel, PDF, HTML, JSON...), bố cục từng mục trong báo cáo, quy tắc đặt tên tệp xuất ra và cơ chế tổng hợp báo cáo từ nhiều máy (nếu có).

#### Phần 5: Luồng giao diện người dùng (UI/UX Workflow)
- Mô tả cấu trúc màn hình chính, các tab/nút chức năng, thanh tiến trình (progress) khi quét bất đồng bộ để không treo giao diện, và thông báo hướng dẫn khắc phục đi kèm cho người dùng cuối.

#### Phần 6: Đề xuất thiết kế kiến trúc phần mềm mới cho đơn vị
Dựa trên toàn bộ phân tích ở trên, đề xuất bản thiết kế kiến trúc (Software Architecture) cho một phần mềm mới viết bằng **[ghi rõ ngôn ngữ bạn định dùng, ví dụ: C# .NET WinForms/WPF hoặc Python]**:
- Tổ chức cấu trúc thư mục theo mô-đun độc lập (Core Scanner, Rule Engine cấu hình bằng file JSON/YAML để dễ cập nhật tiêu chí kiểm tra theo quy định mới mà không cần biên dịch lại, Report Exporter, UI).
- Danh sách các điểm có thể cải tiến thêm so với phần mềm tham khảo (tốc độ quét đa luồng, xuất báo cáo tổng hợp cấp đơn vị, tính năng tự khắc phục các lỗi cơ bản có xác nhận của người dùng).