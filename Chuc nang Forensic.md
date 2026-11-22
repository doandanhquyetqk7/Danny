Hãy đóng vai trò là Kiến trúc sư Phần mềm An ninh mạng & Chuyên gia Điều tra Chứng cứ số (Digital Forensics & Incident Response - DFIR) cấp cao. Hãy thiết kế và viết mã nguồn/kiến trúc chi tiết cho một phần mềm điều tra chứng cứ số chuyên sâu chạy trên hệ điều hành Windows (hỗ trợ thu thập từ xa qua WinRM/SSH hoặc chạy trực tiếp trên máy trạm ở chế độ read-only/ít xâm lấn nhất), phục vụ điều tra các sự cố:
1. Máy tính mạng nội bộ/mạng đặc thù có dấu hiệu kết nối ra Internet trái phép (dual-homed, rogue Wi-Fi/hotspot, USB tethering, proxy/VPN/tunneling, DNS tunneling, thay đổi route/gateway/DNS).
2. Có dấu hiệu lộ lọt tài liệu ra ngoài Internet (exfiltration qua trình duyệt/web upload, email web, cloud drive, FTP/SFTP/SCP, messaging apps, nén/mã hóa/chia nhỏ file trước khi gửi, hoặc copy ra thiết bị lưu trữ trung gian trước khi đưa ra máy có Internet).

YÊU CẦU BẮT BUỘC VỀ NGUYÊN TẮC FORENSIC:
- Bảo toàn tính toàn vẹn chứng cứ: mọi artifact thu thập phải tự động tính mã băm (SHA-256), ghi nhận timestamp UTC + local time, thông tin máy chủ thu thập, phiên bản công cụ, và xuất ra gói bằng chứng có metadata/manifest chống sửa đổi.
- Hạn chế làm biến đổi dữ liệu trên máy đích (minimal footprint): ưu tiên đọc trực tiếp raw artifacts / VSS / event logs / registry hives / network tables thay vì ghi đè hoặc sửa đổi trạng thái hệ thống.
- Có cơ chế tương quan sự kiện (Timeline & Correlation) để nối chuỗi hành vi: [Dấu hiệu truy cập/sửa tài liệu] -> [Đóng gói/nén/đổi tên] -> [Thiết lập kết nối ra ngoài] -> [Truyền dữ liệu đi].

HÃY THIẾT KẾ VÀ TRIỂN KHAI ĐẦY ĐỦ CÁC PHÂN HỆ SAU:

1. PHÂN HỆ THU THẬP CHỨNG CỨ (EVIDENCE COLLECTOR):
- Cấu hình mạng & kết nối: bảng định tuyến (routing table), ARP cache, DNS cache, danh sách interface/adapter (bao gồm card mạng ảo, Wi-Fi, Bluetooth, RNDIS/USB tethering), cấu hình proxy/PAC/WinHTTP, kết nối mạng đang mở và lịch sử kết nối (ETW / NetSession / firewall logs).
- Dấu vết truy cập & lộ lọt tài liệu:
  + Lịch sử truy cập file (NTFS $UsnJrnl, ShellBags, JumpLists, RecentFiles, LNK files, Prefetch).
  + Dấu vết nén/mã hóa/tập hợp tài liệu bất thường (7z, rar, zip, tar, mật khẩu nén, thư mục tạm/staging).
  + Dấu vết thiết bị lưu trữ gắn ngoài & đồng bộ (USBSTOR, SetupAPI logs, volume serials, cloud sync folders).
  + Lịch sử trình duyệt & ứng dụng mạng (Chrome/Edge/Firefox history, downloads, cookies/session liên quan dịch vụ lưu trữ/gửi file, cache/log ứng dụng chat/mail nếu có).
- Dấu vết hệ thống & tiến trình: danh sách tiến trình đang chạy, dịch vụ, scheduled tasks, autorun/persistence, Windows Event Logs (Security, System, PowerShell, Defender/EDR, Firewall) liên quan đến thay đổi mạng, đăng nhập, truy cập file và kết nối ngoài.

2. PHÂN HỆ PHÂN TÍCH & PHÁT HIỆN BẤT THƯỜNG (FORENSIC ANALYZER & RULE ENGINE):
- Bộ quy tắc phát hiện dấu hiệu kết nối Internet trái phép (ví dụ: xuất hiện default gateway lạ, phân giải tên miền ngoài vùng cho phép, lưu lượng bất thường theo cổng/giao thức, kết nối qua interface không thuộc dải IP nội bộ chuẩn, sử dụng công cụ tunneling/remote/proxy).
- Bộ quy tắc phát hiện dấu hiệu rò rỉ tài liệu (ví dụ: truy cập hàng loạt tài liệu nhạy cảm trong thời gian ngắn, tạo file nén lớn ngay trước khi có kết nối ra ngoài, upload/gửi dữ liệu dung lượng lớn bất thường, xóa log hoặc xóa dấu vết file/lịch sử trình duyệt - anti-forensics).
- Chấm điểm mức độ nghi vấn (Risk/Severity Scoring) kèm giải thích bằng chứng cụ thể (tại sao cờ này bật lên, dựa trên artifact nào).

3. PHÂN HỆ XÂY DỰNG DÒNG THỜI GIAN (TIMELINE & CORRELATION ENGINE):
- Hợp nhất sự kiện từ nhiều nguồn về một trục thời gian thống nhất (mili-giây/giây).
- Tự động lọc và làm nổi bật chuỗi sự kiện liên quan đến các file/thư mục nhạy cảm hoặc các IP/domain/interface bất thường.

4. PHÂN HỆ XUẤT BÁO CÁO & GÓI CHỨNG CỨ (REPORTING & EVIDENCE PACKAGER):
- Tạo báo cáo chi tiết (hỗ trợ xuất HTML/PDF/Markdown và dữ liệu JSON/CSV để tra cứu):
  + Tóm tắt điều hành (Executive Summary) & kết luận sơ bộ mức độ nghi ngờ lộ lọt.
  + Hồ sơ máy tính & môi trường mạng được điều tra.
  + Danh sách các chỉ báo (IOCs / Artifacts) kèm đường dẫn gốc, thời gian, mã băm SHA-256.
  + Dòng thời gian sự kiện trọng yếu & chuỗi tương quan nghi vấn lộ lọt.
  + Khuyến nghị xử lý tiếp theo (cô lập máy, thu giữ ổ cứng/ảnh đĩa, rà soát các máy lân cận).
- Đóng gói toàn bộ dữ liệu thô + báo cáo + file `manifest.sha256` để phục vụ lưu trữ, bàn giao và đối soát chứng cứ.

YÊU CẦU CÁCH TRÌNH BÀY ĐẦU RA:
- Trình bày rõ kiến trúc thư mục dự án, luồng xử lý dữ liệu, và định dạng dữ liệu chuẩn hóa cho từng loại artifact.
- Cung cấp mã nguồn mẫu hoàn chỉnh, chạy được cho các thành phần cốt lõi (ưu tiên Python 3.11+ có cấu trúc module rõ ràng, có thể tích hợp các công cụ/thư viện hệ thống hoặc parse trực tiếp log/registry/network, và có cơ chế dry-run/test trên dữ liệu mẫu để kiểm thử an toàn).
- Nêu rõ các hạn chế kỹ thuật (ví dụ: file bị xóa vĩnh viễn, mã hóa đầu-cuối, máy đã tắt nguồn/khởi động lại làm mất volatile data) và cách khắc phục trong quy trình điều tra thực tế.