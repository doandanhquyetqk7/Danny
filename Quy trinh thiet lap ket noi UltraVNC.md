# Quy trình thiết lập kết nối từ xa bằng phiên bản UltraVNC Portable

## Giai đoạn 1: Chuẩn bị trên máy Kỹ thuật viên (Máy nhận kết nối)
Máy của bạn sẽ đóng vai trò chờ đợi người dùng gọi đến.

1. **Mở cổng Firewall:** Trên máy tính kỹ thuật, truy cập Windows Defender Firewall. Tạo một Inbound Rule mới cho phép kết nối TCP qua cổng **5500** (đây là cổng mặc định cho tính năng Listen của VNC, khác với cổng 5900 của kết nối xuôi).
2. **Kích hoạt chế độ Listen (Lắng nghe):** Bạn không mở VNC Viewer theo cách thông thường. Hãy tạo một Shortcut cho file `vncviewer.exe`. Nhấp chuột phải vào Shortcut > Properties > ở ô Target, thêm tham số `-listen` vào cuối cùng (Ví dụ: `"C:\UltraVNC\vncviewer.exe" -listen`) rồi nhấn OK.
3. **Khởi chạy và xác nhận:** Chạy Shortcut vừa tạo. Dưới khay hệ thống (System Tray) góc phải màn hình sẽ xuất hiện biểu tượng VNC Viewer. Rê chuột vào đó, nếu thấy thông báo trạng thái *"Listening on port 5500"*, máy bạn đã sẵn sàng nhận kết nối.

## Giai đoạn 2: Thao tác trên máy tính Quân sự (Máy cần hỗ trợ)
Máy người dùng chỉ cần chạy phần mềm và nhập IP của kỹ thuật viên.

1. **Khởi chạy VNC Server:** Chạy file `winvnc.exe` từ thư mục UltraVNC Portable. Biểu tượng con mắt màu xanh sẽ xuất hiện dưới khay hệ thống.
2. **Khởi tạo kết nối ngược:** Người dùng nhấp chuột phải vào biểu tượng con mắt màu xanh đó và chọn mục **Add New Client**.
3. **Kết nối:** Hộp thoại xuất hiện, người dùng nhập địa chỉ IP của máy tính Kỹ thuật viên (Ví dụ: `192.168.10.55`) và nhấn **OK**.

---

**📌 Verification (Xác nhận kết nối):**
Ngay khi người dùng nhấn OK, một cửa sổ chứa giao diện màn hình của máy tính quân sự sẽ tự động bật lên trên màn hình của kỹ thuật viên, sẵn sàng để điều khiển.

**🛡️ Bảo mật phiên làm việc:**
Dù luồng mạng nội bộ không ra Internet, kết nối VNC thô không được mã hóa. Bạn nên sử dụng kèm plugin DSM (`MSRC4Plugin.dsm`) đặt chung trong thư mục của UltraVNC để mã hóa toàn bộ hình ảnh và phím bấm trên đường truyền cục bộ, chống các công cụ bắt gói tin trong LAN.