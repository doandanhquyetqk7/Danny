# TỔNG HỢP CHI TIẾT: CÔNG CỤ XÓA LOG \& DỌN DẸP DẤU VẾT

> \\\*\\\*Ghi chú:\\\*\\\* Tài liệu này trích xuất toàn bộ các phân tích đặc tả kỹ thuật, điều kiện tiên quyết, danh mục tác vụ và luồng thực thi liên quan đến \\\*\\\*Công cụ Xóa Log (Công cụ dọn dẹp dấu vết)\\\*\\\* từ báo cáo phân tích phần mềm.

\---

## 1\. TỔNG QUAN \& ĐIỀU KIỆN QUYỀN THỰC THI

* **Yêu cầu quyền hạn:** Bắt buộc chạy với quyền **Administrator** (`Run as Administrator`) và một số tác vụ cần nâng quyền đặc quyền hệ thống mức `SYSTEM` (thông qua `ntdll!RtlAdjustPrivilege` để lấy `SeBackupPrivilege`/`SeRestorePrivilege`).
* **Cảnh báo vận hành:** *"Chức năng can thiệp sâu vào hệ thống. Yêu cầu chạy phần mềm bằng quyền Run as Administrator."* — *"Thao tác này không thể hoàn tác!"*

\---

## 2\. DANH MỤC CÁC HẠNG MỤC DỌN DẸP \& XÓA DẤU VẾT (NHÓM H)

|Mã|Hạng mục|Mục tiêu \& Phạm vi tác động|Nguồn dữ liệu / Phương pháp kỹ thuật|
|-|-|-|-|
|**H1**|**Xóa tệp rác**|Giảm bề mặt phát hiện và thu dọn dung lượng tạm|Xóa các tệp tin trong `%TEMP%`, `C:\\\\Windows\\\\Temp`, `C:\\\\Windows\\\\Prefetch`, `C:\\\\Windows\\\\SoftwareDistribution\\\\Download`.|
|**H2**|**Xóa sâu lịch sử USB**|Xóa toàn bộ dấu vết các thiết bị USB lưu trữ từng cắm vào máy|• Gọi `RtlAdjustPrivilege` lấy quyền hệ thống.<br>• Sử dụng `SetAccessControl` + `TakeOwnership` để chiếm quyền sở hữu các khóa Registry bị bảo vệ.<br>• Xóa các khóa Registry: `Enum\\\\USBSTOR`, `Enum\\\\USB`, `DeviceClasses\\\\{53f56307…}`, `{53f5630d…}`, `{10497b1b…}`.<br>• Xóa `MountedDevices` (loại trừ `\\\\DosDevices\\\\C:`).<br>• Xóa `EMDMgmt`, `Windows Portable Devices\\\\Devices`, `MountPoints2` (trừ `CPC`).<br>• Xóa nhật ký cài đặt thiết bị: `C:\\\\Windows\\\\inf\\\\setupapi.\\\*.log`.|
|**H3**|**Xóa lịch sử trình duyệt**|Xóa sạch lịch sử truy cập và bộ nhớ đệm web|• Tắt triệt để các tiến trình: `chrome`, `msedge`, `browser`, `firefox`.<br>• Xóa tệp `History`, `Cache` (trên Chrome, Edge, Cốc Cốc).<br>• Xóa tệp `places.sqlite` (trên Firefox).|
|**G8**|**Xóa sạch Nhật ký Event Log**|Vệ sinh toàn bộ nhật ký an ninh và hệ thống|Gọi `wevtutil el` để lấy danh sách toàn bộ log channels, sau đó thực thi `wevtutil cl <từng\\\_log>` qua `cmd.exe`.|

\---

4\. QUY TRÌNH THỰC THI 
\\\[Bước 1] LogCleaner.ClearTempFilesAsync()
         └── Dọn dẹp %TEMP%, Prefetch, SoftwareDistribution.

\\\[Bước 2] AdvancedLogCleaner.ClearAllBrowsersAsync()
         └── Tắt các trình duyệt đang mở \\\& Xóa History/Cache/SQLite.

\\\[Bước 3] AdvancedLogCleaner.ClearUsbHistoryAsync()
         └── Nâng quyền SYSTEM (RtlAdjustPrivilege) -> Đổi owner khóa Registry -> Xóa sâu lịch sử USBSTOR \\\& setupapi.log.

\\\[Bước 4] LogCleaner.ClearWindowsEventLogsAsync()
         └── Thực thi wevtutil el -> wevtutil cl (vệ sinh sạch toàn bộ Event Logs trên Windows).

```

\---

## 5\. BẢNG MÁP-PING NGUỒN DỮ LIỆU \& HÀM HỆ THỐNG

|Thành phần|Nguồn truy cập / API / Lệnh Shell|
|-|-|
|**Registry Keys bị can thiệp**|`HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\USBSTOR\\\\\\\*`<br>`HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Enum\\\\USB\\\\\\\*`<br>`HKLM\\\\SYSTEM\\\\MountedDevices`<br>`HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows Portable Devices\\\\Devices`<br>`HKCU\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\MountPoints2`|
|**Win32 / Native APIs**|`ntdll!RtlAdjustPrivilege` (bật خاص quyền `SeBackupPrivilege`/`SeRestorePrivilege`)<br>`System.Security.AccessControl.RegistrySecurity`<br>`DirectoryInfo.SetAccessControl` / `TakeOwnership`|
|**Lệnh Shell / Process**|`wevtutil.exe el` \& `wevtutil.exe cl`<br>`cmd.exe /c sc stop <service>`<br>`cmd.exe /c sc config <service> start= disabled`<br>`cmd.exe /c sc delete <service>`|
|**Event Log bị tác động**|Toàn bộ Event Logs (`Security`, `System`, `Application`, `Operational` logs...)|

\---

## 6\. ĐÁNH GIÁ \& ĐỀ XUẤT NÂNG CẤP KIẾN TRÚC CHO MODULE DỌN DẸP

1. **Chuẩn hóa ghi nhận trạng thái:** Khi thực hiện xóa log/tệp tin, cần bổ sung đối tượng quản lý lỗi `CheckOutcome { Pass, Warn, Fail, Skipped, Error }` kèm `SkipReason` chi tiết thay vì sử dụng các khối `catch {}` rỗng để tránh làm mất dấu vết lỗi hệ thống.
2. **An toàn tiến trình:** Đảm bảo việc xóa các file/thư mục được kiểm tra ACL chặt chẽ, loại bỏ việc thao tác trực tiếp trên các đường dẫn dùng chung mà không có xác thực toàn vẹn.
3. **Phân quyền rõ ràng:** Tách biệt module dọn dẹp rác hệ thống (quyền User/Admin thường) với module can thiệp Registry sâu (cần đặc quyền hệ thống) để giảm thiểu rủi ro khi vận hành.

