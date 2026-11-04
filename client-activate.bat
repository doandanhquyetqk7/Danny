@echo off
chcp 65001 >nul
:: ==============================================================================
:: Kịch bản Tự động Đồng bộ Thời gian & Kích hoạt Bản quyền Windows / Office
:: Máy chủ KMS & NTP: 172.20.0.10
:: ==============================================================================

set "KMS_SERVER=172.20.0.10"
set "KMS_PORT=1688"

:: Kiểm tra quyền Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [LỖI] Vui lòng nhấp chuột phải vào file này và chọn "Run as administrator"!
    pause
    exit /b 1
)

echo ==============================================================================
echo  BẮT ĐẦU ĐỒNG BỘ THỜI GIAN & KÍCH HOẠT BẢN QUYỀN
echo  Máy chủ đích: %KMS_SERVER%
echo ==============================================================================
echo.

:: ---------------------------------------------------------
:: 1. ĐỒNG BỘ THỜI GIAN QUA NTP
:: ---------------------------------------------------------
echo [1/3] Đang đồng bộ thời gian với máy chủ NTP %KMS_SERVER%...
net start w32time >nul 2>&1
w32tm /config /manualpeerlist:"%KMS_SERVER%" /syncfromflags:manual /reliable:YES /update >nul 2>&1
w32tm /resync >nul 2>&1
if %errorlevel% equ 0 (
    echo       -^> Đồng bộ thời gian thành công!
) else (
    echo       -^> [CẢNH BÁO] Không thể đồng bộ giờ qua NTP. Vui lòng kiểm tra kết nối mạng.
)
echo.

:: ---------------------------------------------------------
:: 2. KÍCH HOẠT BẢN QUYỀN WINDOWS
:: ---------------------------------------------------------
echo [2/3] Đang cấu hình máy chủ KMS và kích hoạt Windows...
cscript //nologo %SystemRoot%\System32\slmgr.vbs /skms %KMS_SERVER%:%KMS_PORT%
cscript //nologo %SystemRoot%\System32\slmgr.vbs /ato
echo.

:: ---------------------------------------------------------
:: 3. KÍCH HOẠT BẢN QUYỀN MICROSOFT OFFICE
:: ---------------------------------------------------------
echo [3/3] Đang tìm kiếm và kích hoạt Microsoft Office...
set "OFFICE_FOUND=0"

for %%p in (
    "%ProgramFiles%\Microsoft Office\Office16"
    "%ProgramFiles(x86)%\Microsoft Office\Office16"
    "%ProgramFiles%\Microsoft Office\Office15"
    "%ProgramFiles(x86)%\Microsoft Office\Office15"
    "%ProgramFiles%\Microsoft Office\Office14"
    "%ProgramFiles(x86)%\Microsoft Office\Office14"
) do (
    if exist "%%~p\ospp.vbs" (
        set "OFFICE_FOUND=1"
        echo       -^> Tìm thấy Office tại: %%~p
        pushd "%%~p"
        cscript //nologo ospp.vbs /sethst:%KMS_SERVER% >nul 2>&1
        cscript //nologo ospp.vbs /setprt:%KMS_PORT% >nul 2>&1
        cscript //nologo ospp.vbs /act
        popd
    )
)

if "%OFFICE_FOUND%"=="0" (
    echo       -^> Không tìm thấy thư mục cài đặt Office Volume tiêu chuẩn trên máy này.
)

echo.
echo ==============================================================================
echo  HOÀN TẤT QUÁ TRÌNH XỬ LÝ!
echo ==============================================================================
echo.
pause
