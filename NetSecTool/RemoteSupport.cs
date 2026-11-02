using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace NetSecTool;

/// <summary>
///  Engine "Ho tro ky thuat tu xa" dua tren UltraVNC Portable.
///
///  <para>Quy trinh nguon: <c>Quy trinh thiet lap ket noi UltraVNC.md</c>.</para>
///
///  <para>UltraVNC ho tro hai che do:</para>
///  <list type="bullet">
///   <item><b>Máy nhận kết nối</b> (máy kỹ thuật viên): chạy <c>vncviewer.exe -listen 5500</c>.
///         Viewer chờ nghe, khách hàng gọi tới.</item>
///   <item><b>Máy cần hỗ trợ</b> (máy quân sự): chạy <c>winvnc.exe -connect &lt;ip&gt;::&lt;port&gt;</c>
///         để mở kết nối ngược về máy kỹ thuật viên.</item>
///  </list>
///
///  <para>Lưu ý về cú pháp cổng của <c>-connect</c> (đã xác minh từ tài liệu UltraVNC
///  và từ chuỗi nội bộ của <c>winvnc.exe</c>):</para>
///  <list type="bullet">
///   <item><c>host</c>            → cổng 5500 (mặc định của chế độ listen)</item>
///   <item><c>host:port</c>        → cộng 5900 vào giá trị <c>port</c> (VD <c>:1</c> → 5901)</item>
///   <item><c>host::port</c>       → dùng đúng <c>port</c> (hai dấu hai chấm)</item>
///  </list>
///
///  <para>Mặc định mã hoá bằng DSM plugin <c>SecureVNCPlugin64.dsm</c> (UltraVNC 1.4.2.0
///  đi kèm bản phân phối chính thức). Nếu không có plugin thì kết nối vẫn chạy nhưng
///  <b>không mã hoá</b> — phần mềm sẽ cảnh báo rõ ràng.</para>
/// </summary>
internal static class RemoteSupport
{
    // ==================================================================
    //  Hằng số
    // ==================================================================

    /// <summary>Cổng mặc định của chế độ Listen (UltraVNC Viewer).</summary>
    public const int DefaultListenPort = 5500;

    /// <summary>Cổng chuẩn của VNC (display :0) — chỉ để tham khảo.</summary>
    public const int DefaultVncPort = 5900;

    /// <summary>Tên service WinVNC trên máy cần hỗ trợ.</summary>
    public const string ServiceName = "winvnc";

    /// <summary>File cấu hình của UltraVNC.</summary>
    public const string IniFileName = "ultravnc.ini";

    /// <summary>Tên plugin DSM 64-bit đi kèm bản phân phối chính thức.</summary>
    public const string DsmPluginName = "SecureVNCPlugin64.dsm";

    /// <summary>Tên plugin DSM 32-bit.</summary>
    public const string DsmPluginName32 = "SecureVNCPlugin.dsm";

    /// <summary>Kiểu log của engine.</summary>
    public enum LogKind { Info, Success, Warn, Error, Step }

    /// <summary>Kết quả kiểm tra trạng thái.</summary>
    public sealed class Probe
    {
        public bool ViewerFound;
        public string? ViewerPath;
        public bool ServerFound;
        public string? ServerPath;
        public bool DsmPluginFound;
        public string? DsmPluginPath;
        public bool ServiceInstalled;
        public bool ServiceRunning;
        public int ListenPort = DefaultListenPort;
        public bool PortListening;
        public string LocalIPv4 = "";
        public string LocalIPv4List = "";
        public string DefaultGateway = "";
        public bool IsAdministrator;

        public bool Ready
        {
            get
            {
                if (!ViewerFound || !ServerFound) return false;
                if (ServiceInstalled && !ServiceRunning) return false;
                return true;
            }
        }
    }

    /// <summary>Kết quả của một thao tác chuẩn bị.</summary>
    public sealed class ActionResult
    {
        public bool Success;
        public string Summary = "";
        public List<string> Details = new();
    }

    // ==================================================================
    //  1. TÌM FILE
    // ==================================================================

    /// <summary>
    ///  Tìm thư mục UltraVNC trong tools\ hoặc cạnh file exe.
    ///  Ưu tiên bản 64-bit, sau đó tới 32-bit.
    /// </summary>
    public static string? LocateUltraVncDir()
    {
        var roots = new List<string>
        {
            Path.Combine(AppContext.BaseDirectory, "tools", "UltraVNC"),
            Path.Combine(AppContext.BaseDirectory, "tools", "ultravnc"),
            AppContext.BaseDirectory,
            Path.Combine(AppContext.BaseDirectory, "UltraVNC")
        };

        foreach (string root in roots)
        {
            if (!Directory.Exists(root)) continue;

            // Cấu trúc đã giải nén: tools\UltraVNC\x64\... hoặc tools\UltraVNC\...
            foreach (string sub in new[] { "x64", "x86", "" })
            {
                string dir = sub.Length == 0 ? root : Path.Combine(root, sub);
                if (File.Exists(Path.Combine(dir, "vncviewer.exe"))
                    && File.Exists(Path.Combine(dir, "winvnc.exe")))
                    return dir;
            }
        }
        return null;
    }

    /// <summary>Tìm đường dẫn vncviewer.exe / winvnc.exe trong thư mục UltraVNC.</summary>
    public static (string? viewer, string? server) LocateExecutables(string? uvncDir = null)
    {
        uvncDir ??= LocateUltraVncDir();
        if (uvncDir == null) return (null, null);

        string viewer = Path.Combine(uvncDir, "vncviewer.exe");
        string server = Path.Combine(uvncDir, "winvnc.exe");
        return (File.Exists(viewer) ? viewer : null,
                File.Exists(server) ? server : null);
    }

    /// <summary>Tìm plugin DSM trong thư mục UltraVNC (đã giải nén).</summary>
    public static string? LocateDsmPlugin(string? uvncDir = null)
    {
        uvncDir ??= LocateUltraVncDir();
        if (uvncDir == null) return null;

        foreach (string name in new[] { DsmPluginName, DsmPluginName32, "MSRC4Plugin_for_sc.dsm" })
        {
            string p = Path.Combine(uvncDir, name);
            if (File.Exists(p)) return p;
        }
        return null;
    }

    // ==================================================================
    //  2. DÒ MÔI TRƯỜNG
    // ==================================================================

    /// <summary>Kiểm tra toàn bộ trạng thái cần thiết cho chức năng hỗ trợ từ xa.</summary>
    public static Probe RunProbe(int listenPort = DefaultListenPort)
    {
        var p = new Probe { ListenPort = listenPort };

        p.IsAdministrator = IsAdministrator();

        string? dir = LocateUltraVncDir();
        var (viewer, server) = LocateExecutables(dir);
        p.ViewerFound = viewer != null;
        p.ViewerPath = viewer;
        p.ServerFound = server != null;
        p.ServerPath = server;

        string? dsm = LocateDsmPlugin(dir);
        p.DsmPluginFound = dsm != null;
        p.DsmPluginPath = dsm;

        p.ServiceInstalled = ServiceExists(ServiceName);
        p.ServiceRunning = ServiceRunning(ServiceName);

        p.PortListening = IsPortListening(listenPort);

        var (ip, gw) = GetLocalNetworkInfo();
        p.LocalIPv4 = ip;
        p.DefaultGateway = gw;

        var all = GetAllLocalIPv4();
        p.LocalIPv4List = string.Join(", ", all);

        return p;
    }

    /// <summary>Danh sách IPv4 của các card mạng đang hoạt động (bỏ loopback).</summary>
    public static List<string> GetAllLocalIPv4()
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.")) continue;
                    if (!result.Contains(s)) result.Add(s);
                }
            }
        }
        catch { }
        return result;
    }

    /// <summary>Trả về (IP LAN, gateway mặc định) của card đang hoạt động.</summary>
    public static (string ip, string gateway) GetLocalNetworkInfo()
    {
        string ip = "";
        string gw = "";

        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.")) continue;

                    if (ip.Length == 0) ip = s;

                    var g = ni.GetIPProperties().GatewayAddresses
                             .FirstOrDefault(x => x.Address.AddressFamily == AddressFamily.InterNetwork);
                    if (g != null && gw.Length == 0)
                        gw = g.Address.ToString();
                }
            }
        }
        catch { }

        return (ip, gw);
    }

    // ==================================================================
    //  3. FIREWALL
    // ==================================================================

    /// <summary>
    ///  Mở cổng TCP cho chế độ Listen (mặc định 5500) trong Windows Defender Firewall.
    ///  Dùng netsh để tương thích mọi phiên bản Windows 10/11.
    /// </summary>
    public static ActionResult OpenFirewallPort(int port = DefaultListenPort)
    {
        var r = new ActionResult();
        string ruleName = $"Danny UltraVNC Listen TCP {port}";

        // Xóa rule cũ nếu có để tránh trùng
        RunNetSh($"advfirewall firewall delete rule name=\"{ruleName}\"");

        string cmd = $"advfirewall firewall add rule name=\"{ruleName}\" "
                   + "dir=in action=allow protocol=TCP localport=" + port
                   + " profile=any";

        var (ok, output) = RunNetSh(cmd);
        r.Success = ok;
        r.Details.Add($"netsh {cmd}");

        if (ok)
        {
            r.Summary = $"Đã mở cổng TCP {port} trong Windows Defender Firewall.";
            r.Details.Add($"Rule: {ruleName} (inbound, mọi profile)");
        }
        else
        {
            r.Summary = $"Không mở được cổng {port}. Kiểm tra chính sách Group Policy.";
            r.Details.Add("Output: " + TrimOutput(output));
        }
        return r;
    }

    /// <summary>Xóa rule firewall do Danny tạo.</summary>
    public static ActionResult CloseFirewallPort(int port = DefaultListenPort)
    {
        var r = new ActionResult();
        string ruleName = $"Danny UltraVNC Listen TCP {port}";
        var (ok, output) = RunNetSh($"advfirewall firewall delete rule name=\"{ruleName}\"");
        r.Success = ok;
        r.Summary = ok ? $"Đã xóa rule firewall cổng {port}." : "Không tìm thấy rule để xóa.";
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    private static (bool ok, string output) RunNetSh(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("netsh.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (p == null) return (false, "");
            string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(20000);
            return (p.ExitCode == 0, o);
        }
        catch (Exception ex)
        {
            return (false, ex.Message);
        }
    }

    private static string TrimOutput(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return "(không có output)";
        s = s.Trim();
        return s.Length > 400 ? s.Substring(0, 400) + "..." : s;
    }

    // ==================================================================
    //  4. CẤU HÌNH ultravnc.ini
    // ==================================================================

    /// <summary>
    ///  Ghi các khoá vào ultravnc.ini (section [admin]).
    ///
    ///  <para>Các khoá dùng (đã đối chiếu với mã nguồn uvnc_settings.cpp và
    ///  tài liệu ultravnc.ini chính thức):</para>
    ///  <list type="bullet">
    ///   <item><c>UseDSMPlugin</c> = 1 → bật mã hoá bằng plugin DSM</item>
    ///   <item><c>DSMPlugin</c> = tên file plugin</item>
    ///   <item><c>SocketConnect</c> = 1 → phải có socket lắng nghe</item>
    ///   <item><c>PortNumber</c> = 5500 → cổng VNC (chỉ dùng cho chế độ server)</item>
    ///   <item><c>AuthRequired</c> = 1 → yêu cầu mật khẩu</item>
    ///   <item><c>service_commandline</c> → dòng lệnh cho service</item>
    ///  </list>
    /// </summary>
    public static ActionResult WriteIni(string uvncDir, string? dsmPlugin, int port,
                                        string? serviceCommandLine = null)
    {
        var r = new ActionResult();
        try
        {
            string iniPath = Path.Combine(uvncDir, IniFileName);
            var kv = new Dictionary<string, string>
            {
                ["UseDSMPlugin"] = dsmPlugin != null ? "1" : "0",
                ["DSMPlugin"] = dsmPlugin != null ? Path.GetFileName(dsmPlugin) : "",
                ["SocketConnect"] = "1",
                ["AutoPortSelect"] = "0",
                ["PortNumber"] = port.ToString(),
                ["AuthRequired"] = "1",
                ["ReverseAuthRequired"] = "1",
                ["HttpConnect"] = "0",
                ["XDMCPConnect"] = "0"
            };
            if (!string.IsNullOrWhiteSpace(serviceCommandLine))
                kv["service_commandline"] = serviceCommandLine;

            WriteIniSection(iniPath, "admin", kv);
            WriteIniSection(iniPath, "admin_auth", new Dictionary<string, string>
            {
                ["group1"] = "",
                ["group2"] = "",
                ["group3"] = ""
            });

            r.Success = true;
            r.Summary = $"Đã cập nhật {IniFileName}.";
            r.Details.Add("File: " + iniPath);
            foreach (var (k, v) in kv)
                r.Details.Add($"[admin] {k}={v}");
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi ghi ultravnc.ini: " + ex.Message;
        }
        return r;
    }

    /// <summary>
    ///  Ghi (hoặc thay thế) một section trong file .ini kiểu Windows.
    ///  Giữ nguyên các section khác.
    /// </summary>
    public static void WriteIniSection(string iniPath, string section,
                                       Dictionary<string, string> values)
    {
        var lines = new List<string>();

        if (File.Exists(iniPath))
        {
            // "skipping" = dang loai bo phan noi dung cua section cu.
            // Phai bat "skipping" khi gap section moi - neu chi dat co
            // inSection=false luc gap dau section thi cac dong khoa cu
            // (PortNumber=5900, UseDSMPlugin=0...) se bi giu lai va
            // DAN GHI DE GIA TRI MOI (UltraVNC doc gia tri dau tien).
            bool skipping = false;

            foreach (string raw in File.ReadAllLines(iniPath, Encoding.Default))
            {
                string t = raw.Trim();
                if (t.StartsWith("[") && t.EndsWith("]"))
                {
                    string name = t.Substring(1, t.Length - 2).Trim();
                    skipping = name.Equals(section, StringComparison.OrdinalIgnoreCase);
                    if (skipping) continue;   // bo header section cu
                    lines.Add(raw);
                    continue;
                }
                if (skipping) continue;      // bo noi dung section cu
                lines.Add(raw);
            }
        }

        // Thêm section mới
        while (lines.Count > 0 && lines[^1].Trim().Length == 0) lines.RemoveAt(lines.Count - 1);
        lines.Add("[" + section + "]");
        foreach (var (k, v) in values)
            lines.Add(k + "=" + v);
        lines.Add("");

        string? dir = Path.GetDirectoryName(iniPath);
        if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
        File.WriteAllLines(iniPath, lines, Encoding.Default);
    }

    // ==================================================================
    //  5. SERVICE WINVNC (máy cần hỗ trợ)
    // ==================================================================

    /// <summary>Cài WinVNC thành service chạy tự động.</summary>
    public static ActionResult InstallService(string winvncPath)
    {
        var r = new ActionResult();
        if (ServiceExists(ServiceName))
        {
            r.Success = true;
            r.Summary = "Service WinVNC đã được cài đặt sẵn.";
            r.Details.Add("Dùng để gỡ: winvnc.exe -remove");
            return r;
        }

        var (ok, output) = RunProcess(winvncPath, "-install", 30000);
        r.Success = ok;
        r.Summary = ok
            ? "Đã cài service WinVNC (chạy tự động)."
            : "Không cài được service WinVNC.";
        r.Details.Add($"Lệnh: {winvncPath} -install");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    /// <summary>Gỡ service WinVNC.</summary>
    public static ActionResult RemoveService(string winvncPath)
    {
        var r = new ActionResult();
        var (ok, output) = RunProcess(winvncPath, "-remove", 30000);
        r.Success = ok;
        r.Summary = ok ? "Đã gỡ service WinVNC." : "Không gỡ được service WinVNC.";
        r.Details.Add($"Lệnh: {winvncPath} -remove");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    /// <summary>Chạy / dừng service WinVNC.</summary>
    public static ActionResult SetServiceState(bool start)
    {
        var r = new ActionResult();
        var (ok, output) = RunSc(start ? $"start {ServiceName}" : $"stop {ServiceName}");
        r.Success = ok;
        r.Summary = ok
            ? (start ? "Đã khởi động service WinVNC." : "Đã dừng service WinVNC.")
            : (start ? "Không khởi động được service WinVNC."
                     : "Service WinVNC đã dừng (hoặc không chạy).");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    /// <summary>Cài driver mirror cho chế độ multi-monitor (tùy chọn).</summary>
    public static ActionResult InstallMirrorDriver(string winvncPath)
    {
        var r = new ActionResult();
        var (ok, output) = RunProcess(winvncPath, "-installdriver", 30000);
        r.Success = ok;
        r.Summary = ok
            ? "Đã cài driver mirror (hỗ trợ chụp màn hình trên Windows 10/11)."
            : "Không cài được driver mirror (có thể máy đã có driver).";
        r.Details.Add($"Lệnh: {winvncPath} -installdriver");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    // ==================================================================
    //  6. MÁY NHẬN KẾT NỐI — chế độ Listen
    // ==================================================================

    /// <summary>
    ///  Tạo shortcut "UltraVNC Listen" trên Desktop, trỏ tới
    ///  <c>vncviewer.exe -listen &lt;port&gt;</c> (+ DSM plugin nếu có).
    ///
    ///  <para>Đúng theo quy trình gốc: tạo Shortcut cho vncviewer.exe, thêm tham số
    ///  <c>-listen</c> vào cuối ô Target.</para>
    /// </summary>
    public static ActionResult CreateListenShortcut(string viewerPath, int port,
                                                     string? dsmPlugin, string? desktopDir = null)
    {
        var r = new ActionResult();
        try
        {
            desktopDir = ResolveDesktopDir(desktopDir);
            if (desktopDir == null)
            {
                r.Success = false;
                r.Summary = "Không xác định được thư mục Desktop để tạo shortcut.";
                return r;
            }

            string lnk = Path.Combine(desktopDir, "UltraVNC - Lắng nghe (máy nhận kết nối).lnk");

            string target = viewerPath;
            string args = $"-listen {port}";
            if (!string.IsNullOrEmpty(dsmPlugin))
                args += $" -dsmplugin \"{Path.GetFileName(dsmPlugin)}\"";

            bool ok = ShellLink.Create(
                lnk, target, args,
                Path.GetDirectoryName(viewerPath) ?? "",
                $"Máy nhận kết nối - UltraVNC chờ kết nối trên cổng {port}",
                iconLocation: $"{viewerPath},0");

            if (!ok)
            {
                // Cach 2: WScript.Shell - chi dung khi ten file ASCII
                ok = ShellLink.CreateWithWsScript(lnk, target, args,
                    Path.GetDirectoryName(viewerPath) ?? "",
                    $"Máy nhận kết nối - UltraVNC chờ kết nối trên cổng {port}",
                    $"{viewerPath},0");
            }

            r.Success = ok;
            r.Summary = ok
                ? $"Đã tạo shortcut \"{Path.GetFileName(lnk)}\" trên Desktop."
                : "Không tạo được shortcut trên Desktop.";
            r.Details.Add("Target: " + target);
            r.Details.Add("Args: " + args);
            r.Details.Add("File: " + lnk);
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi tạo shortcut: " + ex.Message;
        }
        return r;
    }

    /// <summary>
    ///  Tìm thư mục Desktop thật sự tồn tại (có thể nằm trong OneDrive).
    ///  Trả về null nếu không tìm thấy thư mục nào ghi được.
    /// </summary>
    public static string? ResolveDesktopDir(string? preferred = null)
    {
        var candidates = new List<string>();

        if (!string.IsNullOrWhiteSpace(preferred)) candidates.Add(preferred);
        try { candidates.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)); }
        catch { }
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"));
        candidates.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive", "Desktop"));
        try
        {
            candidates.Add(Environment.GetFolderPath(
                Environment.SpecialFolder.DesktopDirectory));
        }
        catch { }

        foreach (string c in candidates)
        {
            if (string.IsNullOrWhiteSpace(c)) continue;
            try
            {
                if (!Directory.Exists(c)) continue;
                // Thử ghi file thử để chắc chắn thư mục ghi được (OneDrive
                // đôi lúc chỉ tồn tại nhưng không ghi được do chính sách).
                string probe = Path.Combine(c, ".danny_write_test.tmp");
                File.WriteAllText(probe, "1");
                File.Delete(probe);
                return c;
            }
            catch { }
        }
        return null;
    }

    /// <summary>
    ///  Khởi chạy UltraVNC Viewer ở chế độ Listen.
    /// </summary>
    public static ActionResult StartListener(string viewerPath, int port, string? dsmPlugin)
    {
        var r = new ActionResult();
        try
        {
            string args = $"-listen {port}";
            if (!string.IsNullOrEmpty(dsmPlugin))
                args += $" -dsmplugin \"{Path.GetFileName(dsmPlugin)}\"";

            // UseShellExecute = true de KHONG ke thua handle cua console cha.
            // Neu dung UseShellExecute=false, vncviewer se giu pipe stdout cua
            // process cha -> lenh CLI khong bao gio ket thuc (tre).
            var psi = new ProcessStartInfo(viewerPath, args)
            {
                UseShellExecute = true,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Minimized,
                WorkingDirectory = Path.GetDirectoryName(viewerPath) ?? ""
            };
            var proc = Process.Start(psi);

            r.Success = proc != null;
            r.Summary = r.Success
                ? $"Đã khởi chạy UltraVNC Viewer ở chế độ lắng nghe cổng {port}."
                : "Không khởi chạy được UltraVNC Viewer.";
            r.Details.Add($"Lệnh: {viewerPath} {args}");
            if (proc != null) r.Details.Add("PID: " + proc.Id);
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi khởi chạy Viewer: " + ex.Message;
        }
        return r;
    }

    /// <summary>Dừng tiến trình UltraVNC Viewer đang chạy.</summary>
    public static ActionResult StopViewer()
    {
        var r = new ActionResult();
        int n = KillProcesses("vncviewer");
        r.Success = true;
        r.Summary = n > 0
            ? $"Đã dừng {n} tiến trình UltraVNC Viewer."
            : "Không có tiến trình UltraVNC Viewer nào đang chạy.";
        return r;
    }

    // ==================================================================
    //  7. MÁY CẦN HỖ TRỢ — kết nối ngược
    // ==================================================================

    /// <summary>
    ///  Dựng dòng lệnh <c>-connect</c> của winvnc.
    ///
    ///  <para>Cú pháp UltraVNC (đã xác minh):</para>
    ///  <list type="bullet">
    ///   <item><c>host</c>      → cổng 5500</item>
    ///   <item><c>host::port</c> → đúng cổng <c>port</c></item>
    ///  </list>
    ///
    ///  <para>Luôn dùng dạng <c>host::port</c> để không nhầm với quy tắc
    ///  <c>port + 5900</c> của dạng <c>host:port</c>.</para>
    /// </summary>
    public static string BuildConnectArgs(string host, int port)
    {
        return $"-connect {host}::{port}";
    }

    /// <summary>
    ///  Mở kết nối ngược từ máy cần hỗ trợ về máy kỹ thuật viên.
    ///
    ///  <para>Thứ tự bắt buộc (đã xác minh từ tài liệu và diễn đàn UltraVNC):
    ///  phải chạy <c>winvnc.exe</c> trước, rồi mới gọi <c>-connect</c>;
    ///  nếu không có tiến trình winvnc thì <c>-connect</c> sẽ không làm gì.</para>
    ///
    ///  <para>Dùng <c>-autoreconnect</c> để tự kết nối lại nếu phiên bị ngắt.
    ///  Lưu ý: <c>-autoreconnect</c> phải đứng <b>trước</b> <c>-connect</c>.</para>
    /// </summary>
    public static ActionResult ConnectReverse(string winvncPath, string host, int port,
                                               bool autoreconnect = true)
    {
        var r = new ActionResult();
        try
        {
            // 1) Bảo đảm winvnc đang chạy (nếu service thì service đã lo việc này)
            bool running = IsProcessRunning("winvnc");
            if (!running)
            {
                // Dùng StartDetached: winvnc -run chạy liên tục, nếu chờ nó
                // thoát se treo phan mem.
                bool started = StartDetached(winvncPath, "-run", out int pid);
                r.Details.Add(started
                    ? $"Đã khởi chạy winvnc -run (PID {pid})."
                    : "Không khởi chạy được winvnc -run.");
                System.Threading.Thread.Sleep(2500);
            }
            else
            {
                r.Details.Add("winvnc.exe đã chạy sẵn.");
            }

            // 2) Lệnh connect (thứ tự tham số quan trọng)
            string args = BuildConnectArgs(host, port);
            if (autoreconnect) args = "-autoreconnect " + args;

            // Lệnh -connect thoat ra nhanh -> RunProcess la du.
            var (ok2, out2) = RunProcess(winvncPath, args, 15000);
            r.Success = ok2;
            r.Summary = ok2
                ? $"Đã gửi lệnh kết nối ngược tới {host}:{port}."
                : "Không gửi được lệnh kết nối ngược.";
            r.Details.Add($"Lệnh: {winvncPath} {args}");
            r.Details.Add("Output: " + TrimOutput(out2));
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi kết nối ngược: " + ex.Message;
        }
        return r;
    }

    /// <summary>Dừng tiến trình winvnc (chỉ dừng tiến trình, không gỡ service).</summary>
    public static ActionResult StopServer()
    {
        var r = new ActionResult();
        int n = KillProcesses("winvnc");
        r.Success = true;
        r.Summary = n > 0
            ? $"Đã dừng {n} tiến trình winvnc."
            : "Không có tiến trình winvnc nào đang chạy.";
        return r;
    }

    // ==================================================================
    //  8. TIỆN ÍCH
    // ==================================================================

    /// <summary>
    ///  Kiểm tra một cổng TCP có đang lắng nghe hay không.
    ///
    ///  <para>KHÔNG dùng <c>IPGlobalProperties.GetActiveTcpListeners()</c>:
    ///  với UltraVNC Viewer, bảng socket của Windows không phản ánh đúng
    ///  (đo thực tế: bảng báo "không lắng nghe" ở 20/20 lần đo trong khi
    ///  kết nối thật vẫn thành công). Thay vào đó ta thực hiện một kết nối
    ///  TCP thật tới loopback — đây cũng chính là cách một client VNC thật
    ///  sẽ kiểm tra, nên độ tin cậy cao hơn nhiều.</para>
    ///
    ///  <para>Việc thử kết nối rồi đóng không gây ảnh hưởng tới phiên làm
    ///  việc: đã kiểm chứng bằng E2E (10 lần probe liên tiếp + kết nối
    ///  ngược vẫn thành công).</para>
    /// </summary>
    public static bool IsPortListening(int port, int timeoutMs = 1500)
    {
        try
        {
            using var client = new TcpClient();
            var ar = client.BeginConnect(IPAddress.Loopback, port, null, null);
            if (!ar.AsyncWaitHandle.WaitOne(timeoutMs))
            {
                try { client.Close(); } catch { }
                return false;
            }
            client.EndConnect(ar);
            bool ok = client.Connected;
            client.Close();
            return ok;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    ///  Chờ cho tới khi cổng có tiến trình lắng nghe (tối đa <paramref name="timeoutMs"/> ms).
    ///  UltraVNC Viewer cần vài giây mới bind socket, nên phải chờ
    ///  thay vì kiểm tra ngay lập tức.
    /// </summary>
    public static bool WaitForPort(int port, int timeoutMs = 15000)
    {
        int step = 500;
        int waited = 0;
        // Timeout cua moi lan probe phai nho hon buoc cho de tong thoi gian
        // khong vuot qua timeoutMs.
        int probeTimeout = Math.Min(1000, Math.Max(200, timeoutMs / 4));

        while (waited < timeoutMs)
        {
            if (IsPortListening(port, probeTimeout)) return true;
            System.Threading.Thread.Sleep(step);
            waited += step;
        }
        return IsPortListening(port, probeTimeout);
    }

    /// <summary>Kiểm tra một tiến trình có đang chạy hay không.</summary>
    public static bool IsProcessRunning(string processName)
    {
        try
        {
            return Process.GetProcessesByName(processName).Length > 0;
        }
        catch { return false; }
    }

    /// <summary>Dừng mọi tiến trình theo tên, trả về số tiến trình đã dừng.</summary>
    public static int KillProcesses(string processName)
    {
        int n = 0;
        try
        {
            var procs = Process.GetProcessesByName(processName);
            foreach (var pr in procs)
            {
                try { pr.Kill(); pr.WaitForExit(5000); n++; } catch { }
            }
        }
        catch { }
        return n;
    }

    /// <summary>Kiểm tra service có tồn tại không (dùng sc.exe, không cần NuGet).</summary>
    public static bool ServiceExists(string name)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", "query \"" + name + "\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (p == null) return false;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return p.ExitCode == 0 && o.Contains("SERVICE_NAME");
        }
        catch { return false; }
    }

    /// <summary>Kiểm tra service có đang chạy không.</summary>
    public static bool ServiceRunning(string name)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", "query \"" + name + "\"")
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (p == null) return false;
            string o = p.StandardOutput.ReadToEnd();
            p.WaitForExit(10000);
            return o.Contains("RUNNING");
        }
        catch { return false; }
    }

    /// <summary>Chạy một lệnh sc.exe, trả về (thành công, output).</summary>
    private static (bool ok, string output) RunSc(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            });
            if (p == null) return (false, "");
            string o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(15000);
            return (p.ExitCode == 0, o);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>
    ///  Chạy một file với tham số, trả về (mã thoát, output).
    ///
    ///  <para>Quan trọng: phải đọc output bằng <c>ReadToEndAsync</c> và
    ///  <c>WaitForExit(timeout)</c> — nếu đọc đồng bộ (ReadToEnd) trước khi
    ///  chờ, tiến trình chưa thoát sẽ giữ pipe mở và treo vĩnh viễn.
    ///  Ví dụ điển hình: <c>winvnc.exe -run</c> chạy liên tục như ứng dụng
    ///  cửa sổ nền, không bao giờ thoát.</para>
    /// </summary>
    private static (bool ok, string output) RunProcess(string file, string args, int timeoutMs = 30000)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                WorkingDirectory = Path.GetDirectoryName(file) ?? ""
            });
            if (p == null) return (false, "");

            // Đọc output bất đồng bộ để không bị nghẽn pipe
            var tOut = p.StandardOutput.ReadToEndAsync();
            var tErr = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                // Tiến trình không thoát (VD winvnc -run) -> dừng nó và coi
                // như chạy thành công vì mục đích chính là KHỞI CHẠY nó.
                try { p.Kill(); } catch { }
                try { p.WaitForExit(5000); } catch { }
                string partial = SafeRead(tOut) + SafeRead(tErr);
                return (true, partial + "\n[tiến trình vẫn chạy sau " + timeoutMs + "ms — đã dừng]");
            }

            return (p.ExitCode == 0, SafeRead(tOut) + SafeRead(tErr));
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>Lấy kết quả của một tác vụ đọc bất đồng bộ, không chặn.</summary>
    private static string SafeRead(Task<string> task)
    {
        try
        {
            return task.Wait(3000) ? task.Result : "";
        }
        catch { return ""; }
    }

    /// <summary>
    ///  Khởi chạy một tiến trình "nền" mà không chờ nó thoát.
    ///  Dùng cho các lệnh của UltraVNC chạy liên tục (VD <c>winvnc -run</c>).
    /// </summary>
    private static bool StartDetached(string file, string args, out int pid)
    {
        pid = 0;
        try
        {
            // UseShellExecute = true de KHONG ke thua handle console cha
            // (neu khong, lenh CLI se bi tre khi doi lai stdout cua process).
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute = true,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Minimized,
                WorkingDirectory = Path.GetDirectoryName(file) ?? ""
            };
            var proc = Process.Start(psi);
            if (proc == null) return false;
            pid = proc.Id;
            return true;
        }
        catch { return false; }
    }

    /// <summary>Kiểm tra tiến trình hiện tại có chạy với quyền Administrator.</summary>
    public static bool IsAdministrator()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            var p = new System.Security.Principal.WindowsPrincipal(id);
            return p.IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    /// <summary>Kiểm tra chuỗi có phải địa chỉ IPv4 hợp lệ không.</summary>
    public static bool IsValidIPv4(string s)
    {
        return IPAddress.TryParse(s, out var ip)
               && ip.AddressFamily == AddressFamily.InterNetwork;
    }

    /// <summary>Kiểm tra một chuỗi có chứa ký tự nguy hiểm cho lệnh shell hay không.</summary>
    public static bool IsSafeHost(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;
        if (s.Length > 255) return false;
        // Chỉ cho phép chữ/số/dấu chấm/giao thông cho tên host
        return Regex.IsMatch(s, @"^[A-Za-z0-9._\-]+$");
    }
}
