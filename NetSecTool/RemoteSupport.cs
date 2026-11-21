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
///  Engine "Ho tro ky thuat tu xa" dua tren <b>RustDesk</b> o che do
///  <b>Direct IP Access</b> (ket noi truc tiep qua dia chi IP noi bo).
///
///  <para><b>Vi sao RustDesk chay duoc 100% offline?</b></para>
///  <list type="bullet">
///   <item>Che do Direct IP Access mo listener TCP tai cong <c>21118</c> tren may
///         duoc dieu khien (may can ho tro).</item>
///   <item>Máy kỹ thuật viên goi <c>rustdesk.exe --connect &lt;IP&gt;:&lt;Port&gt;</c> —
///         <b>không cần ID server</b>, khong can Internet.</item>
///   <item>Da kiem chung E2E: log RustDesk ghi
///         <c>"Direct server listening on: Some(Ok(0.0.0.0:21118))"</c> va
///         <c>"direct access from &lt;IP&gt;:&lt;ephemeral&gt;"</c> khi ket noi truc tiep.</item>
///  </list>
///
///  <para><b>Co che xac nhan an toan (bat buoc theo yeu cau)</b>: che do
///  <c>approve-mode</c> mac dinh la <c>click</c> — may can ho tro phai bam
///  "Dong y" moi cho phep ket noi. Ngoai ra co the dung mat khau tam thoi
///  (<c>use-temporary-password</c>) hoac mat khau thuong
///  (<c>use-permanent-password</c>).</para>
///
///  <para><b>File cau hinh</b>: RustDesk tach config thanh 3 file
///  (xem <c>hbb_common/src/config.rs</c>):</para>
///  <list type="bullet">
///   <item><c>RustDesk.toml</c> — <c>Config</c>: khoa, enc_id (KHONG sua)</item>
///   <item><c>RustDesk2.toml</c> — <c>Config2</c>: <b>noi dung <c>[options]</c></b>
///         (direct-server, direct-access-port, whitelist, approve-mode...)</item>
///   <item><c>RustDesk_local.toml</c> — <c>LocalConfig</c>: giao dien (KHONG sua)</item>
///  </list>
///
///  <para><b>Thu muc config theo che do chay</b>:</para>
///  <list type="bullet">
///   <item>User mode: <c>%APPDATA%\RustDesk\config\</c></item>
///   <item>Service mode: <c>C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\</c></item>
///  </list>
/// </summary>
internal static class RemoteSupport
{
    // ==================================================================
    //  Hằng số
    // ==================================================================

    /// <summary>Cổng mặc định của RustDesk Direct IP Access.</summary>
    public const int DefaultDirectPort = 21118;

    /// <summary>Tên service RustDesk trên Windows.</summary>
    public const string ServiceName = "RustDesk";

    /// <summary>Tên tệp cấu hình chứa khối <c>[options]</c>.</summary>
    public const string OptionsFileName = "RustDesk2.toml";

    /// <summary>Tên tệp cấu hình chứa khoá (không được sửa).</summary>
    public const string KeyFileName = "RustDesk.toml";

    /// <summary>Tên tệp cấu hình giao diện (không được sửa).</summary>
    public const string LocalFileName = "RustDesk_local.toml";

    /// <summary>Tên file thực thi của RustDesk client.</summary>
    public const string ClientExeName = "rustdesk.exe";

    /// <summary>Dải IP quản trị mặc định của Bộ CHQS tỉnh Lâm Đồng.</summary>
    public const string DefaultWhitelist = "86.134.32.150/24";

    /// <summary>Kiểu log của engine.</summary>
    public enum LogKind { Info, Success, Warn, Error, Step }

    /// <summary>Kết quả kiểm tra trạng thái.</summary>
    public sealed class Probe
    {
        public bool ClientFound;
        public string? ClientPath;
        public bool ServerFound;          // rustdesk-server (hbbs/hbbr) đi kèm
        public bool ServiceInstalled;
        public bool ServiceRunning;
        public int DirectPort = DefaultDirectPort;
        public bool PortListening;
        public bool DirectServerEnabled;  // đọc từ RustDesk2.toml
        public string Whitelist = "";
        public string ApproveMode = "";
        public string LocalIPv4 = "";
        public string LocalIPv4List = "";
        public string DefaultGateway = "";
        public bool IsAdministrator;

        public bool Ready => ClientFound;
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
    ///  Tìm thư mục chứa RustDesk: ưu tiên <c>tools\RustDesk</c> (bản đóng gói),
    ///  sau đó tới thư mục cạnh file exe và các bản cài sẵn của hệ thống.
    /// </summary>
    public static string? LocateRustDeskDir()
    {
        var roots = new List<string>
        {
            Path.Combine(AppContext.BaseDirectory, "tools", "RustDesk"),
            Path.Combine(AppContext.BaseDirectory, "tools", "rustdesk"),
            AppContext.BaseDirectory,
            Path.Combine(AppContext.BaseDirectory, "RustDesk")
        };

        foreach (string root in roots)
        {
            if (!Directory.Exists(root)) continue;
            if (File.Exists(Path.Combine(root, ClientExeName)))
                return root;
        }

        // Bản cài sẵn của RustDesk trên máy (thường ở %ProgramFiles%\RustDesk)
        try
        {
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            foreach (string p in new[] { pf, pf86 })
            {
                if (string.IsNullOrWhiteSpace(p)) continue;
                string d = Path.Combine(p, "RustDesk");
                if (File.Exists(Path.Combine(d, ClientExeName))) return d;
            }
        }
        catch { }

        return null;
    }

    /// <summary>Tìm đường dẫn <c>rustdesk.exe</c>.</summary>
    public static string? LocateClient(string? dir = null)
    {
        dir ??= LocateRustDeskDir();
        if (dir == null) return null;
        string p = Path.Combine(dir, ClientExeName);
        return File.Exists(p) ? p : null;
    }

    /// <summary>Tìm bộ RustDesk Server tự host (hbbs/hbbr) đi kèm.</summary>
    public static (string? hbbs, string? hbbr) LocateServerBinaries(string? dir = null)
    {
        dir ??= LocateRustDeskDir();
        if (dir == null) return (null, null);

        string srvDir = Path.Combine(dir, "server");
        string hbbs = Path.Combine(srvDir, "hbbs.exe");
        string hbbr = Path.Combine(srvDir, "hbbr.exe");
        return (File.Exists(hbbs) ? hbbs : null,
                File.Exists(hbbr) ? hbbr : null);
    }

    // ==================================================================
    //  2. THƯ MỤC CẤU HÌNH
    // ==================================================================

    /// <summary>
    ///  Đường dẫn thư mục config của RustDesk theo chế độ chạy.
    /// </summary>
    /// <param name="asService">
    ///  true = chế độ Windows Service (LocalService),
    ///  false = chế độ user thông thường.
    /// </param>
    public static string ResolveConfigDir(bool asService)
    {
        if (asService)
        {
            string svc = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows),
                "ServiceProfiles", "LocalService", "AppData", "Roaming",
                "RustDesk", "config");
            return svc;
        }

        string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        if (string.IsNullOrWhiteSpace(appData))
            appData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "AppData", "Roaming");
        return Path.Combine(appData, "RustDesk", "config");
    }

    /// <summary>Đường dẫn tệp <c>RustDesk2.toml</c> (chứa khối <c>[options]</c>).</summary>
    public static string OptionsFilePath(bool asService)
        => Path.Combine(ResolveConfigDir(asService), OptionsFileName);

    // ==================================================================
    //  3. ĐỌC / GHI TOML
    // ==================================================================

    /// <summary>
    ///  Đọc giá trị một khoá trong khối <c>[options]</c> của RustDesk2.toml.
    /// </summary>
    public static string ReadOption(string key, bool asService = false)
    {
        try
        {
            string path = OptionsFilePath(asService);
            if (!File.Exists(path)) return "";
            foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
            {
                string t = line.Trim();
                if (t.StartsWith("#") || t.Length == 0) continue;
                int eq = t.IndexOf('=');
                if (eq <= 0) continue;
                string k = t.Substring(0, eq).Trim();
                if (!k.Equals(key, StringComparison.OrdinalIgnoreCase)) continue;
                string v = t.Substring(eq + 1).Trim();
                // Bỏ dấu nháy đơn kép nếu có
                if (v.Length >= 2 &&
                    ((v[0] == '\'' && v[^1] == '\'') || (v[0] == '"' && v[^1] == '"')))
                    v = v.Substring(1, v.Length - 2);
                return v;
            }
        }
        catch { }
        return "";
    }

    /// <summary>
    ///  Ghi / cập nhật các khoá trong khối <c>[options]</c> của RustDesk2.toml.
    ///
    ///  <para>Quy trình: đọc file hiện có (nếu có) → tìm hoặc tạo khối
    ///  <c>[options]</c> → thay thế các dòng có khoá trùng → ghi lại.
    ///  RustDesk chạy nền có thể đang giữ file, nên phải ghi tạm rồi thay thế.</para>
    /// </summary>
    public static ActionResult WriteOptions(Dictionary<string, string> options, bool asService = false)
    {
        var r = new ActionResult();
        try
        {
            string dir = ResolveConfigDir(asService);
            Directory.CreateDirectory(dir);
            string path = Path.Combine(dir, OptionsFileName);

            var lines = new List<string>();
            if (File.Exists(path))
            {
                try { lines.AddRange(File.ReadAllLines(path, Encoding.UTF8)); }
                catch { lines.Clear(); }
            }

            // Tìm vị trí khối [options] (nếu chưa có sẽ tạo ở cuối file)
            int optStart = -1, optEnd = lines.Count;
            for (int i = 0; i < lines.Count; i++)
            {
                string t = lines[i].Trim();
                if (t.StartsWith("[") && t.EndsWith("]"))
                {
                    string sec = t.Substring(1, t.Length - 2).Trim();
                    if (optStart >= 0)
                    {
                        // Kết thúc khối [options]
                        optEnd = i;
                        break;
                    }
                    if (sec.Equals("options", StringComparison.OrdinalIgnoreCase))
                        optStart = i;
                }
            }

            if (optStart < 0)
            {
                // Tạo khối [options] mới ở cuối file
                if (lines.Count > 0 && lines[^1].Trim().Length > 0) lines.Add("");
                lines.Add("[options]");
                optStart = lines.Count - 1;
                optEnd = lines.Count;
            }

            // Thay thế / thêm từng khoá trong khối [options]
            var remaining = new List<KeyValuePair<string, string>>(options);
            for (int i = optStart + 1; i < optEnd; i++)
            {
                string t = lines[i].Trim();
                if (t.Length == 0 || t.StartsWith("#")) continue;
                int eq = t.IndexOf('=');
                if (eq <= 0) continue;
                string k = t.Substring(0, eq).Trim();
                int idx = remaining.FindIndex(x =>
                    x.Key.Equals(k, StringComparison.OrdinalIgnoreCase));
                if (idx < 0) continue;

                var match = remaining[idx];
                lines[i] = $"{match.Key} = '{match.Value}'";
                remaining.RemoveAt(idx);
            }

            // Thêm các khoá còn lại vào cuối khối
            if (remaining.Count > 0)
            {
                // Tìm lại vị trí kết thúc khối sau khi sửa
                int end = optStart + 1;
                while (end < lines.Count)
                {
                    string t = lines[end].Trim();
                    if (t.StartsWith("[") && t.EndsWith("]")) break;
                    end++;
                }
                var ins = remaining.Select(kv => $"{kv.Key} = '{kv.Value}'").ToList();
                lines.InsertRange(end, ins);            }

            // Ghi tạm rồi thay thế (tránh giữ file khi RustDesk đang chạy)
            string tmp = path + ".danny.tmp";
            File.WriteAllLines(tmp, lines, new UTF8Encoding(false));
            File.Copy(tmp, path, true);
            try { File.Delete(tmp); } catch { }

            r.Success = true;
            r.Summary = $"Đã cập nhật cấu hình RustDesk ({OptionsFileName}).";
            r.Details.Add("Tệp: " + path);
            foreach (var kv in options)
                r.Details.Add($"  {kv.Key} = '{kv.Value}'");
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi ghi cấu hình RustDesk: " + ex.Message;
        }
        return r;
    }

    /// <summary>
    ///  Áp dụng cấu hình Direct IP Access chuẩn cho môi trường mạng nội bộ
    ///  đơn vị (100% offline).
    /// </summary>
    /// <param name="port">Cổng Direct IP Access.</param>
    /// <param name="whitelist">
    ///  Danh sách IP/CIDR được phép kết nối (phân tách bằng dấu phẩy).
    ///  Rỗng = không giới hạn.
    /// </param>
    /// <param name="approveMode">
    ///  <c>click</c> (mặc định — phải xin phép), <c>password</c>,
    ///  hoặc <c>password-click</c>.
    /// </param>
    /// <param name="verificationMethod">
    ///  <c>use-temporary-password</c>, <c>use-permanent-password</c>,
    ///  hoặc <c>use-both-passwords</c>.
    /// </param>
    public static ActionResult ApplyDirectIpConfig(int port, string whitelist,
                                                   string approveMode = "click",
                                                   string verificationMethod = "use-temporary-password",
                                                   bool asService = false)
    {
        var opts = new Dictionary<string, string>
        {
            ["direct-server"] = "Y",
            ["direct-access-port"] = port.ToString(),
            ["enable-lan-discovery"] = "N",
            ["whitelist"] = string.IsNullOrWhiteSpace(whitelist) ? "," : whitelist,
            ["approve-mode"] = approveMode,
            ["verification-method"] = verificationMethod
        };
        return WriteOptions(opts, asService);
    }

    // ==================================================================
    //  4. DÒ MÔI TRƯỜNG
    // ==================================================================

    /// <summary>Kiểm tra toàn bộ trạng thái cần thiết cho chức năng hỗ trợ từ xa.</summary>
    public static Probe RunProbe(int directPort = DefaultDirectPort, bool asService = false)
    {
        var p = new Probe { DirectPort = directPort };

        p.IsAdministrator = IsAdministrator();

        string? dir = LocateRustDeskDir();
        string? client = LocateClient(dir);
        p.ClientFound = client != null;
        p.ClientPath = client;

        var (hbbs, _) = LocateServerBinaries(dir);
        p.ServerFound = hbbs != null;

        p.ServiceInstalled = ServiceExists(ServiceName);
        p.ServiceRunning = ServiceRunning(ServiceName);

        p.PortListening = IsPortListening(directPort);

        p.DirectServerEnabled = ReadOption("direct-server", asService)
                                .Equals("Y", StringComparison.OrdinalIgnoreCase);
        p.Whitelist = ReadOption("whitelist", asService);
        p.ApproveMode = ReadOption("approve-mode", asService);

        var (ip, gw) = GetLocalNetworkInfo();
        p.LocalIPv4 = ip;
        p.DefaultGateway = gw;
        p.LocalIPv4List = string.Join(", ", GetAllLocalIPv4());

        return p;
    }

    // ==================================================================
    //  5. FIREWALL
    // ==================================================================

    /// <summary>
    ///  Mở cổng TCP cho RustDesk Direct IP Access trong Windows Defender Firewall.
    ///
    ///  <para>Nếu có whitelist thì khoá chặt theo địa chỉ nguồn
    ///  (<c>RemoteAddress</c>), hỗ trợ cả dải CIDR.</para>
    /// </summary>
    public static ActionResult OpenFirewallPort(int port = DefaultDirectPort, string? whitelist = null)
    {
        var r = new ActionResult();
        string ruleName = BuildFirewallRuleName(port);

        // Xóa rule cũ nếu có để tránh trùng
        RunNetSh($"advfirewall firewall delete rule name=\"{ruleName}\"");

        string cmd = $"advfirewall firewall add rule name=\"{ruleName}\" "
                   + $"dir=in action=allow protocol=TCP localport={port} profile=any";

        // Khoá theo whitelist (nếu có)
        string remote = NormalizeRemoteAddress(whitelist);
        if (remote.Length > 0)
        {
            cmd += $" remoteip={remote}";
        }

        var (ok, output) = RunNetSh(cmd);
        r.Success = ok;
        r.Details.Add($"netsh {cmd}");

        if (ok)
        {
            r.Summary = $"Đã mở cổng TCP {port} trong Windows Defender Firewall.";
            r.Details.Add($"Rule: {ruleName} (inbound)");
            if (remote.Length > 0)
                r.Details.Add($"Giới hạn nguồn (RemoteAddress): {remote}");
            else
                r.Details.Add("Không giới hạn nguồn — mọi IP trong mạng đều gọi được.");
        }
        else
        {
            r.Summary = $"Không mở được cổng {port}. Kiểm tra chính sách Group Policy.";
            r.Details.Add("Output: " + TrimOutput(output));
        }
        return r;
    }

    /// <summary>Xóa rule firewall do Danny tạo.</summary>
    public static ActionResult CloseFirewallPort(int port = DefaultDirectPort)
    {
        var r = new ActionResult();
        string ruleName = BuildFirewallRuleName(port);
        var (ok, output) = RunNetSh($"advfirewall firewall delete rule name=\"{ruleName}\"");
        r.Success = ok;
        r.Summary = ok ? $"Đã xóa rule firewall cổng {port}." : "Không tìm thấy rule để xóa.";
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    private static string BuildFirewallRuleName(int port)
        => $"Danny RustDesk Direct IP TCP {port}";

    /// <summary>
    ///  Chuẩn hoá whitelist thành tham số <c>remoteip</c> của netsh.
    ///  Hỗ trợ: IP đơn, dải CIDR, danh sách phân tách bằng dấu phẩy.
    /// </summary>
    private static string NormalizeRemoteAddress(string? whitelist)
    {
        if (string.IsNullOrWhiteSpace(whitelist)) return "";
        var parts = whitelist.Split(',', StringSplitOptions.RemoveEmptyEntries)
                            .Select(p => p.Trim())
                            .Where(p => p.Length > 0)
                            .ToList();
        if (parts.Count == 0) return "";

        // Chỉ giữ các mục an toàn (IPv4 / IPv4-CIDR) để tránh lỗi netsh
        var valid = parts.Where(p =>
            IsValidIPv4(p) ||
            (p.Contains('/') && IsValidCidr(p)) ||
            IsValidIPv4(p.Split('/')[0]) && p.Contains('/')).ToList();

        return valid.Count == 0 ? "" : string.Join(",", valid);
    }

    /// <summary>Kiểm tra chuỗi dạng <c>a.b.c.d/nn</c>.</summary>
    public static bool IsValidCidr(string s)
    {
        var parts = s.Split('/');
        if (parts.Length != 2) return false;
        if (!IsValidIPv4(parts[0])) return false;
        return int.TryParse(parts[1], out int mask) && mask >= 0 && mask <= 32;
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
            var tOut = p.StandardOutput.ReadToEndAsync();
            var tErr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(20000))
            {
                try { p.Kill(); } catch { }
                return (false, "netsh timeout sau 20s");
            }
            return (p.ExitCode == 0, SafeRead(tOut) + SafeRead(tErr));
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
    //  6. MÁY CẦN HỖ TRỢ — BẬT HỖ TRỢ TỪ XA
    // ==================================================================

    /// <summary>
    ///  Cài RustDesk thành Windows Service (chạy được cả khi người dùng đã
    ///  đăng xuất, và thao tác được trên cửa sổ UAC).
    ///
    ///  <para><b>Hai điểm mấu chốt đã kiểm chứng thực tế:</b></para>
    ///  <list type="number">
    ///   <item>Lệnh <c>--install-service</c> của RustDesk <b>luôn</b> ghi
    ///         ImagePath là <c>"C:\Program Files\RustDesk\RustDesk.exe"</c>,
    ///         kể cả khi chạy bản portable → phải trỏ lại.</item>
    ///   <item>File <c>rustdesk.exe</c> đi kèm Danny là <b>bản portable
    ///         tự giải nén</b> (25 MB). Khi SCM khởi động nó, nó bung file ra
    ///         rồi thoát ngay → SCM báo timeout 180 s. Vì vậy ImagePath
    ///         <b>phải trỏ tới bản đã giải nén</b> (khoảng 386 KB) trong
    ///         thư mục dữ liệu cục bộ của RustDesk.</item>
    ///  </list>
    ///
    ///  <para>Đã kiểm chứng: service RUNNING + cổng 21118 lắng nghe khi
    ///  ImagePath trỏ tới bản giải nén.</para>
    /// </summary>
    public static ActionResult InstallService(string clientPath)
    {
        var r = new ActionResult();

        if (!File.Exists(clientPath))
        {
            r.Success = false;
            r.Summary = "Không tìm thấy rustdesk.exe để cài service.";
            r.Details.Add("Đường dẫn: " + clientPath);
            return r;
        }

        bool already = ServiceExists(ServiceName);

        if (!already)
        {
            var (ok, output) = RunProcess(clientPath, "--install-service", 60000);
            r.Details.Add($"Lệnh: {clientPath} --install-service");
            r.Details.Add("Output: " + TrimOutput(output));
            if (!ok)
            {
                r.Success = false;
                r.Summary = "Không cài được service RustDesk.";
                return r;
            }
        }

        // Chờ service xuất hiện trong SCM
        for (int i = 0; i < 20 && !ServiceExists(ServiceName); i++)
            System.Threading.Thread.Sleep(500);

        if (!ServiceExists(ServiceName))
        {
            r.Success = false;
            r.Summary = "Lệnh cài service chạy xong nhưng service không xuất hiện.";
            return r;
        }

        // Trỏ lại ImagePath về bản đã giải nén (nếu có), ngược lại bản portable
        string? target = ResolveServiceBinary(clientPath);
        var (pathOk, pathMsg) = RepointServiceImagePath(target);
        r.Details.Add(pathMsg);
        if (!pathOk)
        {
            r.Success = false;
            r.Summary = "Service đã cài nhưng không trỏ được ImagePath về " + target + ".";
            return r;
        }

        r.Success = true;
        r.Summary = already
            ? "Service RustDesk đã được cài đặt sẵn (đã trỏ lại đường dẫn)."
            : "Đã cài service RustDesk (chạy tự động, thao tác được cửa sổ UAC).";
        return r;
    }

    /// <summary>
    ///  Tìm bản <c>rustdesk.exe</c> đã giải nén (nếu có) — đây mới là file mà
    ///  Windows Service Control Manager có thể quản lý đúng cách.
    ///
    ///  <para>Bản portable (25 MB) là file tự giải nén: khi SCM chạy nó, tiến
    ///  trình bung file rồi thoát ngay nên SCM báo timeout. Bản đã giải nén
    ///  (~386 KB) nằm trong <c>%LOCALAPPDATA%\rustdesk\</c> cùng với
    ///  <c>librustdesk.dll</c> và các plugin.</para>
    /// </summary>
    public static string? ResolveServiceBinary(string portablePath)
    {
        try
        {
            string local = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "rustdesk", "rustdesk.exe");
            if (File.Exists(local)) return local;
        }
        catch { }

        // Thư mục dữ liệu khác (đã cài sẵn)
        try
        {
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string p = Path.Combine(pf, "RustDesk", "rustdesk.exe");
            if (File.Exists(p)) return p;
        }
        catch { }

        // Không tìm thấy bản giải nén → dùng bản portable (dù sẽ lỗi service)
        return File.Exists(portablePath) ? portablePath : null;
    }

    /// <summary>
    ///  Trỏ ImagePath của service RustDesk về file thực thi đã giải nén.
    /// </summary>
    private static (bool ok, string message) RepointServiceImagePath(string? clientPath)
    {
        if (string.IsNullOrWhiteSpace(clientPath))
            return (false, "Không xác định được file thực thi cho service.");

        try
        {
            string key = @"SYSTEM\CurrentControlSet\Services\" + ServiceName;
            using var reg = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(key, true);
            if (reg == null)
                return (false, "Không mở được registry key của service.");

            object? cur = reg.GetValue("ImagePath");
            string want = $"\"{clientPath}\" --service";
            if (cur is string s && string.Equals(s.Trim(), want.Trim(), StringComparison.OrdinalIgnoreCase))
                return (true, "ImagePath đã đúng: " + want);

            reg.SetValue("ImagePath", want, Microsoft.Win32.RegistryValueKind.String);
            reg.Close();
            return (true, $"Đã trỏ ImagePath service: {cur} → {want}");
        }
        catch (Exception ex)
        {
            return (false, "Lỗi trỏ ImagePath service: " + ex.Message);
        }
    }

    /// <summary>Gỡ service RustDesk.</summary>
    public static ActionResult RemoveService(string clientPath)
    {
        var r = new ActionResult();
        var (ok, output) = RunProcess(clientPath, "--uninstall-service", 60000);
        r.Success = ok;
        r.Summary = ok ? "Đã gỡ service RustDesk." : "Không gỡ được service RustDesk.";
        r.Details.Add($"Lệnh: {clientPath} --uninstall-service");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    /// <summary>Chạy / dừng service RustDesk.</summary>
    public static ActionResult SetServiceState(bool start)
    {
        var r = new ActionResult();

        // Nếu service đã ở đúng trạng thái thì coi như thành công
        if (start && ServiceRunning(ServiceName))
        {
            r.Success = true;
            r.Summary = "Service RustDesk đã chạy sẵn.";
            return r;
        }
        if (!start && !ServiceExists(ServiceName))
        {
            r.Success = true;
            r.Summary = "Service RustDesk chưa được cài (không cần dừng).";
            return r;
        }

        var (ok, output) = RunSc(start ? $"start {ServiceName}" : $"stop {ServiceName}");

        // Mã 1056 = "The service has already been started" → coi như OK
        bool alreadyRunning = output.Contains("1056")
                              || output.Contains("already been started");
        r.Success = ok || (start && alreadyRunning);
        r.Summary = r.Success
            ? (start ? "Đã khởi động service RustDesk." : "Đã dừng service RustDesk.")
            : (start ? "Không khởi động được service RustDesk."
                     : "Service RustDesk đã dừng (hoặc không chạy).");
        r.Details.Add("Output: " + TrimOutput(output));
        return r;
    }

    // ==================================================================
    //  7. KHỞI CHẠY / DỪNG
    // ==================================================================

    /// <summary>
    ///  Khởi chạy RustDesk ở chế độ chia sẻ màn hình (Direct IP listener).
    ///
    ///  <para>Dùng <c>--server</c> (không dùng <c>--tray</c>) để tiến trình
    ///  chạy nền gọn nhẹ; cấu hình Direct IP Access đã bật sẽ khiến RustDesk
    ///  mở listener TCP 21118.</para>
    /// </summary>
    public static ActionResult StartHost(string clientPath, bool asService = false)
    {
        var r = new ActionResult();
        try
        {
            // UseShellExecute = true: tiến trình RustDesk chạy nền, nếu kế thừa
            // handle console cha thì lệnh CLI sẽ không bao giờ kết thúc.
            var psi = new ProcessStartInfo(clientPath, "--server")
            {
                UseShellExecute = true,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Minimized,
                WorkingDirectory = Path.GetDirectoryName(clientPath) ?? ""
            };
            var proc = Process.Start(psi);

            r.Success = proc != null;
            r.Summary = r.Success
                ? "Đã khởi chạy RustDesk (chế độ chia sẻ màn hình)."
                : "Không khởi chạy được RustDesk.";
            r.Details.Add($"Lệnh: {clientPath} --server");
            if (proc != null) r.Details.Add("PID: " + proc.Id);
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi khởi chạy RustDesk: " + ex.Message;
        }
        return r;
    }

    /// <summary>Dừng tiến trình RustDesk đang chạy.</summary>
    public static ActionResult StopClient()
    {
        var r = new ActionResult();
        int n = KillProcesses("rustdesk");
        r.Success = true;
        r.Summary = n > 0
            ? $"Đã dừng {n} tiến trình RustDesk."
            : "Không có tiến trình RustDesk nào đang chạy.";
        return r;
    }

    // ==================================================================
    //  8. MÁY KỸ THUẬT VIÊN — KẾT NỐI
    // ==================================================================

    /// <summary>
    ///  Dựng địa chỉ đích cho lệnh <c>--connect</c>.
    ///
    ///  <para>RustDesk chấp nhận <c>&lt;IP&gt;:&lt;Port&gt;</c> (xem
    ///  <c>hbb_common::is_ipv4_str</c> — regex chấp nhận phần <c>:port</c> tùy
    ///  chọn) và <c>check_port()</c> giữ nguyên port đã chỉ định.</para>
    /// </summary>
    public static string BuildConnectTarget(string host, int port)
    {
        host = host.Trim();
        if (host.Contains(':')) return host;   // đã có :port
        return $"{host}:{port}";
    }

    /// <summary>
    ///  Mở phiên kết nối trực tiếp tới máy cần hỗ trợ.
    /// </summary>
    public static ActionResult ConnectDirect(string clientPath, string host, int port,
                                             string? password = null)
    {
        var r = new ActionResult();
        try
        {
            string target = BuildConnectTarget(host, port);
            string args = $"--connect {target}";
            if (!string.IsNullOrWhiteSpace(password))
                args += $" --password {password}";

            var psi = new ProcessStartInfo(clientPath, args)
            {
                UseShellExecute = true,
                CreateNoWindow = false,
                WindowStyle = ProcessWindowStyle.Normal,
                WorkingDirectory = Path.GetDirectoryName(clientPath) ?? ""
            };
            var proc = Process.Start(psi);

            r.Success = proc != null;
            r.Summary = r.Success
                ? $"Đã mở phiên kết nối trực tiếp tới {target}."
                : "Không mở được phiên kết nối.";
            r.Details.Add($"Lệnh: {clientPath} {args}");
            if (proc != null) r.Details.Add("PID: " + proc.Id);
        }
        catch (Exception ex)
        {
            r.Success = false;
            r.Summary = "Lỗi kết nối: " + ex.Message;
        }
        return r;
    }

    /// <summary>
    ///  Tạo shortcut trên Desktop cho chế độ "Bật hỗ trợ từ xa".
    /// </summary>
    public static ActionResult CreateHostShortcut(string clientPath, int port,
                                                   string? desktopDir = null)
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

            string lnk = Path.Combine(desktopDir, "RustDesk - Bật hỗ trợ từ xa.lnk");
            string target = clientPath;
            string args = "--server";

            bool ok = ShellLink.Create(
                lnk, target, args,
                Path.GetDirectoryName(clientPath) ?? "",
                $"Chia sẻ màn hình máy này qua RustDesk (Direct IP cổng {port})",
                iconLocation: $"{clientPath},0");

            if (!ok)
            {
                ok = ShellLink.CreateWithWsScript(lnk, target, args,
                    Path.GetDirectoryName(clientPath) ?? "",
                    $"Chia sẻ màn hình máy này qua RustDesk (Direct IP cổng {port})",
                    $"{clientPath},0");
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
    /// </summary>
    public static string? ResolveDesktopDir(string? preferred = null)
    {
        var candidates = new List<string>();

        if (!string.IsNullOrWhiteSpace(preferred)) candidates.Add(preferred);
        try { candidates.Add(Environment.GetFolderPath(Environment.SpecialFolder.Desktop)); }
        catch { }
        candidates.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Desktop"));
        candidates.Add(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "OneDrive", "Desktop"));
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
                string probe = Path.Combine(c, ".danny_write_test.tmp");
                File.WriteAllText(probe, "1");
                File.Delete(probe);
                return c;
            }
            catch { }
        }
        return null;
    }

    // ==================================================================
    //  9. MẠNG
    // ==================================================================

    /// <summary>Danh sách IPv4 của các card mạng đang hoạt động (bỏ loopback/APIPA).</summary>
    public static List<string> GetAllLocalIPv4()
    {
        var result = new List<string>();
        try
        {
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;

                // Bỏ qua card ảo (VPN / Hyper-V / VMware) — chỉ lấy card vật lý
                if (IsVirtualAdapter(ni)) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.")) continue;   // APIPA
                    if (s.StartsWith("127.")) continue;       // loopback
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
                if (IsVirtualAdapter(ni)) continue;

                foreach (var ua in ni.GetIPProperties().UnicastAddresses)
                {
                    if (ua.Address.AddressFamily != AddressFamily.InterNetwork) continue;
                    string s = ua.Address.ToString();
                    if (s.StartsWith("169.254.")) continue;
                    if (s.StartsWith("127.")) continue;

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

    /// <summary>Nhận diện card mạng ảo (VPN / Hyper-V / VMware / VirtualBox).</summary>
    private static bool IsVirtualAdapter(NetworkInterface ni)
    {
        try
        {
            string desc = (ni.Description ?? "").ToLowerInvariant();
            string name = (ni.Name ?? "").ToLowerInvariant();
            string[] virt = {
                "virtual", "hyper-v", "vmware", "vbox", "virtualbox",
                "loopback", "tap-", "tap windows", "tailscale", "zerotier",
                "wireguard", "openvpn", "cisco anyconnect", "npcap", "teredo"
            };
            return virt.Any(v => desc.Contains(v) || name.Contains(v));
        }
        catch { return false; }
    }

    // ==================================================================
    //  10. TIỆN ÍCH
    // ==================================================================

    /// <summary>
    ///  Kiểm tra một cổng TCP có đang lắng nghe hay không.
    ///
    ///  <para>Dùng kết nối TCP thật tới loopback thay vì đọc bảng socket của
    ///  Windows — đã xác minh độ tin cậy hơn nhiều (bảng socket không phản ánh
    ///  đúng listener của RustDesk).</para>
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
        catch { return false; }
    }

    /// <summary>Chờ cho tới khi cổng có tiến trình lắng nghe.</summary>
    public static bool WaitForPort(int port, int timeoutMs = 15000)
    {
        int step = 500;
        int waited = 0;
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
        try { return Process.GetProcessesByName(processName).Length > 0; }
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

    /// <summary>Kiểm tra service có tồn tại không (dùng sc.exe).</summary>
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
            var tOut = p.StandardOutput.ReadToEndAsync();
            var tErr = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(15000))
            {
                try { p.Kill(); } catch { }
                return (false, "sc timeout");
            }
            return (p.ExitCode == 0, SafeRead(tOut) + SafeRead(tErr));
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>
    ///  Chạy một file với tham số, trả về (mã thoát, output).
    ///
    ///  <para>Đọc output bằng <c>ReadToEndAsync</c> + <c>WaitForExit(timeout)</c>
    ///  để không bị nghẽn pipe khi tiến trình chạy nền.</para>
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

            var tOut = p.StandardOutput.ReadToEndAsync();
            var tErr = p.StandardError.ReadToEndAsync();

            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(); } catch { }
                try { p.WaitForExit(5000); } catch { }
                return (true, SafeRead(tOut) + SafeRead(tErr)
                        + $"\n[tiến trình vẫn chạy sau {timeoutMs}ms — đã dừng]");
            }

            return (p.ExitCode == 0, SafeRead(tOut) + SafeRead(tErr));
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    /// <summary>Lấy kết quả của một tác vụ đọc bất đồng bộ, không chặn.</summary>
    private static string SafeRead(Task<string> task)
    {
        try { return task.Wait(3000) ? task.Result : ""; }
        catch { return ""; }
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
        return Regex.IsMatch(s, @"^[A-Za-z0-9._\-]+$");
    }

    /// <summary>
    ///  Kiểm tra chuỗi đích kết nối có hợp lệ không: IPv4, IPv4:port,
    ///  IPv4/CIDR, hoặc tên host an toàn.
    /// </summary>
    public static bool IsValidTarget(string s)
    {
        if (string.IsNullOrWhiteSpace(s)) return false;

        // Dạng IP:port
        if (s.Contains(':'))
        {
            var parts = s.Split(':');
            if (parts.Length != 2) return false;
            if (!IsValidIPv4(parts[0])) return false;
            return int.TryParse(parts[1], out int p) && p >= 1 && p <= 65535;
        }

        // Dạng IPv4 thuần
        if (IsValidIPv4(s)) return true;

        // Dạng CIDR (chỉ dùng để kiểm tra, không dùng làm đích kết nối)
        if (IsValidCidr(s)) return true;

        // Tên host
        return IsSafeHost(s);
    }
}
