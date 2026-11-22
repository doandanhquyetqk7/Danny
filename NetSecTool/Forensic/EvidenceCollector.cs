using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace NetSecTool.Forensic;

/// <summary>
/// Thu thập chứng cứ từ máy — CHẾ ĐỘ READ-ONLY / MINIMAL FOOTPRINT.
///
/// <para>Nguyên tắc: chỉ ĐỌC. Không ghi, không xóa, không sửa registry,
/// không thay đổi cấu hình hệ thống. Tài liệu thu thập được ghi ra một
/// thư mục riêng (evidence pack) kèm manifest SHA-256.</para>
///
/// <para>Mọi artifact đọc được đều được băm SHA-256 và ghi nhận mốc thời gian
/// UTC + local time.</para>
/// </summary>
public static class EvidenceCollector
{
    /// <summary>Giới hạn số file băm cho mỗi nguồn (tránh quét quá nặng).</summary>
    private const int MaxHashPerCategory = 400;

    // ==================================================================
    //  HASH
    // ==================================================================
    /// <summary>Tính SHA-256 của file (đọc theo luồng, không khóa file lâu).</summary>
    public static string? Sha256File(string path)
    {
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete, 65536, FileOptions.SequentialScan);
            using var sha = SHA256.Create();
            byte[] hash = sha.ComputeHash(fs);
            var sb = new StringBuilder(hash.Length * 2);
            foreach (byte b in hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Tính SHA-256 của chuỗi văn bản (dùng cho output của lệnh shell).</summary>
    public static string Sha256Text(string text)
    {
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(text ?? ""));
        var sb = new StringBuilder(hash.Length * 2);
        foreach (byte b in hash) sb.Append(b.ToString("x2"));
        return sb.ToString();
    }

    // ==================================================================
    //  1. MANG & KET NOI
    // ==================================================================

    /// <summary>Thu thập thông tin mạng (định tuyến, ARP, DNS, adapter, cổng).</summary>
    public static List<Artifact> CollectNetwork(List<string> errors)
    {
        var arts = new List<Artifact>();

        void Add(string source, string category, string content, string path = "")
        {
            arts.Add(new Artifact
            {
                Source = source,
                Category = category,
                Path = path,
                Kind_ = "command-output",
                ContentPreview = Trim(content, 200_000),
                Sha256 = Sha256Text(content ?? ""),
                ModifiedUtc = DateTime.UtcNow
            });
        }

        // --- Adapter / IP / Gateway / DNS ---
        try
        {
            var sb = new StringBuilder();
            foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                sb.AppendLine($"Interface: {ni.Name} [{ni.NetworkInterfaceType}]");
                sb.AppendLine($"  Description : {ni.Description}");
                sb.AppendLine($"  Status      : {ni.OperationalStatus}");
                sb.AppendLine($"  MacAddress  : {ni.GetPhysicalAddress()}");
                sb.AppendLine($"  Speed       : {ni.Speed}");
                try
                {
                    var props = ni.GetIPProperties();
                    foreach (var ua in props.UnicastAddresses)
                        sb.AppendLine($"  IP          : {ua.Address} /{ua.PrefixLength}");
                    foreach (var ga in props.GatewayAddresses)
                        sb.AppendLine($"  Gateway     : {ga.Address}");
                    foreach (var da in props.DnsAddresses)
                        sb.AppendLine($"  DNS Servers : {da}");
                    foreach (var dh in props.DhcpServerAddresses)
                        sb.AppendLine($"  DHCP Server : {dh}");
                }
                catch { }
                sb.AppendLine();
            }
            Add("network", "Adapters / IP / Gateway / DNS", sb.ToString(), "GetAllNetworkInterfaces");
        }
        catch (Exception ex) { errors.Add("Thu thập adapter: " + ex.Message); }

        string route = RunShell("route.exe", "print");
        if (route.Length > 0)
            Add("network", "Routing table", route, "route print");

        string arp = RunShell("arp.exe", "-a");
        if (arp.Length > 0)
            Add("network", "ARP cache", arp, "arp -a");

        string dns = RunShell("ipconfig.exe", "/displaydns");
        if (dns.Length > 0)
            Add("network", "DNS cache", dns, "ipconfig /displaydns");

        string proxy = RunShell("netsh.exe", "winhttp show proxy");
        if (proxy.Length > 0)
            Add("network", "WinHTTP proxy", proxy, "netsh winhttp show proxy");

        // --- Cổng đang lắng nghe / kết nối ---
        try
        {
            var sb = new StringBuilder();
            var props = IPGlobalProperties.GetIPGlobalProperties();
            foreach (var ep in props.GetActiveTcpListeners())
                sb.AppendLine($"TCP LISTEN {ep.Address}:{ep.Port}");
            foreach (var ep in props.GetActiveUdpListeners())
                sb.AppendLine($"UDP LISTEN {ep.Address}:{ep.Port}");
            foreach (var conn in props.GetActiveTcpConnections())
                sb.AppendLine($"TCP {conn.LocalEndPoint} -> {conn.RemoteEndPoint} [{conn.State}]");
            Add("network", "Active connections / listening ports", sb.ToString(), "IPGlobalProperties");
        }
        catch (Exception ex) { errors.Add("Thu thập cổng kết nối: " + ex.Message); }

        string netstat = RunShell("netstat.exe", "-ano");
        if (netstat.Length > 0)
            Add("network", "netstat -ano", netstat, "netstat -ano");

        string svc = RunShell("sc.exe", "query type= service state= all");
        if (svc.Length > 0)
            Add("service", "Windows services", svc, "sc query");

        // --- WMI adapter ---
        try
        {
            var sb = new StringBuilder();
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_NetworkAdapter");
            using var r = s.Get();
            foreach (ManagementObject m in r)
            {
                sb.AppendLine($"Adapter: {m["Name"]}");
                sb.AppendLine($"  Manufacturer   : {m["Manufacturer"]}");
                sb.AppendLine($"  MACAddress     : {m["MACAddress"]}");
                sb.AppendLine($"  NetEnabled     : {m["NetEnabled"]}");
                sb.AppendLine($"  PhysicalAdapter: {m["PhysicalAdapter"]}");
                sb.AppendLine($"  PNPDeviceID    : {m["PNPDeviceID"]}");
                sb.AppendLine($"  Status         : {m["Status"]}");
                sb.AppendLine();
            }
            Add("network", "WMI Win32_NetworkAdapter", sb.ToString(), "WMI:Win32_NetworkAdapter");
        }
        catch (Exception ex) { errors.Add("Thu thập WMI adapter: " + ex.Message); }

        return arts;
    }

    // ==================================================================
    //  2. REGISTRY
    // ==================================================================

    /// <summary>Thu thập các khóa registry liên quan USB / thiết bị / dấu vết truy cập.</summary>
    public static List<Artifact> CollectRegistry(List<string> errors)
    {
        var arts = new List<Artifact>();

        string[] keys =
        {
            @"SYSTEM\CurrentControlSet\Enum\USBSTOR",
            @"SYSTEM\CurrentControlSet\Enum\USB",
            @"SYSTEM\MountedDevices",
            @"SOFTWARE\Microsoft\Windows Portable Devices\Devices",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            @"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
            @"SOFTWARE\Policies\Microsoft\Windows NT\DNS Server"
        };

        foreach (string key in keys)
        {
            try
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine,
                    Microsoft.Win32.RegistryView.Registry64);
                using var rk = baseKey.OpenSubKey(key);
                if (rk == null) continue;

                string content = DumpKey(rk, 0);
                arts.Add(new Artifact
                {
                    Source = "registry",
                    Category = "HKLM\\" + key,
                    Path = "HKLM\\" + key,
                    Kind_ = "registry",
                    ContentPreview = Trim(content, 200_000),
                    Sha256 = Sha256Text(content),
                    ModifiedUtc = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                errors.Add($"Registry {key}: {ex.Message}");
            }
        }

        // Khóa HKCU — cần mở theo user hiện tại
        string[] hkcu =
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU",
            @"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths",
            @"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        };
        foreach (string key in hkcu)
        {
            try
            {
                using var rk = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(key);
                if (rk == null) continue;
                string content = DumpKey(rk, 0);
                arts.Add(new Artifact
                {
                    Source = "registry",
                    Category = "HKCU\\" + key,
                    Path = "HKCU\\" + key,
                    Kind_ = "registry",
                    ContentPreview = Trim(content, 200_000),
                    Sha256 = Sha256Text(content),
                    ModifiedUtc = DateTime.UtcNow
                });
            }
            catch (Exception ex)
            {
                errors.Add($"Registry HKCU\\{key}: {ex.Message}");
            }
        }

        return arts;
    }

    /// <summary>Đổ nội dung khóa registry (kể cả khóa con) ra văn bản.</summary>
    private static string DumpKey(Microsoft.Win32.RegistryKey key, int depth)
    {
        var sb = new StringBuilder();
        if (depth > 3) return sb.ToString();

        foreach (string name in key.GetValueNames())
        {
            try
            {
                object? val = key.GetValue(name, null,
                    Microsoft.Win32.RegistryValueOptions.DoNotExpandEnvironmentNames);
                sb.AppendLine($"  {name} = {val}");
            }
            catch { }
        }

        foreach (string sub in key.GetSubKeyNames())
        {
            try
            {
                using var child = key.OpenSubKey(sub);
                if (child == null) continue;
                sb.AppendLine($"[{sub}]");
                sb.Append(DumpKey(child, depth + 1));
                sb.AppendLine();
            }
            catch { }
        }
        return sb.ToString();
    }

    // ==================================================================
    //  3. HE THONG & TIEN TRINH
    // ==================================================================

    /// <summary>Thu thập tiến trình, scheduled task, event log liên quan.</summary>
    public static List<Artifact> CollectSystem(List<string> errors)
    {
        var arts = new List<Artifact>();

        void Add(string source, string category, string content, string path = "")
        {
            arts.Add(new Artifact
            {
                Source = source,
                Category = category,
                Path = path,
                Kind_ = "command-output",
                ContentPreview = Trim(content, 200_000),
                Sha256 = Sha256Text(content ?? ""),
                ModifiedUtc = DateTime.UtcNow
            });
        }

        // --- Tien trinh ---
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("PID\tPPID\tSESSION\tNAME\tCREATED\tPATH\tCMDLINE");
            using var s = new ManagementObjectSearcher(
                "SELECT ProcessId, ParentProcessId, SessionId, Name, CommandLine, ExecutablePath, CreationDate " +
                "FROM Win32_Process");
            using var r = s.Get();
            foreach (ManagementObject m in r)
            {
                sb.AppendLine(string.Join("\t", new[]
                {
                    m["ProcessId"]?.ToString() ?? "",
                    m["ParentProcessId"]?.ToString() ?? "",
                    m["SessionId"]?.ToString() ?? "",
                    m["Name"]?.ToString() ?? "",
                    m["CreationDate"]?.ToString() ?? "",
                    m["ExecutablePath"]?.ToString() ?? "",
                    m["CommandLine"]?.ToString() ?? ""
                }));
            }
            Add("process", "Running processes", sb.ToString(), "WMI:Win32_Process");
        }
        catch (Exception ex) { errors.Add("Thu thập tiến trình: " + ex.Message); }

        string tasks = RunShell("schtasks.exe", "/query /fo LIST /v");
        if (tasks.Length > 0)
            Add("process", "Scheduled tasks", tasks, "schtasks /query /fo LIST /v");

        // --- WMI autorun ---
        try
        {
            var sb = new StringBuilder();
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_StartupCommand");
            using var r = s.Get();
            foreach (ManagementObject m in r)
            {
                sb.AppendLine($"Name    : {m["Name"]}");
                sb.AppendLine($"Command : {m["Command"]}");
                sb.AppendLine($"Location: {m["Location"]}");
                sb.AppendLine($"User    : {m["User"]}");
                sb.AppendLine();
            }
            Add("process", "Autorun / startup commands", sb.ToString(), "WMI:Win32_StartupCommand");
        }
        catch (Exception ex) { errors.Add("Thu thập autorun: " + ex.Message); }

        // --- Event logs ---
        foreach (string logName in new[]
        {
            "Security", "System", "Application",
            "Microsoft-Windows-PowerShell/Operational",
            "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
            "Microsoft-Windows-DNS Client Events/Operational"
        })
        {
            try
            {
                string ev = RunShell("wevtutil.exe", "qe \"" + logName + "\" /c:60 /rd:true /f:text");
                if (ev.Length > 0)
                    Add("eventlog", "Event log: " + logName, ev, logName);
            }
            catch (Exception ex) { errors.Add($"Event log {logName}: {ex.Message}"); }
        }

        try
        {
            string sysinfo = RunShell("systeminfo.exe", "/fo list");
            Add("system", "System information", sysinfo, "systeminfo");
        }
        catch { }

        string ipall = RunShell("ipconfig.exe", "/all");
        if (ipall.Length > 0)
            Add("network", "ipconfig /all", ipall, "ipconfig /all");

        return arts;
    }

    // ==================================================================
    //  4. DAU VET TRUY CAP FILE & LO ROT TAI LIEU
    // ==================================================================

    /// <summary>Thu thập dấu vết truy cập file: Prefetch, JumpList, RecentFiles, LNK, staging.</summary>
    public static List<Artifact> CollectFileTraces(List<string> errors)
    {
        var arts = new List<Artifact>();
        string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);

        // --- Prefetch ---
        try
        {
            string prefetch = Path.Combine(win, @"Prefetch");
            if (Directory.Exists(prefetch))
            {
                foreach (string f in SafeFiles(prefetch).Take(MaxHashPerCategory))
                {
                    var fi = new FileInfo(f);
                    arts.Add(new Artifact
                    {
                        Source = "file",
                        Category = "Prefetch (program execution)",
                        Path = f,
                        Kind_ = "file",
                        SizeBytes = fi.Length,
                        ModifiedUtc = fi.LastWriteTimeUtc,
                        Sha256 = Sha256File(f) ?? ""
                    });
                }
            }
        }
        catch (Exception ex) { errors.Add("Thu thập Prefetch: " + ex.Message); }

        // --- Jump Lists / Recent / LNK ---
        try
        {
            var roots = new List<string>();
            foreach (string prof in UserProfiles())
            {
                roots.Add(Path.Combine(prof, @"AppData\Roaming\Microsoft\Windows\Recent"));
                roots.Add(Path.Combine(prof, @"AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations"));
                roots.Add(Path.Combine(prof, @"AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations"));
            }
            int n = 0;
            foreach (string root in roots)
            {
                if (!Directory.Exists(root)) continue;
                foreach (string f in SafeFiles(root))
                {
                    if (n++ >= MaxHashPerCategory) break;
                    var fi = new FileInfo(f);
                    arts.Add(new Artifact
                    {
                        Source = "file",
                        Category = "Jump List / Recent file / LNK",
                        Path = f,
                        Kind_ = "file",
                        SizeBytes = fi.Length,
                        ModifiedUtc = fi.LastWriteTimeUtc,
                        Sha256 = Sha256File(f) ?? ""
                    });
                }
            }
        }
        catch (Exception ex) { errors.Add("Thu thập Jump List: " + ex.Message); }

        // --- $UsnJrnl (chi ghi nhan metadata) ---
        try
        {
            var sb = new StringBuilder();
            sb.AppendLine("$UsnJrnl (NTFS change journal) — chi ghi nhan metadata, khong parse noi dung.");
            sb.AppendLine("Duong dan: \\\\.\\C:\\$Extend\\$UsnJrnl");
            sb.AppendLine("Yeu cau: thu giu o dia bang image/dd de phan tich ngoai tuyen.");
            arts.Add(new Artifact
            {
                Source = "file",
                Category = "NTFS $UsnJrnl (metadata only)",
                Path = @"\\.\C:\$Extend\$UsnJrnl",
                Kind_ = "command-output",
                ContentPreview = sb.ToString(),
                Sha256 = Sha256Text(sb.ToString()),
                ModifiedUtc = DateTime.UtcNow
            });
        }
        catch (Exception ex) { errors.Add("Thu thập $UsnJrnl: " + ex.Message); }

        // --- setupapi.dev.log ---
        try
        {
            string inf = Path.Combine(win, @"inf\setupapi.dev.log");
            if (File.Exists(inf))
            {
                var fi = new FileInfo(inf);
                arts.Add(new Artifact
                {
                    Source = "file",
                    Category = "SetupAPI device install log",
                    Path = inf,
                    Kind_ = "file",
                    SizeBytes = fi.Length,
                    ModifiedUtc = fi.LastWriteTimeUtc,
                    Sha256 = Sha256File(inf) ?? ""
                });
            }
        }
        catch (Exception ex) { errors.Add("Thu thập setupapi log: " + ex.Message); }

        // --- Staging / tep nen ---
        try
        {
            var candidates = new List<string>();
            foreach (string prof in UserProfiles())
            {
                candidates.Add(Path.Combine(prof, @"Downloads"));
                candidates.Add(Path.Combine(prof, @"Desktop"));
                candidates.Add(Path.Combine(prof, @"Documents"));
                candidates.Add(Path.Combine(prof, @"AppData\Local\Temp"));
            }
            var archiveExt = new[] { ".7z", ".rar", ".zip", ".tar", ".gz", ".enc", ".encrypted" };
            int n = 0;
            foreach (string dir in candidates)
            {
                if (!Directory.Exists(dir)) continue;
                foreach (string f in SafeFiles(dir))
                {
                    if (n++ >= 400) break;
                    string ext = Path.GetExtension(f).ToLowerInvariant();
                    bool isArchive = archiveExt.Contains(ext);
                    bool isLarge = false;
                    try { isLarge = new FileInfo(f).Length > 50L * 1024 * 1024; } catch { }
                    if (!isArchive && !isLarge) continue;

                    var fi = new FileInfo(f);
                    arts.Add(new Artifact
                    {
                        Source = "file",
                        Category = isArchive
                            ? "Archive / compressed file (exfil staging)"
                            : "Large file in temp/downloads",
                        Path = f,
                        Kind_ = "file",
                        SizeBytes = fi.Length,
                        ModifiedUtc = fi.LastWriteTimeUtc,
                        Sha256 = Sha256File(f) ?? ""
                    });
                }
            }
        }
        catch (Exception ex) { errors.Add("Thu thập staging: " + ex.Message); }

        return arts;
    }

    // ==================================================================
    //  5. LICH SU TRINH DUYET
    // ==================================================================

    /// <summary>Thu thập lịch sử trình duyệt (Chrome/Edge/Firefox/Brave/Vivaldi).</summary>
    public static List<Artifact> CollectBrowserHistory(List<string> errors)
    {
        var arts = new List<Artifact>();

        var roots = new List<string>();
        foreach (string prof in UserProfiles())
        {
            roots.Add(Path.Combine(prof, @"AppData\Local\Google\Chrome\User Data"));
            roots.Add(Path.Combine(prof, @"AppData\Local\Microsoft\Edge\User Data"));
            roots.Add(Path.Combine(prof, @"AppData\Local\BraveSoftware\Brave-Browser\User Data"));
            roots.Add(Path.Combine(prof, @"AppData\Local\Vivaldi\User Data"));
            roots.Add(Path.Combine(prof, @"AppData\Roaming\Mozilla\Firefox\Profiles"));
        }
        string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        roots.Add(Path.Combine(local, @"Google\Chrome\User Data"));
        roots.Add(Path.Combine(local, @"Microsoft\Edge\User Data"));
        roots.Add(Path.Combine(local, @"Mozilla\Firefox\Profiles"));

        var wanted = new[] { "History", "History-journal", "places.sqlite", "places.sqlite-wal",
                            "cookies.sqlite", "formhistory.sqlite", "Downloads", "Top Sites",
                            "Web Data", @"Network\Cookies", @"Network\Network Persistent State" };

        foreach (string root in roots.Distinct())
        {
            if (!Directory.Exists(root)) continue;
            foreach (string prof in SafeDirs(root))
            {
                foreach (string name in wanted)
                {
                    string p = Path.Combine(prof, name);
                    if (!File.Exists(p)) continue;
                    try
                    {
                        var fi = new FileInfo(p);
                        arts.Add(new Artifact
                        {
                            Source = "browser",
                            Category = "Browser history / cookie / download (" + name + ")",
                            Path = p,
                            Kind_ = "file",
                            SizeBytes = fi.Length,
                            ModifiedUtc = fi.LastWriteTimeUtc,
                            Sha256 = Sha256File(p) ?? ""
                        });
                    }
                    catch (Exception ex) { errors.Add("Browser " + p + ": " + ex.Message); }
                }
            }
        }

        return arts;
    }

    // ==================================================================
    //  TIEN ICH
    // ==================================================================

    /// <summary>Chạy lệnh shell và trả về stdout (đã cắt ngắn).</summary>
    private static string RunShell(string file, string args)
    {
        try
        {
            var psi = new ProcessStartInfo(file, args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.GetEncoding(0),
                StandardErrorEncoding = Encoding.GetEncoding(0)
            };
            using var p = Process.Start(psi);
            if (p == null) return "";
            string outp = p.StandardOutput.ReadToEnd();
            string err = p.StandardError.ReadToEnd();
            if (!p.WaitForExit(30_000)) { try { p.Kill(true); } catch { } }
            return Trim(outp + (err.Length > 0 ? "\n[stderr] " + err : ""), 200_000);
        }
        catch
        {
            return "";
        }
    }

    private static IEnumerable<string> UserProfiles()
    {
        var list = new List<string>();
        try
        {
            string baseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "..");
            foreach (string p in Directory.EnumerateDirectories(baseDir))
            {
                string name = Path.GetFileName(p);
                if (name.StartsWith(".")) continue;
                if (string.Equals(name, "Public", StringComparison.OrdinalIgnoreCase)) continue;
                list.Add(p);
            }
        }
        catch { }
        list.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
        return list.Distinct();
    }

    private static IEnumerable<string> SafeFiles(string dir)
    {
        // Khong yield trong try/catch (C# cho phép yield trong try chi khi khong co catch)
        string[] files;
        try
        {
            files = Directory.GetFiles(dir);
        }
        catch
        {
            yield break;
        }
        foreach (string f in files) yield return f;
    }

    private static IEnumerable<string> SafeDirs(string dir)
    {
        var list = new List<string>();
        try
        {
            foreach (string d in Directory.EnumerateDirectories(dir)) list.Add(d);
        }
        catch { }
        list.Add(dir);
        return list;
    }

    private static string Trim(string s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Length <= max ? s : s.Substring(0, max) + "\n... [da cat bot]";
    }
}
