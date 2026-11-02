using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecTool
{
    /// <summary>Kinh loại dòng nhật ký của chức năng Làm sạch PC một chạm.</summary>
    public enum CleanLogKind
    {
        Info,
        Success,
        Warn,
        Error,
        Step,
        Heading
    }

    /// <summary>Kết quả một lần chạy làm sạch.</summary>
    public sealed class CleanResult
    {
        public int Total;
        public int Succeeded;
        public int Failed;
        public int Skipped;
        public int MiAVInternetRows;
        public int MiAVInternetUnsent;
        public bool InternetDetected;
        public bool RebootScheduled;
        public bool MiAVInstalled;
        public readonly List<string> Items = new List<string>();
    }

    /// <summary>Tùy chọn cho chức năng làm sạch.</summary>
    public sealed class CleanOptions
    {
        /// <summary>Thư mục gốc cài đặt MiAV.</summary>
        public string AgentFMCRoot = @"C:\Users\Public\Documents\AgentFMC";
        /// <summary>Thư mục lưu bản sao lưu + báo cáo.</summary>
        public string BackupRoot = @"C:\_Danny_Cleanup";
        /// <summary>Có xóa lịch sử trình duyệt / SRUM / Prefetch / Amcache / Jump List không.</summary>
        public bool CleanBrowserHistory = true;
        public bool CleanSrum = true;
        public bool CleanDnsCache = true;
        public bool CleanPrefetch = true;
        public bool CleanAmcache = true;
        public bool CleanRunMru = true;
        public bool CleanJumpList = true;
        public bool CleanEventLog = true;
        /// <summary>Có xóa artifact của MiAV (mục 6 / quy trình 12 bước) không.</summary>
        public bool CleanMiAV = true;
        /// <summary>Chạy KVRT quét toàn bộ ổ + tự khử nhiễm.</summary>
        public bool RunKvrt = true;
        /// <summary>Chạy KVRT ở chế độ không giao diện.</summary>
        public bool KvrtSilent = true;
        /// <summary>Cài đặt lại phần mềm MiAV sau khi quét (bước cuối, trước khi reboot).</summary>
        public bool InstallMiAV = true;
        /// <summary>Đường dẫn SetupMiAV.exe (mặc định tìm trong thư mục tools).</summary>
        public string MiAVSetupPath = "";
        /// <summary>Khởi động lại máy sau khi quét xong.</summary>
        public bool RebootAfterKvrt = true;
        /// <summary>Số giây đếm ngược trước khi khởi động lại.</summary>
        public int RebootDelaySeconds = 60;
    }

    /// <summary>
    ///  Chức năng "Làm sạch PC một chạm".
    ///
    ///  Tham chiếu: Phan tich MiAV/BAO-CAO-PHAN-TICH-MIAV.md
    ///    - Mục 6  : Ma trận artifact (nhóm A bắt buộc, nhóm B nên làm, nhóm C tùy chọn)
    ///    - Mục 7  : Quy trình 12 bước
    ///
    ///  Nguyên tắc an toàn (theo báo cáo):
    ///    1. Sao lưu trước khi xóa.
    ///    2. Dừng 4 service + tiến trình MiAV trước khi xóa, bật lại sau đó.
    ///    3. Cột time_sent cho biết dữ liệu nào đã gửi lên server FMS → không thu hồi được cục bộ.
    ///    4. Không đụng tới driver/kernel CBFSFilter (không liên quan lịch sử Internet).
    /// </summary>
    public static class PcCleaner
    {
        // ------------------------------------------------------------
        //  Hằng số đường dẫn
        // ------------------------------------------------------------
        private static readonly string[] MiAVServices =
        {
            "MiAVProtect", "MiAVUpdate", "MiAVWD", "Defense"
        };

        private static readonly string[] MiAVProcesses =
        {
            "MiAV.exe", "MiAV_Protect.exe", "MiAV_Update.exe", "MiAV_WD.exe", "SerDefense.exe"
        };

        private static readonly string[] MiAVPolicyFiles =
        {
            "policy.info", "policy.ping", "policy.net",
            "policy.tracertWiki", "policy.tracertpBTL", "policy.tracertlBTL"
        };

        private static readonly string[] MiAVLogDirs =
        {
            "logs", "Debug"
        };

        private static readonly string[] MiAVLogFiles =
        {
            "log.txt", "syslog.ini", "debugmiav.txt", "debug.ini"
        };

        private static readonly string[] MiAVModuleDirs =
        {
            "auto", "0dpm", "2109", "rasoat"
        };

        // ============================================================
        //  P1 - Kiểm tra Internet (bước 1)
        // ============================================================
        public static bool DetectInternet()
        {
            try
            {
                using var p = new Process
                {
                    StartInfo = new ProcessStartInfo("ping.exe", "-n 1 -w 1500 8.8.8.8")
                    {
                        CreateNoWindow = true,
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true
                    }
                };
                p.Start();
                string output = p.StandardOutput.ReadToEnd();
                p.WaitForExit(4000);
                return output.Contains("TTL=") || output.Contains("tl=");
            }
            catch { return false; }
        }

        // ============================================================
        //  P2 - Kiểm kê hiện trạng (bước 2)
        // ============================================================
        public static (int total, int internet, int unsent) InspectMiAVLogs(string agentRoot)
        {
            try
            {
                string db = Path.Combine(agentRoot, @"data\data.db");
                if (!File.Exists(db)) return (0, 0, 0);

                using var conn = new SqliteDb(db);
                conn.Open();
                int total = conn.ScalarInt("SELECT COUNT(*) FROM Logs");
                int internet = conn.ScalarInt("SELECT COUNT(*) FROM Logs WHERE type='Internet'");
                int unsent = conn.ScalarInt(
                    "SELECT COUNT(*) FROM Logs WHERE type='Internet' AND (time_sent IS NULL OR time_sent='')");
                return (total, internet, unsent);
            }
            catch { return (0, 0, 0); }
        }

        // ============================================================
        //  HÀM CHÍNH
        // ============================================================
        public static CleanResult Run(
            CleanOptions opt,
            Action<string, CleanLogKind>? log = null,
            Action<int, int>? progress = null,
            CancellationToken ct = default)
        {
            var res = new CleanResult();
            Action<string, CleanLogKind> L = (m, k) => log?.Invoke(m, k);
            Action<int, int> P = (c, t) => progress?.Invoke(c, t);

            string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            string workDir = Path.Combine(opt.BackupRoot, stamp);
            string reportDir = Path.Combine(workDir, "BaoCao");

            // Danh sách bước để thanh tiến độ (phải khớp đúng số lần gọi NextStep)
            var steps = new List<string>();
            if (opt.CleanMiAV)
            {
                steps.Add("Kiểm tra Internet");
                steps.Add("Kiểm kê MiAV");
                steps.Add("Sao lưu");
                steps.Add("Dừng service MiAV");
                steps.Add("Xóa artifact MiAV nhóm A");
                steps.Add("Xóa artifact MiAV nhóm B");
                steps.Add("Xác minh MiAV");
                steps.Add("Bật lại service MiAV");
            }
            if (opt.CleanBrowserHistory) steps.Add("Xóa lịch sử trình duyệt");
            if (opt.CleanSrum) steps.Add("Xóa SRUM");
            if (opt.CleanDnsCache) steps.Add("Xóa DNS cache");
            if (opt.CleanPrefetch) steps.Add("Xóa Prefetch");
            if (opt.CleanAmcache) steps.Add("Xóa Amcache");
            if (opt.CleanRunMru) steps.Add("Xóa RunMRU / TypedPaths");
            if (opt.CleanJumpList) steps.Add("Xóa Jump List");
            if (opt.CleanEventLog) steps.Add("Xóa Windows Event Log");
            if (opt.RunKvrt) steps.Add("Quét & khử nhiễm KVRT");
            if (opt.InstallMiAV) steps.Add("Cài đặt lại phần mềm MiAV");
            steps.Add("Hoàn tất");

            int idx = -1;
            void NextStep(string title)
            {
                idx++;
                L($"BƯỚC {idx + 1}/{steps.Count}: {title}", CleanLogKind.Heading);
                P(Math.Min(idx, steps.Count), steps.Count);
            }
            void Item(string name, bool ok, string? detail = null)
            {
                res.Total++;
                if (ok) { res.Succeeded++; res.Items.Add("[OK]   " + name + (detail != null ? " — " + detail : "")); L($"✓ {name}" + (detail != null ? " — " + detail : ""), CleanLogKind.Success); }
                else { res.Failed++; res.Items.Add("[LỖI]  " + name + (detail != null ? " — " + detail : "")); L($"✗ {name}" + (detail != null ? " — " + detail : ""), CleanLogKind.Error); }
            }
            void Skip(string name, string? detail = null)
            {
                res.Skipped++;
                res.Items.Add("[BỎ QUA] " + name + (detail != null ? " — " + detail : ""));
                L($"– {name}" + (detail != null ? " — " + detail : ""), CleanLogKind.Warn);
            }

            try
            {
                // ============ BƯỚC 1: kiểm tra Internet ============
                if (opt.CleanMiAV)
                {
                    NextStep("Kiểm tra trạng thái Internet của máy");
                    res.InternetDetected = DetectInternet();
                    if (res.InternetDetected)
                    {
                        L("Máy ĐANG có Internet. Nên ngắt Internet trước khi làm sạch, "
                          + "vì MiAV sẽ tự tạo lại file policy.* và ghi sự kiện Plug-in mới ngay lập.",
                          CleanLogKind.Warn);
                    }
                    else
                    {
                        L("Máy không có Internet — điều kiện lý tưởng để làm sạch.", CleanLogKind.Success);
                    }

                    // ============ BƯỚC 2: kiểm kê ============
                    NextStep("Kiểm kê hiện trạng log MiAV");
                    var (total, internet, unsent) = InspectMiAVLogs(opt.AgentFMCRoot);
                    res.MiAVInternetRows = internet;
                    res.MiAVInternetUnsent = unsent;
                    L($"Bảng Logs: tổng {total} dòng, type='Internet' {internet} dòng "
                      + $"(trong đó {unsent} dòng chưa gửi đi).", CleanLogKind.Info);
                    if (unsent > 0)
                        L($"⚠ {unsent} dòng chưa gửi → xóa cục bộ là đủ. "
                          + $"{Math.Max(0, internet - unsent)} dòng đã gửi lên server FMS → "
                          + "cần đề nghị quản trị viên FMS/BTL86 xóa phía server.",
                          CleanLogKind.Warn);
                    if (internet > 0)
                        L("Có dấu vết 'máy đã từng nối Internet' trong bảng Logs của MiAV.", CleanLogKind.Warn);
                    else
                        L("Không có dấu vết sự kiện Internet trong bảng Logs.", CleanLogKind.Success);

                    // ============ BƯỚC 3: sao lưu ============
                    NextStep("Sao lưu toàn bộ thư mục AgentFMC");
                    try
                    {
                        Directory.CreateDirectory(workDir);
                        if (Directory.Exists(opt.AgentFMCRoot))
                        {
                            string dest = Path.Combine(workDir, "AgentFMC");
                            CopyDirectory(opt.AgentFMCRoot, dest);
                            L($"Đã sao lưu: {opt.AgentFMCRoot} → {dest}", CleanLogKind.Success);
                        }
                        else
                        {
                            Skip("Sao lưu thư mục MiAV", "không tồn tại " + opt.AgentFMCRoot);
                        }
                    }
                    catch (Exception ex) { Item("Sao lưu thư mục MiAV", false, ex.Message); }

                    // ============ BƯỚC 4: dừng service MiAV ============
                    NextStep("Dừng 4 service MiAV (MiAVProtect / MiAVUpdate / MiAVWD / Defense)");
                    foreach (string svc in MiAVServices)
                    {
                        if (!ServiceExists(svc)) { Skip($"Dừng service {svc}", "service không tồn tại"); continue; }
                        bool ok = RunSc($"stop {svc}") && RunSc($"config {svc} start= disabled");
                        Item($"Dừng + tạm khóa service {svc}", ok);
                    }

                    // Dừng tiến trình GUI
                    foreach (string proc in MiAVProcesses)
                    {
                        bool found = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(proc)).Length > 0;
                        if (!found) { Skip($"Dừng tiến trình {proc}", "không chạy"); continue; }
                        bool ok = KillProcess(proc);
                        Item($"Dừng tiến trình {proc}", ok);
                    }
                    Thread.Sleep(1500);

                    // ============ BƯỚC 5: xóa artifact MiAV (nhóm A + B) ============
                    NextStep("Xóa artifact MiAV — nhóm A (bắt buộc)");
                    // A1 — bảng Logs trong data.db
                    string dbPath = Path.Combine(opt.AgentFMCRoot, @"data\data.db");
                    if (File.Exists(dbPath))
                    {
                        try
                        {
                            using var conn = new SqliteDb(dbPath);
                            conn.Open();
                            int rows = conn.ScalarInt("SELECT COUNT(*) FROM Logs");
                            conn.Execute("DELETE FROM Logs");
                            try { conn.Execute("VACUUM"); } catch { }
                            Item("Xóa toàn bộ bảng Logs trong data.db", true, $"{rows} dòng đã xóa + VACUUM");
                        }
                        catch (Exception ex) { Item("Xóa bảng Logs trong data.db", false, ex.Message); }
                    }
                    else Skip("Xóa bảng Logs", "không tìm thấy data.db");

                    // A2..A9 — file policy.*
                    foreach (string f in MiAVPolicyFiles)
                    {
                        string path = Path.Combine(opt.AgentFMCRoot, f);
                        if (!File.Exists(path)) { Skip($"Xóa {f}", "không tồn tại"); continue; }
                        Item($"Xóa {f}", DeletePath(path));
                    }
                    // A2 — thư mục logs, Debug
                    foreach (string d in MiAVLogDirs)
                    {
                        string path = Path.Combine(opt.AgentFMCRoot, d);
                        if (!Directory.Exists(path)) { Skip($"Xóa thư mục {d}", "không tồn tại"); continue; }
                        Item($"Xóa thư mục {d}", DeletePath(path));
                    }
                    // A3 — file log text
                    foreach (string f in MiAVLogFiles)
                    {
                        string path = Path.Combine(opt.AgentFMCRoot, f);
                        if (!File.Exists(path)) { Skip($"Xóa {f}", "không tồn tại"); continue; }
                        Item($"Xóa {f}", DeletePath(path));
                    }

                    NextStep("Xóa artifact MiAV — nhóm B (nên làm)");
                    // B1 — config.ini
                    string cfg = Path.Combine(opt.AgentFMCRoot, @"data\config.ini");
                    if (File.Exists(cfg)) Item("Xóa data\\config.ini", DeletePath(cfg));
                    else Skip("Xóa data\\config.ini", "không tồn tại");
                    // B2 — module tải về
                    foreach (string d in MiAVModuleDirs)
                    {
                        string path = Path.Combine(opt.AgentFMCRoot, d);
                        if (!Directory.Exists(path)) { Skip($"Xóa thư mục {d}", "không tồn tại"); continue; }
                        Item($"Xóa thư mục {d}", DeletePath(path));
                    }
                    // B3 — Blackip.txt
                    string blackip = Path.Combine(opt.AgentFMCRoot, "Blackip.txt");
                    if (File.Exists(blackip)) Item("Xóa Blackip.txt", DeletePath(blackip));
                    else Skip("Xóa Blackip.txt", "không tồn tại");
                    // B4 — bảng LocalFiles (AutoRun đã thu thập)
                    if (File.Exists(dbPath))
                    {
                        try
                        {
                            using var conn = new SqliteDb(dbPath);
                            conn.Open();
                            int rows = conn.ScalarInt("SELECT COUNT(*) FROM LocalFiles");
                            conn.Execute("DELETE FROM LocalFiles");
                            Item("Xóa bảng LocalFiles (AutoRun)", true, $"{rows} dòng");
                        }
                        catch (Exception ex) { Item("Xóa bảng LocalFiles", false, ex.Message); }
                    }

                    // ============ BƯỚC 6: xác minh MiAV ============
                    NextStep("Xác minh kết quả trên artifact MiAV");
                    var (t2, i2, _) = InspectMiAVLogs(opt.AgentFMCRoot);
                    bool policyLeft = MiAVPolicyFiles.Any(f => File.Exists(Path.Combine(opt.AgentFMCRoot, f)));
                    if (i2 == 0 && !policyLeft)
                        L("Xác minh OK: bảng Logs không còn sự kiện 'Internet', không còn file policy.*.", CleanLogKind.Success);
                    else
                        L($"Xác minh: còn {i2} dòng Internet, policy.* còn tồn tại: {policyLeft}.", CleanLogKind.Warn);

                    // ============ BƯỚC 7: bật lại service ============
                    NextStep("Bật lại 4 service MiAV");
                    foreach (string svc in MiAVServices)
                    {
                        if (!ServiceExists(svc)) { Skip($"Bật lại service {svc}", "service không tồn tại"); continue; }
                        bool ok = RunSc($"config {svc} start= auto") && RunSc($"start {svc}");
                        Item($"Bật lại service {svc}", ok);
                    }
                }

                // ============ NHÓM C: artifact Windows ============
                if (opt.CleanBrowserHistory)
                {
                    NextStep("Xóa lịch sử trình duyệt (Chrome / Edge / Firefox / IE)");
                    int removed = CleanBrowserHistory(L);
                    if (removed > 0) L($"Đã xóa {removed} nhóm tệp lịch sử trình duyệt.", CleanLogKind.Success);
                    else Skip("Lịch sử trình duyệt", "không tìm thấy tệp nào (chưa cài trình duyệt)");
                }

                if (opt.CleanSrum)
                {
                    NextStep("Xóa SRUM (SRUDB.dat)");
                    Item("Xóa SRUDB.dat", CleanSrum(L));
                }

                if (opt.CleanDnsCache)
                {
                    NextStep("Xóa DNS cache");
                    bool ok = RunCommand("ipconfig.exe", "/flushdns");
                    Item("ipconfig /flushdns", ok);
                    bool arp = RunCommand("arp.exe", "-d *");
                    Item("arp -d * (xóa bảng ARP)", arp);
                }

                if (opt.CleanPrefetch)
                {
                    NextStep("Xóa Prefetch");
                    string pf = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Prefetch");
                    if (!Directory.Exists(pf)) Skip("Xóa Prefetch", "thư mục không tồn tại");
                    else
                    {
                        int n = 0; bool ok = true;
                        foreach (string f in Directory.EnumerateFiles(pf))
                            if (DeletePath(f)) n++;
                            else ok = false;
                        Item("Xóa tệp Prefetch", ok, $"{n} tệp");
                    }
                }

                if (opt.CleanAmcache)
                {
                    NextStep("Xóa Amcache (Amcache.hve)");
                    Item("Xóa Amcache.hve", CleanAmcache(L));
                }

                if (opt.CleanRunMru)
                {
                    NextStep("Xóa RunMRU / TypedPaths / RecentDocs");
                    int n = 0;
                    if (DeleteRegistryKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU")) n++;
                    if (DeleteRegistryKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths")) n++;
                    if (DeleteRegistryKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs")) n++;
                    // Word / Office MRU
                    if (DeleteRegistryKey(@"Software\Microsoft\Office\16.0\Word\Options")) n++;
                    if (DeleteRegistryKey(@"Software\Microsoft\Office\16.0\Excel\Options")) n++;
                    Item("Xóa RunMRU / TypedPaths / RecentDocs", true, $"{n} khóa registry đã xóa");
                }

                if (opt.CleanJumpList)
                {
                    NextStep("Xóa Jump List (AutomaticDestinations / CustomDestinations)");
                    int n = 0; bool ok = true;
                    foreach (string profile in EnumerateUserProfiles())
                    {
                        foreach (string sub in new[] { "AutomaticDestinations", "CustomDestinations" })
                        {
                            string p = Path.Combine(profile, @"AppData\Roaming\Microsoft\Windows\Recent", sub);
                            if (!Directory.Exists(p)) continue;
                            if (DeletePath(p)) n++; else ok = false;
                        }
                    }
                    Item("Xóa Jump List", ok, $"{n} thư mục");
                }

                if (opt.CleanEventLog)
                {
                    NextStep("Xóa Windows Event Log (winevt)");
                    Item("Xóa toàn bộ Event Log", ClearEventLogs(L));
                }

                // ============ KVRT ============
                if (opt.RunKvrt)
                {
                    NextStep("Chạy Kaspersky KVRT — quét toàn bộ ổ đĩa + tự khử nhiễm");
                    string kvrt = LocateKvrt();
                    if (kvrt == null)
                    {
                        Skip("Kaspersky KVRT", "không tìm thấy KVRT.exe trong thư mục tools\\");
                    }
                    else
                    {
                        L($"Sử dụng: {kvrt}", CleanLogKind.Info);
                        string kvrtData = Path.Combine(workDir, "KVRT_Data");
                        Directory.CreateDirectory(kvrtData);
                        string args = BuildKvrtArgs(opt, kvrtData);
                        L($"Lệnh: KVRT.exe {args}", CleanLogKind.Info);
                        bool ok = RunKvrt(kvrt, args, L);
                        if (ok)
                        {
                            L("KVRT đã hoàn tất quét và khử nhiễm.", CleanLogKind.Success);
                            Item("Chạy KVRT (allvolumes + adinsilent)", true);
                        }
                        else
                        {
                            L("KVRT kết thúc với mã lỗi hoặc bị người dùng hủy.", CleanLogKind.Warn);
                            Item("Chạy KVRT", false, "xem nhật ký trong thư mục dữ liệu KVRT");
                        }
                    }
                }

                // ============ BƯỚC CUỐI: cài đặt lại phần mềm MiAV ============
                if (opt.InstallMiAV)
                {
                    NextStep("Cài đặt lại phần mềm MiAV (BTL86)");
                    string setupPath = LocateMiAVSetup(opt.MiAVSetupPath);
                    if (setupPath == null)
                    {
                        Skip("Cài đặt MiAV", "không tìm thấy SetupMiAV.exe trong thư mục tools\\");
                        L("Đặt file SetupMiAV.exe vào thư mục tools\\ cạnh Danny.exe "
                          + "để phần mềm có thể cài lại MiAV tự động.", CleanLogKind.Warn);
                    }
                    else
                    {
                        L($"Sử dụng: {setupPath}", CleanLogKind.Info);
                        bool ok = InstallMiAVSoftware(setupPath, workDir, L);
                        res.MiAVInstalled = ok;
                        if (ok)
                        {
                            Item("Cài đặt lại MiAV (4 service đã tạo)", true);
                        }
                        else
                        {
                            Item("Cài đặt lại MiAV", false,
                                "xem log cài đặt trong thư mục làm sạch");
                        }
                    }
                }

                // ============ Hoàn tất ============
                NextStep("Hoàn tất");
                try { Directory.CreateDirectory(reportDir); } catch { }
                try
                {
                    string csv = Path.Combine(reportDir, "BaoCao_LamSach.csv");
                    File.WriteAllLines(csv, new[]
                    {
                        "Kết quả,Làm sạch PC một chạm",
                        "Thời điểm," + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"),
                        "Máy có Internet khi chạy," + res.InternetDetected,
                        "Tổng hạng mục," + res.Total,
                        "Thành công," + res.Succeeded,
                        "Thất bại," + res.Failed,
                        "Bỏ qua," + res.Skipped,
                        "Dòng Logs type=Internet trước khi xóa," + res.MiAVInternetRows,
                        "Dòng Logs type=Internet chưa gửi," + res.MiAVInternetUnsent,
                        "Đã cài lại MiAV," + res.MiAVInstalled,
                        ""
                    }.Concat(res.Items));
                    L($"Báo cáo: {csv}", CleanLogKind.Info);
                }
                catch { }

                L($"Tổng: {res.Succeeded} thành công / {res.Failed} lỗi / {res.Skipped} bỏ qua.", CleanLogKind.Heading);
            }
            catch (Exception ex)
            {
                L("Lỗi không mong đợi: " + ex.Message, CleanLogKind.Error);
                Item("Chạy chức năng làm sạch", false, ex.Message);
            }

            P(steps.Count, steps.Count);
            return res;
        }

        // ============================================================
        //  Thành phần: lịch sử trình duyệt
        // ============================================================
        private static int CleanBrowserHistory(Action<string, CleanLogKind> L)
        {
            int removed = 0;
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);

            // Thu thap moi thu muc "User Data" cua tat ca profile (khong chi user hien tai)
            var chromiumRoots = new List<string>();
            foreach (string profileDir in EnumerateUserProfiles())
            {
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Local\Google\Chrome\User Data"));
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Local\Microsoft\Edge\User Data"));
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Local\BraveSoftware\Brave-Browser\User Data"));
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Local\Vivaldi\User Data"));
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Local\Yandex\YandexBrowser\User Data"));
                chromiumRoots.Add(Path.Combine(profileDir, @"AppData\Roaming\Opera Software\Opera Stable"));
            }
            // Profile cua user hien tai (du phong)
            chromiumRoots.Add(Path.Combine(local, @"Google\Chrome\User Data"));
            chromiumRoots.Add(Path.Combine(local, @"Microsoft\Edge\User Data"));
            chromiumRoots.Add(Path.Combine(roaming, @"Opera Software\Opera Stable"));

            // Chrome / Edge (Chromium) — moi Profile
            foreach (string browserRoot in chromiumRoots.Distinct())
            {
                if (!Directory.Exists(browserRoot)) continue;

                // File "History" nam o goc root voi cac profile khac ten (Default, Profile 1...)
                foreach (string profile in SafeEnumerateDirs(browserRoot))
                {
                    foreach (string name in new[] { "History", "History-journal", "Login Data", "Login Data-journal", "Cookies", "Cookies-journal", "Web Data", "Web Data-journal", "Top Sites", "Shortcuts", "Favicons", @"Network\Cookies" })
                    {
                        string p = Path.Combine(profile, name);
                        if (!File.Exists(p)) continue;
                        if (DeletePath(p)) removed++;
                        else L($"Không xóa được {p} (file đang bị khóa).", CleanLogKind.Warn);
                    }
                    // "Network" thu muc chua Cookies / Network Persistent State
                    string netDir = Path.Combine(profile, "Network");
                    if (Directory.Exists(netDir))
                    {
                        foreach (string f in SafeEnumerateFiles(netDir))
                            if (DeletePath(f)) removed++;
                    }
                }
            }

            // Firefox — moi profile
            foreach (string profileDir in EnumerateUserProfiles().Append(local).Distinct())
            {
                string ffRoot = Path.Combine(profileDir, @"Mozilla\Firefox\Profiles");
                if (!Directory.Exists(ffRoot)) continue;
                foreach (string profile in SafeEnumerateDirs(ffRoot))
                {
                    foreach (string name in new[] { "places.sqlite", "places.sqlite-wal", "places.sqlite-shm", "formhistory.sqlite", "formhistory.sqlite-wal", "formhistory.sqlite-shm", "cookies.sqlite", "cookies.sqlite-wal", "webappsstore.sqlite", "content-prefs.sqlite", "permissions.sqlite", "sessionstore.jsonlz4", "sessionstore-backups" })
                    {
                        string p = Path.Combine(profile, name);
                        if (!File.Exists(p)) continue;
                        if (DeletePath(p)) removed++;
                    }
                }
            }

            // Internet Explorer / Edge Legacy
            foreach (string p in new[]
            {
                Path.Combine(local, @"Microsoft\Windows\WebCache"),
                Path.Combine(local, @"Microsoft\Windows\INetCache"),
                Path.Combine(local, @"Microsoft\Windows\WebCacheV01.dat"),
                Path.Combine(local, @"Microsoft\Internet Explorer\IntelliForms\Storage\IE-WebCacheV01.dat")
            })
            {
                if (File.Exists(p)) { if (DeletePath(p)) removed++; }
                else if (Directory.Exists(p)) { if (DeletePath(p)) removed++; }
            }

            return removed;
        }

        // ============================================================
        //  Thành phần: SRUM
        // ============================================================
        private static bool CleanSrum(Action<string, CleanLogKind> L)
        {
            string data = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\SRUDB.dat");
            if (!File.Exists(data)) return true;

            // Dịch vụ SRUM (DiagTrack) giữ khoá tệp → phải dừng trước
            foreach (string svc in new[] { "DiagTrack", "WerSvc", "WaaSMedicSvc" })
            {
                if (ServiceExists(svc)) RunSc($"stop {svc}");
            }
            Thread.Sleep(1200);

            bool ok = DeletePath(data);
            if (!ok)
            {
                L("Không xóa được SRUDB.dat trực tiếp (đang bị khóa) → thử với quyền SYSTEM.", CleanLogKind.Warn);
                ok = RunAsSystem($"del /f /q \"{data}\"");
            }
            foreach (string svc in new[] { "DiagTrack", "WerSvc" })
                if (ServiceExists(svc)) RunSc($"start {svc}");
            return ok;
        }

        // ============================================================
        //  Thành phần: Amcache (cần quyền SYSTEM)
        // ============================================================
        private static bool CleanAmcache(Action<string, CleanLogKind> L)
        {
            string win = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string amcache = Path.Combine(win, @"AppCompat\Programs\Amcache.hve");
            if (!File.Exists(amcache)) return true;

            // Amcache hạn chế quyền TrustedInstaller → chạy takeown/icacls/del bằng SYSTEM
            string cmd =
                $"takeown /f \"{amcache}\" /a && " +
                $"icacls \"{amcache}\" /grant *S-1-5-18:F /c /q && " +
                $"del /f /q \"{amcache}\"";

            bool ok = RunAsSystem(cmd);
            if (!ok)
            {
                L("Không xóa được Amcache.hve bằng SYSTEM → thử quyền trực tiếp.", CleanLogKind.Warn);
                ok = DeletePath(amcache);
            }
            return ok;
        }

        // ============================================================
        //  Thành phần: Windows Event Log
        // ============================================================
        private static bool ClearEventLogs(Action<string, CleanLogKind> L)
        {
            int cleared = 0, failed = 0;
            foreach (string log in SafeEnumerateFiles(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Windows), @"System32\winevt\Logs")))
            {
                if (!log.EndsWith(".evtx", StringComparison.OrdinalIgnoreCase)) continue;
                if (RunCommand("wevtutil.exe", "cl \"" + log + "\""))
                    cleared++;
                else
                    failed++;
            }
            L($"Đã xóa {cleared} tệp Event Log, {failed} tệp không xóa được "
              + "(một số log hệ thống không cho phép xóa dù đã có quyền quản trị).",
              failed > 0 ? CleanLogKind.Warn : CleanLogKind.Success);
            // Dọn thêm log hệ thống không nằm trong thư mục Logs
            foreach (string svc in new[] { "eventlog", "Sysmon", "Sysmon64", "WinDefend" })
                if (ServiceExists(svc)) { RunSc($"stop {svc}"); }
            foreach (string svc in new[] { "eventlog", "Sysmon", "Sysmon64", "WinDefend" })
                if (ServiceExists(svc)) { RunSc($"start {svc}"); }
            return cleared > 0 || failed == 0;
        }

        // ============================================================
        //  Thành phần: cài đặt lại MiAV (bước cuối, trước khi reboot)
        // ============================================================

        /// <summary>
        ///  Tìm file SetupMiAV.exe trong thư mục tools (hoặc đường dẫn chỉ định).
        /// </summary>
        public static string? LocateMiAVSetup(string? explicitPath = null)
        {
            var candidates = new List<string>();
            if (!string.IsNullOrWhiteSpace(explicitPath))
                candidates.Add(explicitPath);
            candidates.Add(Path.Combine(AppContext.BaseDirectory, "tools", "SetupMiAV.exe"));
            candidates.Add(Path.Combine(AppContext.BaseDirectory, "SetupMiAV.exe"));
            candidates.Add(Path.Combine(Path.GetTempPath(), "SetupMiAV.exe"));

            foreach (string c in candidates)
                if (File.Exists(c)) return c;
            return null;
        }

        /// <summary>
        ///  Xây dựng dòng lệnh cài đặt cho SetupMiAV.exe.
        ///
        ///  SetupMiAV.exe là trình cài đặt Inno Setup 6.6.1 (Unicode) với các
        ///  thuộc tính đã xác minh từ install_script.iss:
        ///    DisableDirPage=yes          → không cần thư mục đích (mặc định {commondocs}\AgentFMC)
        ///    DisableProgramGroupPage=yes → không tạo menu Start
        ///    ShowLanguageDialog=yes      → cần chỉ định /LANG để chạy không tương tác
        ///    Uninstallable=no            → không tạo mục gỡ cài đặt
        ///
        ///  Tham số Inno Setup:
        ///    /VERYSILENT           — cài không tương tác, không hiện cửa sổ
        ///    /SUPPRESSMSGBOXES     — bỏ qua hộp thoại nhắc
        ///    /SP-                  — bỏ qua hộp "This will install..." (đã dùng)
        ///    /NORESTART            — không tự khởi động lại (Danny sẽ reboot ở bước sau)
        ///    /LOG="file"           — ghi log cài đặt để điều tra
        ///    /LANG=english         — bỏ qua hộp chọn ngôn ngữ
        /// </summary>
        public static string BuildMiAVInstallArgs(string logFile)
        {
            var sb = new StringBuilder();
            sb.Append("/VERYSILENT ");
            sb.Append("/SUPPRESSMSGBOXES ");
            sb.Append("/SP- ");
            sb.Append("/NORESTART ");
            sb.Append("/LANG=english ");
            sb.Append("/LOG=\"").Append(logFile).Append('"');
            return sb.ToString().Trim();
        }

        /// <summary>
        ///  Cài đặt lại MiAV sau khi quét KVRT.
        ///
        ///  Thứ tự thực hiện (theo install_script.iss):
        ///    1. Giải phóng file đang bị khóa: MiAV.exe, MiAV_WD.exe, MiAV_Protect.exe,
        ///       MiAV_Update.exe, SerDefense.exe, MiAV_Listdlls.exe (TaskKill trong [Files])
        ///    2. Xóa service cũ: UpdateServices, FMCAgent (được xóa trong [Run])
        ///    3. Chạy SetupMiAV.exe /VERYSILENT
        ///    4. Xác minh 4 service đã được tạo: MiAVWD, MiAVUpdate, MiAVProtect, Defense
        /// </summary>
        public static bool InstallMiAVSoftware(
            string setupPath,
            string logDir,
            Action<string, CleanLogKind> L)
        {
            try
            {
                // --- 1. Dừng tiến trình MiAV để file không bị khóa ---
                foreach (string proc in MiAVProcesses)
                    KillProcess(proc);
                KillProcess("MiAV_Listdlls");
                L("Đã dừng các tiến trình MiAV đang chạy.", CleanLogKind.Info);

                // --- 2. Dừng + xóa service cũ ---
                foreach (string svc in new[] { "UpdateServices", "FMCAgent" })
                {
                    if (!ServiceExists(svc)) continue;
                    RunSc($"stop {svc}");
                    RunSc($"delete {svc}");
                }
                // Cũng dừng 4 service chính (setup sẽ sc create lại)
                foreach (string svc in MiAVServices)
                {
                    if (!ServiceExists(svc)) continue;
                    RunSc($"stop {svc}");
                    RunSc($"delete {svc}");
                }
                L("Đã gỡ các service MiAV cũ (UpdateServices, FMCAgent, MiAVProtect, MiAVUpdate, MiAVWD, Defense).",
                    CleanLogKind.Info);

                // --- 3. Chạy trình cài đặt ---
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, "SetupMiAV_install.log");
                string args = BuildMiAVInstallArgs(logFile);
                L($"Chạy trình cài đặt: {Path.GetFileName(setupPath)} {args}", CleanLogKind.Info);

                var psi = new ProcessStartInfo(setupPath, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = new Process { StartInfo = psi };
                p.Start();
                L($"SetupMiAV đang chạy (PID {p.Id}). Quá trình cài đặt có thể mất 1–5 phút...", CleanLogKind.Step);

                // Inno Setup với /VERYSILENT có thể spawn tiếp trình con → chờ tiến trình cha kết thúc
                int waited = 0;
                while (!p.HasExited && waited < 30 * 60 * 1000)
                {
                    Thread.Sleep(1000);
                    waited += 1000;
                }
                if (!p.HasExited)
                {
                    L("Trình cài đặt chạy quá 30 phút — dừng chờ (có thể đang chờ tương tác).", CleanLogKind.Warn);
                    return false;
                }
                p.WaitForExit();
                L($"SetupMiAV kết thúc với mã thoát {p.ExitCode}.", CleanLogKind.Info);

                // --- 4. Xác minh 4 service đã được tạo ---
                Thread.Sleep(3000);
                int created = 0;
                foreach (string svc in MiAVServices)
                {
                    bool exists = ServiceExists(svc);
                    if (exists) created++;
                    L($"Service {svc}: {(exists ? "đã được tạo" : "KHÔNG tồn tại")}",
                        exists ? CleanLogKind.Success : CleanLogKind.Warn);
                }

                bool ok = created == MiAVServices.Length;
                if (ok)
                {
                    L("Cài đặt MiAV thành công — 4 service đã hoạt động.", CleanLogKind.Success);
                    L($"Thư mục cài đặt: {Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonDocuments), "AgentFMC")}",
                        CleanLogKind.Info);
                }
                else
                {
                    L($"Cài đặt MiAV không hoàn tất: mới tạo được {created}/{MiAVServices.Length} service. "
                      + $"Kiểm tra log: {logFile}", CleanLogKind.Error);
                }
                return ok;
            }
            catch (Exception ex)
            {
                L("Lỗi khi cài đặt MiAV: " + ex.Message, CleanLogKind.Error);
                return false;
            }
        }

        // ============================================================
        //  Thành phần: KVRT
        // ============================================================
        public static string? LocateKvrt()
        {
            string[] candidates =
            {
                Path.Combine(AppContext.BaseDirectory, "tools", "KVRT.exe"),
                Path.Combine(AppContext.BaseDirectory, "KVRT.exe"),
                Path.Combine(Path.GetTempPath(), "KVRT_Offline.exe")
            };
            foreach (string c in candidates)
                if (File.Exists(c)) return c;
            return null;
        }

        /// <summary>
        ///  Xây dựng dòng lệnh KVRT.
        ///
        ///  Tham số xác minh từ chuỗi nội bộ của KVRT2020 (bảng "KVRT2020 - Command line arguments help"):
        ///    -accepteula  : accept EULA, Privacy Policy and KSN Statement
        ///    -ksnstate off: tắt trạng thái KSN
        ///    -allvolumes  : add all volumes to scan  (quét tất cả ổ đĩa cục bộ)
        ///    -adinsilent  : run active disinfection in silent mode (tự khử nhiễm)
        ///    -silent      : chạy không giao diện
        ///    -freboot     : tự khởi động lại sau khi quét
        ///    -d &lt;dir&gt;     : path to quarantine and reports folder
        /// </summary>
        public static string BuildKvrtArgs(CleanOptions opt, string dataDir)
        {
            var sb = new StringBuilder();
            sb.Append("-accepteula ");
            sb.Append("-ksnstate off ");
            sb.Append("-allvolumes ");
            if (opt.KvrtSilent) sb.Append("-silent ");
            sb.Append("-adinsilent ");
            if (opt.RebootAfterKvrt) sb.Append("-freboot ");
            sb.Append("-d \"").Append(dataDir).Append('"');
            return sb.ToString().Trim();
        }

        private static bool RunKvrt(string exe, string args, Action<string, CleanLogKind> L)
        {
            try
            {
                var psi = new ProcessStartInfo(exe, args)
                {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                };
                using var p = new Process { StartInfo = psi };
                p.Start();
                L($"KVRT đang chạy (PID {p.Id}). Quét toàn bộ ổ đĩa có thể mất 30–120 phút.", CleanLogKind.Info);

                // Đọc output theo luồng để không bị nghẽn buffer
                var sbOut = new StringBuilder();
                p.OutputDataReceived += (s, e) => { if (e.Data != null) sbOut.AppendLine(e.Data); };
                p.ErrorDataReceived += (s, e) => { if (e.Data != null) sbOut.AppendLine(e.Data); };
                p.BeginOutputReadLine();
                p.BeginErrorReadLine();

                while (!p.HasExited)
                {
                    Thread.Sleep(1500);
                }
                p.WaitForExit();
                string outText = sbOut.ToString();
                if (outText.Length > 0)
                {
                    string logFile = Path.Combine(Path.GetTempPath(), "Danny_KVRT_" +
                        DateTime.Now.ToString("yyyyMMdd_HHmmss") + ".log");
                    try { File.WriteAllText(logFile, outText); L($"Nhật ký KVRT: {logFile}", CleanLogKind.Info); }
                    catch { }
                    foreach (string line in outText.Split('\n'))
                    {
                        string t = line.Trim();
                        if (t.Length == 0) continue;
                        if (t.Contains("INF") || t.Contains("Scan") || t.Contains("Disinfect") || t.Contains("found"))
                            L("KVRT: " + t, CleanLogKind.Info);
                    }
                }
                return p.ExitCode == 0;
            }
            catch (Exception ex)
            {
                L("Lỗi khi chạy KVRT: " + ex.Message, CleanLogKind.Error);
                return false;
            }
        }

        /// <summary>Khởi động lại máy sau khi quét.</summary>
        public static bool ScheduleReboot(int delaySeconds)
        {
            try
            {
                RunCommand("shutdown.exe", $"/r /t {delaySeconds} /c \"Danny ver4.0: khoi dong lai sau khi quet va khu nhiet\"");
                return true;
            }
            catch { return false; }
        }

        // ============================================================
        //  Tiện ích hệ thống
        // ============================================================
        private static bool ServiceExists(string name)
        {
            // Dung sc.exe query thay vi ServiceController (khong can them NuGet rieng)
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

        private static bool RunSc(string arguments)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo("sc.exe", arguments)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                if (p == null) return false;
                p.WaitForExit(15000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        private static bool KillProcess(string name)
        {
            try
            {
                var procs = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(name));
                if (procs.Length == 0) return true;
                foreach (var pr in procs) { try { pr.Kill(); pr.WaitForExit(5000); } catch { } }
                return true;
            }
            catch { return false; }
        }

        public static bool RunCommand(string file, string args)
        {
            try
            {
                using var p = Process.Start(new ProcessStartInfo(file, args)
                {
                    CreateNoWindow = true,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true
                });
                if (p == null) return false;
                p.WaitForExit(20000);
                return p.ExitCode == 0;
            }
            catch { return false; }
        }

        /// <summary>
        ///  Chạy một lệnh với quyền SYSTEM thông qua Scheduled Task tạm.
        ///  Dùng cho các tệp bị TrustedInstaller/System khóa (Amcache.hve, SRUDB.dat).
        /// </summary>
        private static bool RunAsSystem(string commandLine)
        {
            string taskName = "DannyTmp_" + Guid.NewGuid().ToString("N").Substring(0, 12);
            try
            {
                string time = DateTime.Now.AddMinutes(1).ToString("HH:mm");
                string wrapper = "cmd.exe /c " + commandLine;

                if (!RunCommand("schtasks.exe",
                        $"/create /tn {taskName} /tr \"{wrapper}\" /ru SYSTEM /sc once /st {time} /f"))
                    return false;

                bool started = RunCommand("schtasks.exe", $"/run /tn {taskName}");
                if (started)
                {
                    // Chờ tác vụ chạy xong (tối đa 60 giây)
                    for (int i = 0; i < 120; i++)
                    {
                        Thread.Sleep(500);
                        try
                        {
                            using var p = Process.Start(new ProcessStartInfo("schtasks.exe", $"/query /tn {taskName}")
                            {
                                CreateNoWindow = true, UseShellExecute = false,
                                RedirectStandardOutput = true
                            });
                            if (p != null)
                            {
                                string o = p.StandardOutput.ReadToEnd();
                                p.WaitForExit(5000);
                                if (o.Contains("Running") || o.Contains("Đang chạy")) continue;
                                break;
                            }
                        }
                        catch { break; }
                    }
                }
                RunCommand("schtasks.exe", $"/delete /tn {taskName} /f");
                return started;
            }
            catch { return false; }
        }

        private static bool DeletePath(string path)
        {
            try
            {
                if (Directory.Exists(path))
                {
                    // Bỏ thuộc tính read-only/hidden/system rồi xóa
                    try
                    {
                        foreach (string f in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                        {
                            try { File.SetAttributes(f, FileAttributes.Normal); } catch { }
                        }
                        foreach (string d in Directory.EnumerateDirectories(path, "*", SearchOption.AllDirectories))
                        {
                            try { File.SetAttributes(d, FileAttributes.Normal); } catch { }
                        }
                        File.SetAttributes(path, FileAttributes.Normal);
                    }
                    catch { }
                    Directory.Delete(path, true);
                }
                else if (File.Exists(path))
                {
                    try { File.SetAttributes(path, FileAttributes.Normal); } catch { }
                    File.Delete(path);
                }
                return !Directory.Exists(path) && !File.Exists(path);
            }
            catch { return false; }
        }

        private static bool DeleteRegistryKey(string subKey)
        {
            try
            {
                using var reg = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(subKey, true);
                if (reg == null) return true;
                reg.DeleteSubKeyTree(subKey, false);
                return true;
            }
            catch { return false; }
        }

        private static void CopyDirectory(string src, string dst)
        {
            Directory.CreateDirectory(dst);
            foreach (string dir in SafeEnumerateDirs(src, true))
            {
                string name = Path.GetFileName(dir);
                if (string.IsNullOrEmpty(name)) continue;
                CopyDirectory(dir, Path.Combine(dst, name));
            }
            foreach (string file in SafeEnumerateFiles(src, true))
            {
                string name = Path.GetFileName(file);
                try
                {
                    File.SetAttributes(file, FileAttributes.Normal);
                    File.Copy(file, Path.Combine(dst, name), true);
                }
                catch { }
            }
        }

        private static IEnumerable<string> EnumerateUserProfiles()
        {
            string baseDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string parent = Directory.GetParent(baseDir)?.FullName;
            if (parent == null || !Directory.Exists(parent)) yield break;
            foreach (string d in SafeEnumerateDirs(parent))
            {
                string appData = Path.Combine(d, "AppData", "Roaming");
                if (Directory.Exists(appData)) yield return d;
            }
        }

        private static IEnumerable<string> SafeEnumerateDirs(string root, bool all = false)
        {
            List<string> list = new List<string>();
            try
            {
                var opt = new EnumerationOptions
                {
                    RecurseSubdirectories = all,
                    IgnoreInaccessible = true,
                    AttributesToSkip = 0
                };
                list.AddRange(Directory.EnumerateDirectories(root, "*", opt));
            }
            catch { }
            return list;
        }

        private static IEnumerable<string> SafeEnumerateFiles(string root, bool all = false)
        {
            List<string> list = new List<string>();
            try
            {
                var opt = new EnumerationOptions
                {
                    RecurseSubdirectories = all,
                    IgnoreInaccessible = true,
                    AttributesToSkip = 0
                };
                list.AddRange(Directory.EnumerateFiles(root, "*", opt));
            }
            catch { }
            return list;
        }
    }

    // ==================================================================
    //  Lớp bọc tối thiểu cho SQLite (winsqlite3.dll có sẵn trên Win10+)
    // ==================================================================
    internal sealed class SqliteDb : IDisposable
    {
        private IntPtr _db = IntPtr.Zero;

        private const int SQLITE_OK = 0;
        private const int SQLITE_OPEN_READWRITE = 0x00000002;
        private const int SQLITE_OPEN_CREATE = 0x00000004;

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_open_v2")]
        private static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_exec")]
        private static extern int sqlite3_exec(IntPtr db, byte[] sql, IntPtr callback, IntPtr arg, out IntPtr err);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_close")]
        private static extern int sqlite3_close(IntPtr db);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_errmsg")]
        private static extern IntPtr sqlite3_errmsg(IntPtr db);

        public SqliteDb(string path) { _path = path; }
        private readonly string _path;

        public void Open()
        {
            if (_db != IntPtr.Zero) return;
            int rc = sqlite3_open_v2(Encoding.UTF8.GetBytes(_path + "\0"), out _db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, IntPtr.Zero);
            if (rc != SQLITE_OK)
            {
                string msg = _db == IntPtr.Zero ? "khong mo duoc" : Marshal.PtrToStringAnsi(sqlite3_errmsg(_db)) ?? "";
                throw new IOException("sqlite3_open_v2: " + msg);
            }
        }

        public void Execute(string sql)
        {
            if (_db == IntPtr.Zero) throw new InvalidOperationException("Database chưa mở.");
            int rc = sqlite3_exec(_db, Encoding.UTF8.GetBytes(sql + "\0"), IntPtr.Zero, IntPtr.Zero, out IntPtr err);
            if (rc != SQLITE_OK)
            {
                string msg = Marshal.PtrToStringAnsi(sqlite3_errmsg(_db)) ?? "lỗi SQL";
                throw new IOException("sqlite3_exec: " + msg);
            }
        }

        public int ScalarInt(string sql)
        {
            if (_db == IntPtr.Zero) return 0;
            // Dùng sqlite3_exec với callback không cần — đọc bằng cách exec và parse log hơi phức tạp,
            // nên dùng sqlite3_prepare/step cho trường hợp này.
            IntPtr stmt = IntPtr.Zero;
            int rc = sqlite3_prepare_v2(_db, Encoding.UTF8.GetBytes(sql + "\0"), -1, out stmt, IntPtr.Zero);
            if (rc != SQLITE_OK || stmt == IntPtr.Zero) return 0;
            try
            {
                rc = sqlite3_step(stmt);
                if (rc == 100) // SQLITE_ROW
                {
                    long v = sqlite3_column_int64(stmt, 0);
                    return (int)v;
                }
                return 0;
            }
            finally { sqlite3_finalize(stmt); }
        }

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_prepare_v2")]
        private static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nByte, out IntPtr stmt, IntPtr tail);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_step")]
        private static extern int sqlite3_step(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_finalize")]
        private static extern int sqlite3_finalize(IntPtr stmt);

        [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl,
            EntryPoint = "sqlite3_column_int64")]
        private static extern long sqlite3_column_int64(IntPtr stmt, int col);

        public void Dispose()
        {
            if (_db != IntPtr.Zero) { sqlite3_close(_db); _db = IntPtr.Zero; }
        }
    }
}
