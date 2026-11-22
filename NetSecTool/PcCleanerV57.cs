using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Threading;

namespace NetSecTool
{
    /// <summary>
    /// Kết quả kiểm tra chuẩn hóa cho từng hạng mục làm sạch.
    /// </summary>
    /// <remarks>
    /// <para>Thay thế hoàn toàn việc dùng bool/empty-catch. Mỗi hạng mục đều
    /// phải có kết quả rõ ràng + lý do nếu không hoàn thành.</para>
    /// </remarks>
    public enum CheckOutcome
    {
        /// <summary>Thực hiện thành công hoàn toàn.</summary>
        Pass,
        /// <summary>Hoàn thành nhưng có cảnh báo (ví dụ: còn sót ít file do đang mở).</summary>
        Warn,
        /// <summary>Thất bại — không đạt mục tiêu.</summary>
        Fail,
        /// <summary>Bỏ qua — không phù hợp với máy này (lý do xem <see cref="SkipReason"/>).</summary>
        Skipped,
        /// <summary>Lỗi ngoại lệ khi thực hiện.</summary>
        Error
    }

    /// <summary>Lý do bỏ qua một hạng mục.</summary>
    public enum SkipReason
    {
        None,
        /// <summary>Không có quyền Administrator.</summary>
        NotAdmin,
        /// <summary>Đường dẫn không tồn tại trên máy này.</summary>
        PathNotFound,
        /// <summary>Thành phần không được cài đặt (trình duyệt / dịch vụ).</summary>
        NotInstalled,
        /// <summary>Không có gì để xóa.</summary>
        NothingToDo,
        /// <summary>Tệp đang được tiến trình khác sử dụng.</summary>
        FileLocked,
        /// <summary>Khóa registry được bảo vệ, không lấy được quyền sở hữu.</summary>
        AccessDenied,
        /// <summary>Hệ điều hành không hỗ trợ thao tác này.</summary>
        UnsupportedOS,
        /// <summary>Người dùng hủy.</summary>
        Cancelled
    }

    /// <summary>Kết quả của một hạng mục kiểm tra/xóa.</summary>
    public sealed class CleanCheck
    {
        public string Name = "";
        public CheckOutcome Outcome = CheckOutcome.Pass;
        public SkipReason Reason = SkipReason.None;
        /// <summary>Chi tiết bổ sung (số lượng đã xóa, thông báo lỗi...).</summary>
        public string Detail = "";

        public static CleanCheck Pass(string name, string detail = "") =>
            new CleanCheck { Name = name, Outcome = CheckOutcome.Pass, Detail = detail };

        public static CleanCheck Warn(string name, string detail = "") =>
            new CleanCheck { Name = name, Outcome = CheckOutcome.Warn, Detail = detail };

        public static CleanCheck Fail(string name, string detail = "") =>
            new CleanCheck { Name = name, Outcome = CheckOutcome.Fail, Detail = detail };

        public static CleanCheck Error(string name, string detail = "") =>
            new CleanCheck { Name = name, Outcome = CheckOutcome.Error, Detail = detail };

        public static CleanCheck Skip(string name, SkipReason reason, string detail = "") =>
            new CleanCheck { Name = name, Outcome = CheckOutcome.Skipped, Reason = reason, Detail = detail };

        /// <summary>Biểu tượng hiển thị.</summary>
        public string Icon => Outcome switch
        {
            CheckOutcome.Pass => "✓",
            CheckOutcome.Warn => "!",
            CheckOutcome.Fail => "✗",
            CheckOutcome.Skipped => "–",
            _ => "E"
        };

        /// <summary>Nhãn kết quả.</summary>
        public string Label => Outcome switch
        {
            CheckOutcome.Pass => "ĐẠT",
            CheckOutcome.Warn => "CẢNH BÁO",
            CheckOutcome.Fail => "KHÔNG ĐẠT",
            CheckOutcome.Skipped => "BỎ QUA",
            _ => "LỖI"
        };
    }

    /// <summary>Kết quả của một bước trong quy trình 4 bước.</summary>
    public sealed class CleanStepResult
    {
        public int StepNumber;
        public string Title = "";
        public readonly List<CleanCheck> Checks = new();

        public int Pass => Checks.Count(c => c.Outcome == CheckOutcome.Pass);
        public int Warn => Checks.Count(c => c.Outcome == CheckOutcome.Warn);
        public int Fail => Checks.Count(c => c.Outcome == CheckOutcome.Fail);
        public int Error => Checks.Count(c => c.Outcome == CheckOutcome.Error);
        public int Skipped => Checks.Count(c => c.Outcome == CheckOutcome.Skipped);

        /// <summary>Bước này có đạt hay không (bỏ qua không tính là đạt).</summary>
        public bool IsOk => Fail == 0 && Error == 0;
    }

    /// <summary>Kết quả toàn bộ quy trình làm sạch 4 bước.</summary>
    public sealed class CleanV57Result
    {
        public bool IsAdmin;
        public bool Cancelled;
        public string StartedUtc = "";
        public string FinishedUtc = "";
        public double ElapsedSeconds;
        public readonly List<CleanStepResult> Steps = new();

        public int TotalPass => Steps.Sum(s => s.Pass);
        public int TotalWarn => Steps.Sum(s => s.Warn);
        public int TotalFail => Steps.Sum(s => s.Fail);
        public int TotalError => Steps.Sum(s => s.Error);
        public int TotalSkipped => Steps.Sum(s => s.Skipped);

        /// <summary>Tóm tắt một dòng.</summary>
        public string Summary =>
            $"Đạt {TotalPass} · Cảnh báo {TotalWarn} · Không đạt {TotalFail} · " +
            $"Lỗi {TotalError} · Bỏ qua {TotalSkipped}";
    }

    /// <summary>Tùy chọn quy trình làm sạch 4 bước (ver5.7).</summary>
    public sealed class CleanV57Options
    {
        /// <summary>Bước 1 — dọn file tạm.</summary>
        public bool Step1Temp = true;
        /// <summary>Bước 2 — dọn trình duyệt.</summary>
        public bool Step2Browsers = true;
        /// <summary>Bước 3 — xóa sâu lịch sử USB.</summary>
        public bool Step3UsbHistory = true;
        /// <summary>Bước 4 — xóa Windows Event Log.</summary>
        public bool Step4EventLog = true;
        /// <summary>Có chạy KVRT sau khi làm sạch không.</summary>
        public bool RunKvrtAfter = true;
        /// <summary>Thư mục lưu nhật ký làm sạch.</summary>
        public string ReportRoot = @"C:\_Danny_Cleanup";
    }

    /// <summary>
    /// Quy trình "LÀM SẠCH PC MỘT CHẠM" phiên bản 5.7 — 4 bước tuần tự.
    ///
    /// <para>Bước 1: Xóa file tạm (%TEMP%, C:\Windows\Temp, Prefetch, SoftwareDistribution\Download).</para>
    /// <para>Bước 2: Xóa lịch sử tất cả trình duyệt (Chrome, Edge, Cốc Cốc, Firefox).</para>
    /// <para>Bước 3: Xóa sâu lịch sử USB (nâng quyền SeBackup/SeRestorePrivilege,
    /// đổi quyền sở hữu registry, xóa USBSTOR/USB/MountedDevices/... ).</para>
    /// <para>Bước 4: Xóa toàn bộ Windows Event Log (wevtutil el → wevtutil cl).</para>
    ///
    /// <para>Yêu cầu quyền Administrator. Mọi hạng mục dùng chuẩn
    /// <see cref="CheckOutcome"/> — không còn khối catch rỗng.</para>
    /// </summary>
    public static class PcCleanerV57
    {
        // ============================================================
        //  PRIVILEGE ESCALATION
        // ============================================================
        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public uint Attributes;
        }

        private const uint SE_PRIVILEGE_ENABLED = 0x00000002;
        private const int SE_BACKUP_PRIVILEGE = 19;
        private const int SE_RESTORE_PRIVILEGE = 18;
        private const int SE_SECURITY_PRIVILEGE = 17;

        [DllImport("ntdll.dll")]
        private static extern int RtlAdjustPrivilege(
            int privilege, bool enable, bool currentThread, out LUID_AND_ATTRIBUTES previous);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool OpenProcessToken(
            IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool LookupPrivilegeValue(
            string? systemName, string? name, out LUID luid);

        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern bool AdjustTokenPrivileges(
            IntPtr tokenHandle, bool disableAll, ref LUID_AND_ATTRIBUTES newState,
            int bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);

        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;
        private const uint TOKEN_QUERY = 0x0008;

        /// <summary>Kiểm tra quyền Administrator hiện tại.</summary>
        public static bool IsAdministrator()
        {
            try
            {
                using var identity = WindowsIdentity.GetCurrent();
                var principal = new WindowsPrincipal(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Bật quyền đặc biệt qua <c>ntdll!RtlAdjustPrivilege</c>.
        /// Trả về false nếu không bật được (không ném exception).
        /// </summary>
        public static bool EnablePrivilege(int privilegeId, string displayName)
        {
            try
            {
                if (!OpenProcessToken(GetCurrentProcess(),
                        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, out IntPtr token))
                    return false;

                try
                {
                    if (!LookupPrivilegeValue(null, displayName, out LUID luid))
                        return false;

                    LUID_AND_ATTRIBUTES newState = new()
                    {
                        Luid = luid,
                        Attributes = SE_PRIVILEGE_ENABLED
                    };

                    bool ok = AdjustTokenPrivileges(token, false, ref newState,
                        0, IntPtr.Zero, IntPtr.Zero);

                    // AdjustTokenPrivileges luôn trả true — kiểm tra GetLastError
                    if (!ok) return false;
                    int err = Marshal.GetLastWin32Error();
                    return err == 0; // ERROR_SUCCESS
                }
                finally
                {
                    CloseHandle(token);
                }
            }
            catch
            {
                return false;
            }
        }

        /// <summary>Bật SeBackupPrivilege + SeRestorePrivilege + SeSecurityPrivilege.</summary>
        public static bool EnableBackupRestorePrivileges()
        {
            bool a = EnablePrivilege(SE_BACKUP_PRIVILEGE, "SeBackupPrivilege");
            bool b = EnablePrivilege(SE_RESTORE_PRIVILEGE, "SeRestorePrivilege");
            bool c = EnablePrivilege(SE_SECURITY_PRIVILEGE, "SeSecurityPrivilege");
            return a && b && c;
        }

        // ============================================================
        //  QUY TRÌNH CHÍNH
        // ============================================================

        /// <summary>
        /// Chạy quy trình làm sạch 4 bước.
        /// </summary>
        public static CleanV57Result Run(
            CleanV57Options opt,
            Action<string, CleanLogKind>? log = null,
            Action<int, int>? progress = null,
            CancellationToken ct = default)
        {
            var res = new CleanV57Result();
            Action<string, CleanLogKind> L = (m, k) => log?.Invoke(m, k);
            Action<int, int> P = (c, t) => progress?.Invoke(c, t);

            var sw = Stopwatch.StartNew();
            res.StartedUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
            res.IsAdmin = IsAdministrator();

            L("=== LÀM SẠCH PC MỘT CHẠM — QUY TRÌNH 4 BƯỚC (ver5.7) ===", CleanLogKind.Heading);

            if (!res.IsAdmin)
            {
                L("✗ Không có quyền Administrator. Một số hạng mục (đặc biệt là lịch sử USB và Event Log) "
                  + "sẽ không thực hiện được.", CleanLogKind.Error);
                L("  → Hãy chạy lại phần mềm bằng cách nhấp chuột phải → \"Chạy với tư cách quản trị viên\".",
                  CleanLogKind.Warn);
            }
            else
            {
                L("✓ Đang chạy với quyền Administrator.", CleanLogKind.Success);
            }

            // Danh sách bước
            var stepDefs = new List<(bool enabled, string title, Func<CleanStepResult, List<CleanCheck>> fn)>();
            if (opt.Step1Temp)
                stepDefs.Add((true, "BƯỚC 1: Dọn file tạm (Temp / Prefetch / Windows Update cache)", Step1TempFiles));
            if (opt.Step2Browsers)
                stepDefs.Add((true, "BƯỚC 2: Dọn lịch sử tất cả trình duyệt", Step2Browsers));
            if (opt.Step3UsbHistory)
                stepDefs.Add((true, "BƯỚC 3: Xóa sâu lịch sử USB", Step3UsbHistory));
            if (opt.Step4EventLog)
                stepDefs.Add((true, "BƯỚC 4: Xóa Windows Event Log", Step4EventLog));

            if (stepDefs.Count == 0)
            {
                L("Không có bước nào được chọn.", CleanLogKind.Warn);
                res.FinishedUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
                return res;
            }

            int stepNo = 0;
            foreach (var def in stepDefs)
            {
                if (ct.IsCancellationRequested)
                {
                    res.Cancelled = true;
                    L("Đã hủy theo yêu cầu.", CleanLogKind.Warn);
                    break;
                }

                stepNo++;
                L("", CleanLogKind.Info);
                L($"BƯỚC {stepNo}/{stepDefs.Count}: {def.title}", CleanLogKind.Heading);

                var step = new CleanStepResult { StepNumber = stepNo, Title = def.title };
                P(stepNo - 1, stepDefs.Count);

                try
                {
                    step.Checks.AddRange(def.fn(step));
                }
                catch (Exception ex)
                {
                    step.Checks.Add(CleanCheck.Error(def.title, ex.Message));
                }

                res.Steps.Add(step);

                foreach (CleanCheck c in step.Checks)
                {
                    string prefix = c.Outcome switch
                    {
                        CheckOutcome.Pass => "  ✓ ",
                        CheckOutcome.Warn => "  ! ",
                        CheckOutcome.Fail => "  ✗ ",
                        CheckOutcome.Skipped => "  – ",
                        _ => "  E "
                    };
                    string reason = c.Outcome == CheckOutcome.Skipped && c.Reason != SkipReason.None
                        ? $" ({DescribeReason(c.Reason)})" : "";
                    L(prefix + c.Name + reason + (c.Detail.Length > 0 ? " — " + c.Detail : ""),
                        c.Outcome switch
                        {
                            CheckOutcome.Pass => CleanLogKind.Success,
                            CheckOutcome.Warn => CleanLogKind.Warn,
                            CheckOutcome.Fail => CleanLogKind.Error,
                            CheckOutcome.Skipped => CleanLogKind.Info,
                            _ => CleanLogKind.Error
                        });
                }
            }

            // --- KVRT ---
            if (opt.RunKvrtAfter && !res.Cancelled)
            {
                L("", CleanLogKind.Info);
                L("BƯỚC BỔ SUNG: Quét virus ngoại tuyến bằng Kaspersky KVRT", CleanLogKind.Heading);
                CleanCheck kvrt = RunKvrt();
                var kvrtStep = new CleanStepResult { StepNumber = stepNo + 1, Title = "Quét KVRT" };
                kvrtStep.Checks.Add(kvrt);
                res.Steps.Add(kvrtStep);
                L((kvrt.Outcome == CheckOutcome.Pass ? "  ✓ " : "  ! ") + kvrt.Name +
                  (kvrt.Detail.Length > 0 ? " — " + kvrt.Detail : ""),
                  kvrt.Outcome == CheckOutcome.Pass ? CleanLogKind.Success : CleanLogKind.Warn);
            }

            sw.Stop();
            res.ElapsedSeconds = sw.Elapsed.TotalSeconds;
            res.FinishedUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
            P(stepDefs.Count, stepDefs.Count);

            L("", CleanLogKind.Info);
            L($"=== HOÀN TẤT trong {res.ElapsedSeconds:F1}s — {res.Summary} ===", CleanLogKind.Heading);

            // Ghi báo cáo
            try
            {
                string reportDir = Path.Combine(opt.ReportRoot,
                    "CleanV57_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(reportDir);
                WriteReport(reportDir, res);
                L("Báo cáo làm sạch: " + reportDir, CleanLogKind.Info);
            }
            catch (Exception ex)
            {
                L("Không ghi được báo cáo: " + ex.Message, CleanLogKind.Warn);
            }

            return res;
        }

        /// <summary>Mô tả lý do bỏ qua (tiếng Việt).</summary>
        public static string DescribeReason(SkipReason r) => r switch
        {
            SkipReason.NotAdmin => "cần quyền Administrator",
            SkipReason.PathNotFound => "không có trên máy này",
            SkipReason.NotInstalled => "chưa cài đặt",
            SkipReason.NothingToDo => "không có gì để xóa",
            SkipReason.FileLocked => "tệp đang được sử dụng",
            SkipReason.AccessDenied => "không lấy được quyền truy cập",
            SkipReason.UnsupportedOS => "hệ điều hành không hỗ trợ",
            SkipReason.Cancelled => "đã hủy",
            _ => ""
        };

        // ============================================================
        //  BƯỚC 1: FILE TẠM
        // ============================================================
        private static List<CleanCheck> Step1TempFiles(CleanStepResult step)
        {
            var results = new List<CleanCheck>();

            var targets = new List<(string Label, string Path)>
            {
                ("%TEMP% người dùng", Path.GetTempPath()),
                ("C:\\Windows\\Temp", @"C:\Windows\Temp"),
                ("C:\\Windows\\Prefetch", @"C:\Windows\Prefetch"),
                ("C:\\Windows\\SoftwareDistribution\\Download", @"C:\Windows\SoftwareDistribution\Download")
            };

            foreach (var (label, path) in targets)
            {
                if (!Directory.Exists(path))
                {
                    results.Add(CleanCheck.Skip(label, SkipReason.PathNotFound, path));
                    continue;
                }

                int deleted = 0;
                int failed = 0;
                long freed = 0;
                var errors = new List<string>();

                try
                {
                    foreach (string file in Directory.EnumerateFiles(path, "*", SearchOption.AllDirectories))
                    {
                        try
                        {
                            var fi = new FileInfo(file);
                            long len = fi.Length;
                            fi.Attributes = FileAttributes.Normal;
                            fi.Delete();
                            deleted++;
                            freed += len;
                        }
                        catch (Exception ex)
                        {
                            failed++;
                            if (errors.Count < 3) errors.Add(Path.GetFileName(file) + ": " + ex.Message);
                        }
                    }
                }
                catch (Exception ex)
                {
                    results.Add(CleanCheck.Error(label, ex.Message));
                    continue;
                }

                string detail = $"đã xóa {deleted} tệp, giải phóng {freed / 1024.0 / 1024:F1} MB";
                if (failed > 0)
                {
                    detail += $"; {failed} tệp bỏ qua ({string.Join(" | ", errors)})";
                    results.Add(CleanCheck.Warn(label, detail));
                }
                else
                {
                    results.Add(CleanCheck.Pass(label, detail));
                }
            }

            return results;
        }

        // ============================================================
        //  BƯỚC 2: TRÌNH DUYỆT
        // ============================================================
        private static List<CleanCheck> Step2Browsers(CleanStepResult step)
        {
            var results = new List<CleanCheck>();

            // Tắt các tiến trình trình duyệt trước khi xóa
            string[] browsers = { "chrome", "msedge", "browser", "firefox", "brave", "vivaldi", "opera" };
            var killed = new List<string>();
            foreach (string b in browsers)
            {
                try
                {
                    var procs = Process.GetProcessesByName(b);
                    foreach (var p in procs)
                    {
                        try { p.Kill(); killed.Add(b); } catch { }
                        finally { p.Dispose(); }
                    }
                }
                catch { }
            }
            if (killed.Count > 0)
            {
                System.Threading.Thread.Sleep(800);
                results.Add(CleanCheck.Pass("Đóng trình duyệt đang chạy",
                    "đã đóng: " + string.Join(", ", killed.Distinct())));
            }

            // Định nghĩa các trình duyệt + file lịch sử tương ứng
            var profiles = new List<(string Browser, string Label, Func<List<string>> Roots)>();

            void AddProfile(string browser, string label, params string[] relPaths)
            {
                string[] captured = relPaths;
                profiles.Add((browser, label, () => ExpandProfilePaths(captured)));
            }

            AddProfile("Chrome", "Google Chrome",
                @"AppData\Local\Google\Chrome\User Data\Default\History",
                @"AppData\Local\Google\Chrome\User Data\Default\History-journal",
                @"AppData\Local\Google\Chrome\User Data\Default\Cookies",
                @"AppData\Local\Google\Chrome\User Data\Default\Login Data",
                @"AppData\Local\Google\Chrome\User Data\Default\Top Sites",
                @"AppData\Local\Google\Chrome\User Data\Default\Web Data",
                @"AppData\Local\Google\Chrome\User Data\Default\Network\Cookies");

            AddProfile("msedge", "Microsoft Edge",
                @"AppData\Local\Microsoft\Edge\User Data\Default\History",
                @"AppData\Local\Microsoft\Edge\User Data\Default\History-journal",
                @"AppData\Local\Microsoft\Edge\User Data\Default\Cookies",
                @"AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies",
                @"AppData\Local\Microsoft\Edge\User Data\Default\Login Data");

            AddProfile("browser", "Cốc Cốc",
                @"AppData\Local\Browser\User Data\Default\History",
                @"AppData\Local\Browser\User Data\Default\History-journal",
                @"AppData\Local\Browser\User Data\Default\Cookies",
                @"AppData\Local\Browser\User Data\Default\Network\Cookies",
                @"AppData\Local\Browser\User Data\Default\Login Data");

            AddProfile("firefox", "Mozilla Firefox",
                @"AppData\Roaming\Mozilla\Firefox\Profiles\places.sqlite",
                @"AppData\Roaming\Mozilla\Firefox\Profiles\places.sqlite-wal",
                @"AppData\Roaming\Mozilla\Firefox\Profiles\cookies.sqlite",
                @"AppData\Roaming\Mozilla\Firefox\Profiles\formhistory.sqlite",
                @"AppData\Roaming\Mozilla\Firefox\Profiles\downloads.sqlite");

            // Gom theo trình duyệt
            foreach (var group in profiles.GroupBy(p => p.Label))
            {
                var browserName = group.First().Browser;
                var allPaths = group.SelectMany(g => g.Roots()).Distinct().ToList();

                if (allPaths.Count == 0)
                {
                    results.Add(CleanCheck.Skip(group.Key, SkipReason.NotInstalled, "không tìm thấy profile"));
                    continue;
                }

                int deleted = 0, failed = 0;
                long freed = 0;
                var errors = new List<string>();

                foreach (string p in allPaths)
                {
                    if (!File.Exists(p)) continue;
                    try
                    {
                        var fi = new FileInfo(p);
                        long len = fi.Length;
                        fi.Attributes = FileAttributes.Normal;
                        fi.Delete();
                        deleted++;
                        freed += len;
                    }
                    catch (Exception ex)
                    {
                        failed++;
                        if (errors.Count < 3)
                            errors.Add(Path.GetFileName(p) + ": " + ex.Message);
                    }
                }

                if (deleted == 0 && failed == 0)
                {
                    results.Add(CleanCheck.Skip(group.Key, SkipReason.NothingToDo, "lịch sử đã trống"));
                }
                else if (failed > 0)
                {
                    results.Add(CleanCheck.Warn(group.Key,
                        $"xóa {deleted}, bỏ qua {failed} ({string.Join(" | ", errors)})"));
                }
                else
                {
                    results.Add(CleanCheck.Pass(group.Key,
                        $"xóa {deleted} tệp lịch sử, giải phóng {freed / 1024.0:F0} KB"));
                }
            }

            return results;
        }

        /// <summary>Mở rộng các đường dẫn tương đối theo mọi profile người dùng.</summary>
        private static List<string> ExpandProfilePaths(string[] relPaths)
        {
            var outp = new List<string>();
            foreach (string baseProfile in EnumerateUserProfiles())
            {
                foreach (string rel in relPaths)
                {
                    string p = Path.Combine(baseProfile, rel);
                    if (File.Exists(p)) outp.Add(p);
                    else
                    {
                        // Thay "Default" bằng tên profile thực tế
                        if (rel.Contains(@"\Default\"))
                        {
                            string parent = rel.Substring(0, rel.IndexOf(@"\Default\", StringComparison.OrdinalIgnoreCase));
                            string tail = rel.Substring(rel.IndexOf(@"\Default\", StringComparison.OrdinalIgnoreCase) + 9);
                            string parentDir = Path.Combine(baseProfile, parent);
                            if (Directory.Exists(parentDir))
                            {
                                try
                                {
                                    foreach (string profDir in Directory.EnumerateDirectories(parentDir))
                                    {
                                        string cand = Path.Combine(profDir, tail);
                                        if (File.Exists(cand)) outp.Add(cand);
                                    }
                                }
                                catch { }
                            }
                        }
                    }
                }
            }
            return outp;
        }

        /// <summary>Liệt kê thư mục profile của mọi user trên máy.</summary>
        private static IEnumerable<string> EnumerateUserProfiles()
        {
            var list = new List<string>();
            try
            {
                string root = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
                string parent = Path.GetDirectoryName(root.TrimEnd('\\')) ?? root;
                foreach (string dir in Directory.EnumerateDirectories(parent))
                {
                    string name = Path.GetFileName(dir);
                    if (name.StartsWith(".") || name.StartsWith("Public")
                        || name.StartsWith("Default") || name.StartsWith("All Users"))
                        continue;
                    list.Add(dir);
                }
            }
            catch { }
            list.Add(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile));
            return list.Distinct();
        }

        // ============================================================
        //  BƯỚC 3: LỊCH SỬ USB (SIÊU SÂU)
        // ============================================================
        private static List<CleanCheck> Step3UsbHistory(CleanStepResult step)
        {
            var results = new List<CleanCheck>();

            if (!IsAdministrator())
            {
                results.Add(CleanCheck.Skip("Toàn bộ bước xóa lịch sử USB",
                    SkipReason.NotAdmin, "cần chạy với quyền Administrator"));
                return results;
            }

            // 3.1 — Nâng quyền SeBackupPrivilege / SeRestorePrivilege
            bool privOk = EnableBackupRestorePrivileges();
            results.Add(privOk
                ? CleanCheck.Pass("Nâng quyền SeBackupPrivilege / SeRestorePrivilege / SeSecurityPrivilege")
                : CleanCheck.Warn("Nâng quyền SeBackupPrivilege / SeRestorePrivilege / SeSecurityPrivilege",
                    "không bật được toàn bộ — vẫn có thể xóa được phần lớn khóa"));

            // 3.2 — Xóa các khóa registry USB
            var regTargets = new List<(string Label, string Path, bool Recursive)>
            {
                ("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*", @"SYSTEM\CurrentControlSet\Enum\USBSTOR", true),
                ("HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USB\\*", @"SYSTEM\CurrentControlSet\Enum\USB", true),
                ("HKLM\\SOFTWARE\\Microsoft\\Windows Portable Devices\\Devices\\*", @"SOFTWARE\Microsoft\Windows Portable Devices\Devices", true),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2\\CPC", @"Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2", false)
            };

            foreach (var t in regTargets)
            {
                results.Add(DeleteRegistryKey(t.Path, t.Recursive, t.Label));
            }

            // 3.3 — MountedDevices (loại trừ tuyệt đối \DosDevices\C:)
            results.Add(CleanMountedDevices());

            // 3.4 — EMDMgmt
            results.Add(DeleteRegistryKey(@"SYSTEM\CurrentControlSet\Enum\EMDMgmt", true,
                "HKLM\\SYSTEM\\CurrentControlSet\\Enum\\EMDMgmt"));

            // 3.5 — DeviceClasses\{...}
            results.Add(CleanDeviceClasses());

            // 3.6 — setupapi logs
            results.Add(DeleteSetupApiLogs());

            return results;
        }

        /// <summary>Xóa một khóa registry (có nâng quyền sở hữu nếu cần).</summary>
        private static CleanCheck DeleteRegistryKey(string subKey, bool recursive, string label)
        {
            try
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine,
                    Microsoft.Win32.RegistryView.Registry64);

                using var key = baseKey.OpenSubKey(subKey, true);
                if (key == null)
                    return CleanCheck.Skip(label, SkipReason.PathNotFound);

                // Lấy quyền sở hữu + toàn quyền trước khi xóa
                bool tookOwnership = TryTakeOwnershipAndGrant(key);

                // Xóa khóa con bên dưới (recursive=false vì khóa con đã xử lý riêng ở trên)
                key.DeleteSubKeyTree(subKey, false);
                return CleanCheck.Pass(label, tookOwnership ? "đã đổi quyền sở hữu và xóa" : "đã xóa");
            }
            catch (UnauthorizedAccessException)
            {
                return CleanCheck.Fail(label, "không có quyền — cần chạy với quyền Administrator");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error(label, ex.Message);
            }
        }

        /// <summary>Đổi quyền sở hữu khóa registry và cấp quyền cho user hiện tại.</summary>
        private static bool TryTakeOwnershipAndGrant(Microsoft.Win32.RegistryKey key)
        {
            try
            {
                var sec = key.GetAccessControl(AccessControlSections.All);
                var identity = WindowsIdentity.GetCurrent().User;
                if (identity == null) return false;

                // Chủ sở hữu = SYSTEM (để có toàn quyền thao tác)
                var systemSid = new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null);
                sec.SetOwner(systemSid);

                // Cấp toàn quyền cho user hiện tại
                var rule = new RegistryAccessRule(identity,
                    RegistryRights.FullControl,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow);
                sec.AddAccessRule(rule);

                key.SetAccessControl(sec);
                return true;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Xóa các mục USB trong MountedDevices, TUYỆT ĐỐI giữ nguyên \DosDevices\C:.
        /// </summary>
        private static CleanCheck CleanMountedDevices()
        {
            const string label = "HKLM\\SYSTEM\\MountedDevices (giữ nguyên \\DosDevices\\C:)";
            try
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine,
                    Microsoft.Win32.RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(@"SYSTEM\MountedDevices", true);
                if (key == null) return CleanCheck.Skip(label, SkipReason.PathNotFound);

                var toDelete = new List<string>();
                foreach (string name in key.GetValueNames())
                {
                    // LUOI BAO VE: \DosDevices\C: (phan he thong) va \DosDevices\C:\...
                    if (IsProtectedMountedDevice(name)) continue;
                    toDelete.Add(name);
                }

                if (toDelete.Count == 0)
                    return CleanCheck.Pass(label, "không có mục USB nào để xóa (đã bảo vệ phân vùng hệ thống)");

                int deleted = 0;
                var errors = new List<string>();
                foreach (string name in toDelete)
                {
                    try { key.DeleteValue(name, false); deleted++; }
                    catch (Exception ex)
                    {
                        if (errors.Count < 3) errors.Add(name + ": " + ex.Message);
                    }
                }

                if (deleted < toDelete.Count)
                    return CleanCheck.Warn(label,
                        $"xóa {deleted}/{toDelete.Count} mục ({string.Join(" | ", errors)})");
                return CleanCheck.Pass(label, $"xóa {deleted} mục USB, giữ nguyên \\DosDevices\\C:");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error(label, ex.Message);
            }
        }

        /// <summary>Kiểm tra một mục MountedDevices có cần bảo vệ hay không.</summary>
        private static bool IsProtectedMountedDevice(string name)
        {
            if (string.IsNullOrEmpty(name)) return true;
            // Bảo vệ mọi mục liên quan tới phân vùng hệ thống
            if (name.Equals(@"\DosDevices\C:", StringComparison.OrdinalIgnoreCase)) return true;
            if (name.StartsWith(@"\DosDevices\C:\", StringComparison.OrdinalIgnoreCase)) return true;
            // Cũng bảo vệ \DosDevices\... (partition không ký tự) để an toàn
            if (name.StartsWith(@"\DosDevices\", StringComparison.OrdinalIgnoreCase)
                && name.Count(ch => ch == ':') == 0) return true;
            return false;
        }

        /// <summary>Xóa các lớp thiết bị USB khỏi DeviceClasses (giữ lớp disk).</summary>
        private static CleanCheck CleanDeviceClasses()
        {
            const string label = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceClasses\\{...}";
            try
            {
                using var baseKey = Microsoft.Win32.RegistryKey.OpenBaseKey(
                    Microsoft.Win32.RegistryHive.LocalMachine,
                    Microsoft.Win32.RegistryView.Registry64);
                using var key = baseKey.OpenSubKey(
                    @"SYSTEM\CurrentControlSet\Control\DeviceClasses", true);
                if (key == null) return CleanCheck.Skip(label, SkipReason.PathNotFound);

                // Chỉ xóa lớp có liên quan USB/STOR — bỏ qua lớp disk/volume để máy không mất ổ
                string[] usbHints = { "USB", "STOR", "SWD", "VID_", "PID_" };
                int deleted = 0;
                var errors = new List<string>();

                foreach (string sub in key.GetSubKeyNames())
                {
                    if (!sub.StartsWith("{", StringComparison.Ordinal)) continue;
                    bool isUsb = usbHints.Any(h => sub.IndexOf(h, StringComparison.OrdinalIgnoreCase) >= 0);
                    if (!isUsb) continue;

                    try
                    {
                        using var child = key.OpenSubKey(sub, true);
                        child?.DeleteSubKeyTree(sub, false);
                        deleted++;
                    }
                    catch (Exception ex)
                    {
                        if (errors.Count < 3) errors.Add(sub + ": " + ex.Message);
                    }
                }

                if (deleted == 0)
                    return CleanCheck.Pass(label, "không có lớp thiết bị USB nào");
                if (errors.Count > 0)
                    return CleanCheck.Warn(label, $"xóa {deleted} lớp, một số lỗi ({string.Join(" | ", errors)})");
                return CleanCheck.Pass(label, $"xóa {deleted} lớp thiết bị USB");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error(label, ex.Message);
            }
        }

        /// <summary>Xóa nhật ký cài đặt thiết bị setupapi.*.log.</summary>
        private static CleanCheck DeleteSetupApiLogs()
        {
            const string label = "C:\\Windows\\inf\\setupapi.*.log";
            try
            {
                string infDir = @"C:\Windows\inf";
                if (!Directory.Exists(infDir))
                    return CleanCheck.Skip(label, SkipReason.PathNotFound);

                var logs = Directory.GetFiles(infDir, "setupapi*.log");
                if (logs.Length == 0)
                    return CleanCheck.Skip(label, SkipReason.NothingToDo);

                int deleted = 0;
                var errors = new List<string>();
                foreach (string f in logs)
                {
                    try
                    {
                        var fi = new FileInfo(f);
                        fi.Attributes = FileAttributes.Normal;
                        fi.Delete();
                        deleted++;
                    }
                    catch (Exception ex)
                    {
                        if (errors.Count < 3) errors.Add(Path.GetFileName(f) + ": " + ex.Message);
                    }
                }

                if (deleted == 0)
                    return CleanCheck.Fail(label, string.Join(" | ", errors));
                if (errors.Count > 0)
                    return CleanCheck.Warn(label, $"xóa {deleted}/{logs.Length} tệp");
                return CleanCheck.Pass(label, $"xóa {deleted} tệp nhật ký cài đặt thiết bị");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error(label, ex.Message);
            }
        }

        // ============================================================
        //  BƯỚC 4: EVENT LOG
        // ============================================================
        private static List<CleanCheck> Step4EventLog(CleanStepResult step)
        {
            var results = new List<CleanCheck>();

            if (!IsAdministrator())
            {
                results.Add(CleanCheck.Skip("Xóa Windows Event Log",
                    SkipReason.NotAdmin, "cần chạy với quyền Administrator"));
                return results;
            }

            try
            {
                // 4.1 — Liệt kê kênh log
                var (ok, listOut, listErr) = RunCapture("wevtutil.exe", "el");
                if (!ok || string.IsNullOrWhiteSpace(listOut))
                {
                    results.Add(CleanCheck.Error("Liệt kê kênh Event Log (wevtutil el)", listErr));
                    return results;
                }

                var channels = listOut.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)
                                     .Select(s => s.Trim()).Where(s => s.Length > 0).ToList();

                results.Add(CleanCheck.Pass("Liệt kê kênh Event Log (wevtutil el)",
                    $"tìm thấy {channels.Count} kênh"));

                // 4.2 — Xóa từng kênh
                int cleared = 0;
                int failed = 0;
                var errors = new List<string>();

                foreach (string ch in channels)
                {
                    var (cOk, _, cErr) = RunCapture("wevtutil.exe", "cl \"" + ch + "\"");
                    if (cOk) cleared++;
                    else
                    {
                        failed++;
                        if (errors.Count < 5) errors.Add(ch + ": " + cErr.Trim());
                    }
                }

                if (failed == 0)
                    results.Add(CleanCheck.Pass("Xóa nội dung tất cả kênh Event Log (wevtutil cl)",
                        $"đã xóa {cleared}/{channels.Count} kênh"));
                else if (cleared > 0)
                    results.Add(CleanCheck.Warn("Xóa nội dung tất cả kênh Event Log (wevtutil cl)",
                        $"xóa {cleared}/{channels.Count} kênh; lỗi: {string.Join(" | ", errors)}"));
                else
                    results.Add(CleanCheck.Fail("Xóa nội dung tất cả kênh Event Log (wevtutil cl)",
                        string.Join(" | ", errors)));

                // 4.3 — Xóa file .evtx trực tiếp (bổ sung)
                results.Add(DeleteEvtxFiles());
            }
            catch (Exception ex)
            {
                results.Add(CleanCheck.Error("Bước 4 — Xóa Event Log", ex.Message));
            }

            return results;
        }

        /// <summary>Xóa trực tiếp các tệp .evtx trong thư mục log.</summary>
        private static CleanCheck DeleteEvtxFiles()
        {
            const string label = "Xóa tệp .evtx trong C:\\Windows\\System32\\winevt\\Logs";
            try
            {
                string logDir = @"C:\Windows\System32\winevt\Logs";
                if (!Directory.Exists(logDir))
                    return CleanCheck.Skip(label, SkipReason.PathNotFound);

                var files = Directory.GetFiles(logDir, "*.evtx");
                if (files.Length == 0)
                    return CleanCheck.Skip(label, SkipReason.NothingToDo);

                int deleted = 0;
                var errors = new List<string>();
                foreach (string f in files)
                {
                    try
                    {
                        var fi = new FileInfo(f);
                        fi.Attributes = FileAttributes.Normal;
                        fi.Delete();
                        deleted++;
                    }
                    catch (Exception ex)
                    {
                        if (errors.Count < 3) errors.Add(Path.GetFileName(f) + ": " + ex.Message);
                    }
                }

                if (deleted == 0)
                    return CleanCheck.Warn(label, "không xóa được tệp nào (đang được hệ thống giữ) — " +
                                              string.Join(" | ", errors));
                if (errors.Count > 0)
                    return CleanCheck.Warn(label, $"xóa {deleted}/{files.Length} tệp");
                return CleanCheck.Pass(label, $"xóa {deleted} tệp .evtx");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error(label, ex.Message);
            }
        }

        // ============================================================
        //  KVRT
        // ============================================================
        private static CleanCheck RunKvrt()
        {
            string kvrtPath = Path.Combine(AppContext.BaseDirectory, "tools", "KVRT.exe");
            if (!File.Exists(kvrtPath))
                kvrtPath = Path.Combine(Path.GetTempPath(), "KVRT_Offline.exe");

            if (!File.Exists(kvrtPath))
                return CleanCheck.Skip("Chạy Kaspersky KVRT quét ngoại tuyến",
                    SkipReason.PathNotFound, "không có tools\\KVRT.exe");

            try
            {
                var psi = new ProcessStartInfo(kvrtPath)
                {
                    UseShellExecute = true,
                    Arguments = "/ALL /SILENT"
                };
                Process.Start(psi);
                return CleanCheck.Pass("Chạy Kaspersky KVRT quét ngoại tuyến",
                    "đã khởi chạy ở chế độ nền");
            }
            catch (Exception ex)
            {
                return CleanCheck.Error("Chạy Kaspersky KVRT quét ngoại tuyến", ex.Message);
            }
        }

        // ============================================================
        //  TIEN ICH
        // ============================================================
        /// <summary>Chạy lệnh và thu stdout/stderr.</summary>
        private static (bool ok, string stdout, string stderr) RunCapture(string file, string args)
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
                if (p == null) return (false, "", "không khởi chạy được");
                string o = p.StandardOutput.ReadToEnd();
                string e = p.StandardError.ReadToEnd();
                p.WaitForExit(30_000);
                return (p.ExitCode == 0, o, e);
            }
            catch (Exception ex)
            {
                return (false, "", ex.Message);
            }
        }

        /// <summary>Ghi báo cáo kết quả làm sạch ra thư mục.</summary>
        private static void WriteReport(string dir, CleanV57Result res)
        {
            var sb = new StringBuilder();
            sb.AppendLine("BÁO CÁO LÀM SẠCH PC MỘT CHẠM — Danny ver5.7");
            sb.AppendLine("==================================================");
            sb.AppendLine($"Bắt đầu (UTC)   : {res.StartedUtc}");
            sb.AppendLine($"Kết thúc (UTC)  : {res.FinishedUtc}");
            sb.AppendLine($"Thời gian       : {res.ElapsedSeconds:F1} giây");
            sb.AppendLine($"Quyền Admin     : {(res.IsAdmin ? "CÓ" : "KHÔNG")}");
            sb.AppendLine($"Tổng kết quả    : {res.Summary}");
            sb.AppendLine();

            foreach (CleanStepResult step in res.Steps)
            {
                sb.AppendLine($"--- BƯỚC {step.StepNumber}: {step.Title} ---");
                foreach (CleanCheck c in step.Checks)
                {
                    string reason = c.Outcome == CheckOutcome.Skipped && c.Reason != SkipReason.None
                        ? $" [{DescribeReason(c.Reason)}]" : "";
                    sb.AppendLine($"  {c.Icon} {c.Label,-8} | {c.Name}{reason}" +
                                 (c.Detail.Length > 0 ? " — " + c.Detail : ""));
                }
                sb.AppendLine();
            }

            File.WriteAllText(Path.Combine(dir, "Bao-cao-lam-sach.txt"), sb.ToString(), Encoding.UTF8);
        }
    }
}
