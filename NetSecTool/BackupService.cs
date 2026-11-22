using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecTool;

/// <summary>Một ổ đĩa vật lý quét qua WMI (3 tầng).</summary>
public sealed class PhysicalDisk
{
    public string DeviceId = "";
    public string Model = "";
    public string Serial = "";
    public string InterfaceType = "";
    public string MediaType = "";
    /// <summary>Dung lượng vật lý (bytes).</summary>
    public long SizeBytes;
    public string SizeText = "";
    public bool IsRemovable;
    public bool IsExternal;
    public readonly List<string> Partitions = new();
    public readonly List<string> DriveLetters = new();
}

/// <summary>Kết quả quét ổ đĩa.</summary>
public sealed class DiskScanResult
{
    public readonly List<PhysicalDisk> Disks = new();
    public readonly List<string> Errors = new();
    /// <summary>Ổ di động gắn ngoài đủ điều kiện làm nơi sao lưu (>= 1 TB).</summary>
    public readonly List<PhysicalDisk> ValidExternalTargets = new();
    public readonly List<string> Rejected = new();
}

/// <summary>Kết quả một lần sao lưu.</summary>
public sealed class BackupResult
{
    public bool Success;
    public bool Cancelled;
    public long BytesSystemImage;
    public long BytesUserData;
    public string DestinationRoot = "";
    public string SessionFolder = "";
    public string Message = "";
    public readonly List<string> Steps = new();
    public readonly List<string> Errors = new();
    public readonly List<string> Warnings = new();
}

/// <summary>Tùy chọn sao lưu.</summary>
public sealed class BackupOptions
{
    /// <summary>Ổ đĩa đích (ví dụ "E:\"). Bắt buộc là ổ di động >= 1 TB.</summary>
    public string TargetDrive = "";
    /// <summary>Có sao lưu ảnh hệ thống (Acronis) không.</summary>
    public bool BackupSystemImage = true;
    /// <summary>Có sao lưu dữ liệu người dùng (Robocopy) không.</summary>
    public bool BackupUserData = true;
    /// <summary>Các ổ dữ liệu cần sao lưu (D:\, E:\...). Rỗng = tự phát hiện.</summary>
    public readonly List<string> UserDrives = new();
    /// <summary>Đường dẫn engine Acronis CLI (acrocmd.exe / Acronis True Image CLI).</summary>
    public string AcronisEnginePath = "";
    /// <summary>Tên máy dùng trong thư mục bản sao lưu.</summary>
    public string MachineName = "";
    /// <summary>Chạy chế độ dry-run (không ghi thật) — dùng để kiểm thử.</summary>
    public bool DryRun;
}

/// <summary>
/// Dịch vụ sao lưu máy tính.
///
/// <para>Hai chức năng:
///   1. Ảnh hệ thống (Full Disk / System Image) bằng engine Acronis CLI,
///      bao gồm ESP + MSR + Recovery + phân vùng Windows + bảng phân vùng GPT/MBR.
///   2. Dữ liệu người dùng bằng robocopy.exe với bộ tham số an toàn.</para>
///
/// <para>Ràng buộc bắt buộc: chỉ sao lưu vào ổ cứng di động gắn ngoài có dung lượng
/// vật lý >= 1 TB (930 GiB). Tuyệt đối không cho phép ghi vào ổ gắn trong.</para>
/// </summary>
public static class BackupService
{
    /// <summary>Ngưỡng dung lượng tối thiểu cho ổ đích — 1 TB thật hiển thị ~931 GiB trên Windows.</summary>
    public const long MinTargetBytes = 1_000_000_000_000L;   // 1 TB theo bytes thật
    public const long MinTargetBytesGiB = 930L * 1024 * 1024 * 1024; // ~930 GiB

    // ==================================================================
    //  PHAN 1: QUET O DIA VAT LY (WMI 3 TANG)
    // ==================================================================

    /// <summary>
    /// Quét ổ đĩa vật lý: Win32_DiskDrive → Win32_DiskPartition → Win32_LogicalDisk.
    /// </summary>
    public static DiskScanResult ScanDisks()
    {
        var res = new DiskScanResult();

        // --- Tang 1: Win32_DiskDrive ---
        try
        {
            using var s = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
            using var results = s.Get();

            foreach (ManagementObject raw in results)
            {
                try
                {
                    // Phai tao ManagementObject moi tu path de WMI refresh
                    // property (SELECT * + Get() khong duoc doc truc tiep).
                    using var d = new ManagementObject(raw.Path.Path);
                    d.Get();

                    var disk = new PhysicalDisk
                    {
                        DeviceId = WmiStr(d, "DeviceID"),
                        Model = WmiStr(d, "Model"),
                        Serial = WmiStr(d, "SerialNumber").Trim(),
                        InterfaceType = WmiStr(d, "InterfaceType"),
                        MediaType = WmiStr(d, "MediaType"),
                        SizeBytes = WmiLong(d, "Size"),
                        IsRemovable = WmiBool(d, "Removable"),
                    };
                    disk.SizeText = FormatBytes(disk.SizeBytes);

                    // Xac dinh o gan ngoai: removable OR interface USB/SD/MMC/External
                    string ifType = (disk.InterfaceType ?? "").ToUpperInvariant();
                    string mediaType = (disk.MediaType ?? "").ToUpperInvariant();
                    string model = (disk.Model ?? "").ToUpperInvariant();
                    disk.IsExternal = disk.IsRemovable
                        || ifType.Contains("USB")
                        || ifType.Contains("SD")
                        || ifType.Contains("MMC")
                        || ifType.Contains("FLASH")
                        || mediaType.Contains("EXTERNAL")
                        || mediaType.Contains("REMOVABLE")
                        || model.Contains("PORTABLE")
                        || model.Contains("EXTERNAL")
                        || model.Contains("ELEMENT")
                        || model.Contains("BASICS")
                        || model.Contains("S2 PORTABLE");

                    res.Disks.Add(disk);
                }
                catch (Exception ex)
                {
                    res.Errors.Add("Lỗi đọc ổ đĩa: " + ex.Message);
                }
            }
        }
        catch (Exception ex)
        {
            res.Errors.Add("Không quét được danh sách ổ đĩa vật lý: " + ex.Message);
        }

        // --- Tang 2: LogicalDisk -> Partition (ASSOCIATORS) ---
        try
        {
            using var ls = new ManagementObjectSearcher("SELECT * FROM Win32_LogicalDisk");
            using var lr = ls.Get();
            foreach (ManagementObject rawL in lr)
            {
                using var l = new ManagementObject(rawL.Path.Path);
                l.Get();
                string drive = WmiStr(l, "DeviceID");
                if (drive.Length < 2) continue;

                int diskIndex = -1;
                try
                {
                    using var assoc = new ManagementObjectSearcher(
                        "ASSOCIATORS OF {Win32_LogicalDisk.DeviceID='" + drive + "'} " +
                        "WHERE AssocClass = Win32_LogicalDiskToPartition");
                    using var ar = assoc.Get();
                    foreach (ManagementObject rawP in ar)
                    {
                        using var p = new ManagementObject(rawP.Path.Path);
                        p.Get();
                        int di = (int)WmiLong(p, "DiskIndex");
                        if (di < 0) continue;
                        if (diskIndex < 0) diskIndex = di;
                        else if (di != diskIndex) diskIndex = -2; // nhieu dia -> bo qua
                    }
                }
                catch (Exception ex)
                {
                    res.Errors.Add($"Lỗi ánh xạ {drive} → phân vùng: {ex.Message}");
                }

                if (diskIndex < 0) continue;

                PhysicalDisk? target = res.Disks.FirstOrDefault(d =>
                    string.Equals(DiskNumberOf(d.DeviceId), diskIndex.ToString(),
                                  StringComparison.OrdinalIgnoreCase));

                if (target == null) continue;

                if (!target.DriveLetters.Contains(drive))
                    target.DriveLetters.Add(drive);
            }
        }
        catch (Exception ex)
        {
            res.Errors.Add("Không đọc được quan hệ LogicalDisk → DiskPartition: " + ex.Message);
        }

        // --- Tang 3: gan ten phan vung cho tung dia ---
        try
        {
            using var ps = new ManagementObjectSearcher("SELECT * FROM Win32_DiskPartition");
            using var pr = ps.Get();
            foreach (ManagementObject rawP in pr)
            {
                using var p = new ManagementObject(rawP.Path.Path);
                p.Get();
                int di = (int)WmiLong(p, "DiskIndex");
                PhysicalDisk? target = res.Disks.FirstOrDefault(d =>
                    string.Equals(DiskNumberOf(d.DeviceId), di.ToString(),
                                  StringComparison.OrdinalIgnoreCase));
                if (target == null) continue;
                string partIdx = WmiStr(p, "Index");
                if (!target.Partitions.Contains(partIdx))
                    target.Partitions.Add(partIdx);
            }
        }
        catch (Exception ex)
        {
            res.Errors.Add("Không đọc được danh sách phân vùng: " + ex.Message);
        }

        // Phan loai: chi o di dong >= 1TB moi la noi sao luu hop le
        foreach (PhysicalDisk d in res.Disks)
        {
            if (!d.IsExternal)
            {
                res.Rejected.Add($"{d.DeviceId} {d.Model} — Ổ GẮN TRONG (không được phép sao lưu vào ổ nội bộ)");
                continue;
            }
            if (d.SizeBytes < MinTargetBytes && d.SizeBytes < MinTargetBytesGiB)
            {
                res.Rejected.Add(
                    $"{d.DeviceId} {d.Model} ({d.SizeText}) — dung lượng dưới ngưỡng 1 TB yêu cầu");
                continue;
            }
            res.ValidExternalTargets.Add(d);
        }

        return res;
    }

    /// <summary>Lấy số thứ tự ổ vật lý từ DeviceID dạng "\\.\PHYSICALDRIVE3".</summary>
    private static string DiskNumberOf(string deviceId)
    {
        if (string.IsNullOrWhiteSpace(deviceId)) return "";
        int idx = deviceId.LastIndexOfAny(new[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' });
        return idx < 0 ? "" : deviceId.Substring(idx);
    }

    public static string? ValidateTarget(string driveLetter, out PhysicalDisk? disk)
    {
        disk = null;
        if (string.IsNullOrWhiteSpace(driveLetter))
            return "Chưa chọn ổ đĩa đích.";

        string letter = driveLetter.Trim().ToUpperInvariant();
        if (letter.Length == 1) letter += ":\\";
        else if (letter.EndsWith(":") == false && letter.EndsWith("\\") == false) letter += "\\";

        DiskScanResult scan = ScanDisks();
        PhysicalDisk? found = scan.Disks.FirstOrDefault(d =>
            d.DriveLetters.Any(l => l.Equals(letter.Substring(0, 2), StringComparison.OrdinalIgnoreCase)));

        if (found == null)
            return "Không xác định được ổ vật lý của " + letter + " — hãy cắm ổ cứng di động rồi làm mới.";

        disk = found;

        if (!found.IsExternal)
            return $"{found.DeviceId} {found.Model} là Ổ GẮN TRONG. " +
                   "Tuyệt đối không cho phép lưu bản sao lưu vào ổ cứng nội bộ.";

        if (found.SizeBytes < MinTargetBytes && found.SizeBytes < MinTargetBytesGiB)
            return $"{found.Model} ({found.SizeText}) có dung lượng dưới ngưỡng 1 TB yêu cầu. " +
                   "Vui lòng dùng ổ cứng di động tối thiểu 1 TB.";

        return null;
    }

    /// <summary>Tìm các ổ dữ liệu gắn trong (khác C:) để sao lưu dữ liệu người dùng.</summary>
    public static List<string> DetectUserDataDrives(string? excludeDrive = null)
    {
        var list = new List<string>();
        string excl = NormalizeDrive(excludeDrive);

        try
        {
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) continue;
                if (d.DriveType == DriveType.Removable) continue;   // ổ USB không phải dữ liệu
                if (d.DriveType == DriveType.CDRom) continue;       // ổ đĩa quang
                if (d.Name.StartsWith("C:", StringComparison.OrdinalIgnoreCase)) continue; // ổ hệ thống

                // Loai o dia chinh (o dich) - tranh robocopy copy vao chinh no
                if (excl.Length > 0 &&
                    d.Name.StartsWith(excl, StringComparison.OrdinalIgnoreCase)) continue;

                list.Add(d.Name);
            }
        }
        catch { }
        return list;
    }

    /// <summary>Chuan hoa "E", "E:", "E:\\" thanh "E:".</summary>
    private static string NormalizeDrive(string? drive)
    {
        if (string.IsNullOrWhiteSpace(drive)) return "";
        string s = drive.Trim().ToUpperInvariant();
        int i = 0;
        while (i < s.Length && char.IsLetter(s[i])) i++;
        if (i == 0) return "";
        return s.Substring(0, i) + ":";
    }

    // ==================================================================
    //  PHAN 2: ENGINE ACRO NIS (ANH HE THONG)
    // ==================================================================

    /// <summary>Tìm engine Acronis CLI trong tools\acronis hoặc đường dẫn cài đặt thông dụng.</summary>
    public static string? LocateAcronisEngine(string? explicitPath = null)
    {
        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(explicitPath)) candidates.Add(explicitPath);

        candidates.Add(Path.Combine(AppContext.BaseDirectory, "tools", "acronis", "acrocmd.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "tools", "acronis", "AcronisTrueImageCmd.exe"));
        candidates.Add(Path.Combine(AppContext.BaseDirectory, "tools", "acronis", "AcronisCLI.exe"));

        // Duong dan cai dat mac dinh cua Acronis
        string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        foreach (string root in new[] { pf, pf86 })
        {
            if (string.IsNullOrEmpty(root)) continue;
            string acr = Path.Combine(root, "Acronis");
            if (!Directory.Exists(acr)) continue;
            try
            {
                foreach (string f in Directory.EnumerateFiles(acr, "*.exe", SearchOption.AllDirectories))
                {
                    string name = Path.GetFileName(f).ToLowerInvariant();
                    if (name.Contains("acrocmd") || name.Contains("trueimagecmd") || name.Contains("acroniscli"))
                        candidates.Add(f);
                }
            }
            catch { }
        }

        foreach (string c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    /// <summary>
    /// Tạo lệnh Acronis tạo ảnh hệ thống (Full Disk) cho phân vùng Windows.
    ///
    /// <para>Ảnh bao gồm toàn bộ ổ (tất cả phân vùng kể cả ESP/MSR/Recovery)
    /// để khôi phục được trên phần cứng mới. Cấu trúc thư mục:
    /// <c>&lt;TenMay&gt;_&lt;yyyyMMdd_HHmmss&gt;\SystemImage\</c>.</para>
    /// </summary>
    public static string BuildAcronisBackupCommand(
        string enginePath,
        string systemDrive,
        string outputDir,
        string sessionName)
    {
        var sb = new StringBuilder();

        // Tao storage + tat cacung
        sb.Append("create backup --target ");
        sb.Append(Quote(outputDir));
        sb.Append(" --type " + Quote("entire machine"));
        sb.Append(" --name " + Quote(sessionName + " - Full Disk"));
        sb.Append(" --system " + Quote(systemDrive));
        sb.Append(" --sources " + Quote(systemDrive));
        sb.Append(" --backup-type " + Quote("entire machine"));
        sb.Append(" --comment " + Quote("Danny ver5.7 - Anh he thong (EFI+MSR+Recovery+Windows)"));
        sb.Append(" --log-level " + Quote("info"));
        sb.Append(" --log " + Quote(Path.Combine(outputDir, "acronis.log")));
        sb.Append(" --quiet ");

        return sb.ToString();
    }

    /// <summary>Chạy engine Acronis với lệnh đã dựng, ghi log stdout/stderr theo thời gian thực.</summary>
    public static async Task<(bool ok, int exitCode)> RunAcronisAsync(
        string enginePath,
        string arguments,
        Action<string> onOutput,
        CancellationToken ct)
    {
        try
        {
            var psi = new ProcessStartInfo(enginePath, arguments)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            using var p = new Process { StartInfo = psi };
            p.OutputDataReceived += (s, e) => { if (e.Data != null) onOutput("[ACRONIS] " + e.Data); };
            p.ErrorDataReceived += (s, e) => { if (e.Data != null) onOutput("[ACRONIS-LỖI] " + e.Data); };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            while (!p.HasExited)
            {
                if (ct.IsCancellationRequested)
                {
                    try { p.Kill(true); } catch { }
                    return (false, -1);
                }
                await Task.Delay(400, ct).ConfigureAwait(false);
            }

            p.WaitForExit();
            return (p.ExitCode == 0, p.ExitCode);
        }
        catch (Exception ex)
        {
            onOutput("[ACRONIS-LỖI] " + ex.Message);
            return (false, -1);
        }
    }

    // ==================================================================
    //  PHAN 3: ENGINE ROBOCOPY (DU LIEU NGUOI DUNG)
    // ==================================================================

    /// <summary>
    /// Dựng lệnh robocopy an toàn + tối ưu tốc độ + tránh lặp junction.
    /// </summary>
    public static string BuildRobocopyCommand(string source, string destination, string logFile)
    {
        var sb = new StringBuilder();
        sb.Append('"').Append(source.TrimEnd('\\')).Append('"');
        sb.Append(" \"");
        sb.Append(destination.TrimEnd('\\'));
        sb.Append('"');
        sb.Append(" /E /COPY:DAT /DCOPY:T /R:2 /W:3 /MT:8 /XJ");
        sb.Append(" /XD \"$RECYCLE.BIN\" \"System Volume Information\"");
        sb.Append(" /UNILOG+:").Append(Quote(logFile));
        sb.Append(" /NFL /NDL /NP");
        return sb.ToString();
    }

    /// <summary>Chạy robocopy, báo cáo dung lượng đã copy theo thời gian thực.</summary>
    public static async Task<(bool ok, int exitCode, long bytes)> RunRobocopyAsync(
        string source,
        string destination,
        string logFile,
        Action<string> onOutput,
        IProgress<long>? onBytes,
        CancellationToken ct)
    {
        long copied = 0;
        try
        {
            string args = BuildRobocopyCommand(source, destination, logFile);
            var psi = new ProcessStartInfo("robocopy.exe", args)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardOutputEncoding = Encoding.GetEncoding(0),
                StandardErrorEncoding = Encoding.GetEncoding(0)
            };

            using var p = new Process { StartInfo = psi };
            p.OutputDataReceived += (s, e) =>
            {
                if (e.Data == null) return;
                string line = e.Data.Trim();
                if (line.Length == 0) return;
                onOutput("[ROBOCOPY] " + line);
            };
            p.ErrorDataReceived += (s, e) => { if (e.Data != null) onOutput("[ROBOCOPY-LỖI] " + e.Data); };
            p.Start();
            p.BeginOutputReadLine();
            p.BeginErrorReadLine();

            // Doc file log de lay tong so byte (robocopy ghi tong o cuoi)
            long lastReported = 0;
            while (!p.HasExited)
            {
                if (ct.IsCancellationRequested)
                {
                    try { p.Kill(true); } catch { }
                    return (false, -1, copied);
                }

                try
                {
                    if (File.Exists(logFile))
                    {
                        var fi = new FileInfo(logFile);
                        if (fi.Length != lastReported)
                        {
                            lastReported = fi.Length;
                            copied = ReadRobocopyCopiedBytes(logFile);
                            onBytes?.Report(copied);
                        }
                    }
                }
                catch { }

                await Task.Delay(700, ct).ConfigureAwait(false);
            }

            p.WaitForExit();
            try { copied = ReadRobocopyCopiedBytes(logFile); } catch { }
            onBytes?.Report(copied);

            // Robocopy: 0-7 = thanh cong, 8+ = loi
            return (p.ExitCode < 8, p.ExitCode, copied);
        }
        catch (Exception ex)
        {
            onOutput("[ROBOCOPY-LỖI] " + ex.Message);
            return (false, -1, copied);
        }
    }

    /// <summary>Parse tong so byte da copy tu log robocopy (cot "Bytes").</summary>
    private static long ReadRobocopyCopiedBytes(string logFile)
    {
        try
        {
            var lines = File.ReadAllLines(logFile);
            for (int i = lines.Length - 1; i >= 0 && i > lines.Length - 60; i--)
            {
                string ln = lines[i];
                if (!ln.Contains("Bytes :", StringComparison.OrdinalIgnoreCase)) continue;
                string after = ln.Substring(ln.IndexOf("Bytes :", StringComparison.OrdinalIgnoreCase) + 7);
                var parts = after.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (string part in parts)
                {
                    if (long.TryParse(part, out long v)) return v;
                }
            }
        }
        catch { }
        return 0;
    }

    // ==================================================================
    //  PHAN 4: LUONG CHINH
    // ==================================================================

    /// <summary>
    /// Chạy quy trình sao lưu. Trả về kết quả mô tả (không ném exception ra ngoài).
    /// </summary>
    public static async Task<BackupResult> RunAsync(
        BackupOptions opt,
        Action<string> onLog,
        Action<int, int>? onProgress = null,
        CancellationToken ct = default)
    {
        var res = new BackupResult();
        Action<string> L = (m) => { res.Steps.Add(m); onLog(m); };

        string machine = string.IsNullOrWhiteSpace(opt.MachineName)
            ? Environment.MachineName
            : opt.MachineName;
        string stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        string session = $"{SanitizeName(machine)}_{stamp}";
        res.SessionFolder = session;

        // --- Kiem tra o dich ---
        L("Kiểm tra ổ đích sao lưu...");
        string? reject = ValidateTarget(opt.TargetDrive, out PhysicalDisk? targetDisk);
        if (reject != null)
        {
            res.Message = reject;
            L("✗ " + reject);
            return res;
        }
        L($"✓ Ổ đích hợp lệ: {targetDisk!.Model} ({targetDisk.SizeText}) — {targetDisk.DeviceId}");

        string driveRoot = opt.TargetDrive.Trim();
        if (driveRoot.Length == 1) driveRoot += ":";
        if (!driveRoot.EndsWith("\\")) driveRoot += "\\";

        string sessionDir = Path.Combine(driveRoot, session);
        res.DestinationRoot = sessionDir;

        // --- Tao cau truc thu muc ---
        try
        {
            if (opt.DryRun)
            {
                // Che do dry-run KHONG tao thu muc that tren o dich
                L($"[DRY-RUN] Thu muc dich se la: {sessionDir}");
            }
            else
            {
                Directory.CreateDirectory(sessionDir);
                string sysDir = Path.Combine(sessionDir, "SystemImage");
                string usrDir = Path.Combine(sessionDir, "UserData");
                Directory.CreateDirectory(sysDir);
                Directory.CreateDirectory(usrDir);
                L($"Đã tạo thư mục: {sessionDir}");
            }
        }
        catch (Exception ex)
        {
            res.Message = "Không tạo được thư mục đích: " + ex.Message;
            L("✗ " + res.Message);
            return res;
        }

        // --- Kiem tra dung luong trong ---
        try
        {
            var di = new DriveInfo(driveRoot);
            long need = EstimateRequiredBytes(opt);
            if (di.AvailableFreeSpace < need)
            {
                res.Warnings.Add(
                    $"Dung lượng trống còn lại ({FormatBytes(di.AvailableFreeSpace)}) có thể không đủ " +
                    $"cho ảnh hệ thống + dữ liệu (ước tính {FormatBytes(need)}).");
                L("⚠ " + res.Warnings[res.Warnings.Count - 1]);
            }
            else
            {
                L($"Dung lượng trống: {FormatBytes(di.AvailableFreeSpace)} (ước tính cần {FormatBytes(need)})");
            }
        }
        catch (Exception ex)
        {
            res.Warnings.Add("Không đọc được dung lượng ổ đích: " + ex.Message);
        }

        // --- Buoc A: anh he thong bang Acronis ---
        if (opt.BackupSystemImage)
        {
            L("=== BƯỚC A: ẢNH HỆ THỐNG (Acronis) ===");
            string? engine = LocateAcronisEngine(opt.AcronisEnginePath);
            if (engine == null)
            {
                res.Errors.Add(
                    "Không tìm thấy engine Acronis CLI. Hãy đặt acrocmd.exe (hoặc AcronisTrueImageCmd.exe) " +
                    "vào thư mục tools\\acronis\\ cạnh phần mềm, hoặc cài Acronis True Image rồi chọn đường dẫn.");
                L("✗ " + res.Errors[res.Errors.Count - 1]);
            }
            else
            {
                L("Engine: " + engine);
                string sysDir = Path.Combine(sessionDir, "SystemImage");
                string cmd = BuildAcronisBackupCommand(engine, "C:", sysDir, session);

                if (opt.DryRun)
                {
                    L("[DRY-RUN] Lệnh sẽ chạy: " + cmd);
                }
                else
                {
                    L("Đang tạo ảnh hệ thống — có thể mất 30–180 phút tùy dung lượng ổ...");
                    var (ok, code) = await RunAcronisAsync(engine, cmd, L, ct).ConfigureAwait(false);
                    if (ok)
                    {
                        res.BytesSystemImage = MeasureDir(sysDir);
                        L($"✓ Ảnh hệ thống hoàn tất ({FormatBytes(res.BytesSystemImage)})");
                    }
                    else
                    {
                        res.Errors.Add($"Acronis kết thúc với mã {code}. Xem log: {Path.Combine(sysDir, "acronis.log")}");
                        L("✗ " + res.Errors[res.Errors.Count - 1]);
                    }
                }
            }
        }

        // --- Buoc B: du lieu nguoi dung bang Robocopy ---
        if (opt.BackupUserData)
        {
            L("=== BƯỚC B: DỮ LIỆU NGƯỜI DÙNG (Robocopy) ===");
            List<string> sources = opt.UserDrives.Count > 0
                ? new List<string>(opt.UserDrives)
                : DetectUserDataDrives(opt.TargetDrive);

            if (sources.Count == 0)
            {
                res.Warnings.Add("Không phát hiện ổ dữ liệu gắn trong nào (ngoài C:) để sao lưu.");
                L("⚠ " + res.Warnings[res.Warnings.Count - 1]);
            }

            string usrDir = Path.Combine(sessionDir, "UserData");
            foreach (string src in sources)
            {
                if (ct.IsCancellationRequested) { res.Cancelled = true; break; }

                string letter = src.Trim().ToUpperInvariant();
                if (letter.Length >= 2) letter = letter.Substring(0, 2);
                string dst = Path.Combine(usrDir, "Drive_" + letter.Replace(":", ""));
                string logFile = Path.Combine(usrDir, "robocopy_" + letter.Replace(":", "") + ".log");

                try
                {
                    L($"Sao chép {src} → {dst}");

                    if (opt.DryRun)
                    {
                        L("[DRY-RUN] robocopy " + BuildRobocopyCommand(src, dst, logFile));
                        continue;
                    }

                    Directory.CreateDirectory(dst);

                    var (ok, code, bytes) = await RunRobocopyAsync(
                        src, dst, logFile, L,
                        new Progress<long>(b => res.BytesUserData = b),
                        ct).ConfigureAwait(false);

                    if (ok)
                    {
                        L($"✓ Sao chép {src} hoàn tất ({FormatBytes(bytes)})");
                    }
                    else
                    {
                        res.Errors.Add($"Robocopy {src} kết thúc với mã {code}. Xem log: {logFile}");
                        L("✗ " + res.Errors[res.Errors.Count - 1]);
                    }
                }
                catch (Exception ex)
                {
                    res.Errors.Add($"Lỗi sao chép {src}: " + ex.Message);
                    L("✗ " + res.Errors[res.Errors.Count - 1]);
                }
            }
        }

        // --- Tong ket ---
        res.Success = res.Errors.Count == 0 && !res.Cancelled;
        if (res.Cancelled)
            res.Message = "Đã hủy theo yêu cầu.";
        else if (res.Success)
            res.Message = $"Sao lưu hoàn tất. Ảnh hệ thống: {FormatBytes(res.BytesSystemImage)} · " +
                          $"Dữ liệu: {FormatBytes(res.BytesUserData)} → {sessionDir}";
        else
            res.Message = $"Sao lưu hoàn tất với {res.Errors.Count} lỗi. Thư mục: {sessionDir}";

        L(res.Message);
        return res;
    }

    private static long EstimateRequiredBytes(BackupOptions opt)
    {
        long need = 0;
        try
        {
            var di = new DriveInfo("C:\\");
            need = (long)(di.TotalSize * 1.2); // anh he thong + 20% du phong
        }
        catch { need = 120L * 1024 * 1024 * 1024; }

        if (opt.BackupUserData)
        {
            List<string> srcs = opt.UserDrives.Count > 0
                ? new List<string>(opt.UserDrives)
                : DetectUserDataDrives(opt.TargetDrive);
            foreach (string s in srcs)
            {
                try { need += new DriveInfo(s).TotalSize; }
                catch { }
            }
        }
        return need;
    }

    private static long MeasureDir(string dir)
    {
        try
        {
            if (!Directory.Exists(dir)) return 0;
            long total = 0;
            foreach (string f in Directory.EnumerateFiles(dir, "*", SearchOption.AllDirectories))
            {
                try { total += new FileInfo(f).Length; } catch { }
            }
            return total;
        }
        catch { return 0; }
    }

    private static string SanitizeName(string s)
    {
        var sb = new StringBuilder();
        foreach (char c in s)
            sb.Append(char.IsLetterOrDigit(c) || c == '-' || c == '_' ? c : '_');
        return sb.ToString();
    }

    private static string Quote(string s) => "\"" + s + "\"";

    /// <summary>
    /// Doc property cua WMI theo ten, khong nem loi.
    ///
    /// <para>Mot so property (vi du "Removable" cua Win32_DiskDrive) khong ton
    /// tai tren may Windows 10/11 khi refresh object theo path -&gt; truy cap
    /// truc tiep se nem ManagementException("Not found") va lam ca bang quet
    /// o dia that bai. Helper nay tra ve gia tri mac dinh neu property khong
    /// ton tai hoac provider loi.</para>
    /// </summary>
    private static object? WmiProp(ManagementBaseObject o, string name)
    {
        try
        {
            object? v = o[name];
            return v;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>Doc property WMI dang chuoi (null -&gt; chuoi rong).</summary>
    private static string WmiStr(ManagementBaseObject o, string name)
    {
        object? v = WmiProp(o, name);
        return v?.ToString() ?? "";
    }

    /// <summary>Doc property WMI dang so (khong doc -&gt; 0).</summary>
    private static long WmiLong(ManagementBaseObject o, string name)
    {
        object? v = WmiProp(o, name);
        try { return v == null ? 0L : Convert.ToInt64(v); } catch { return 0L; }
    }

    /// <summary>Doc property WMI dang bool (null -&gt; false).</summary>
    private static bool WmiBool(ManagementBaseObject o, string name)
    {
        object? v = WmiProp(o, name);
        if (v == null) return false;
        try { return Convert.ToBoolean(v); } catch { return false; }
    }

    private static string ToStr(Object? o) => o?.ToString() ?? "";
    private static long ToLong(object? o)
    {
        try { return Convert.ToInt64(o ?? 0L); } catch { return 0; }
    }
    private static bool ToBool(object? o)
    {
        try { return Convert.ToBoolean(o); } catch { return false; }
    }

    /// <summary>Định dạng dung lượng cho người dùng đọc.</summary>
    public static string FormatBytes(long b)
    {
        if (b < 0) return "—";
        if (b < 1024) return b + " B";
        if (b < 1024L * 1024) return (b / 1024.0).ToString("F1") + " KB";
        if (b < 1024L * 1024 * 1024) return (b / 1024.0 / 1024).ToString("F1") + " MB";
        if (b < 1024L * 1024 * 1024 * 1024) return (b / 1024.0 / 1024 / 1024).ToString("F2") + " GB";
        return (b / 1024.0 / 1024 / 1024 / 1024).ToString("F2") + " TB";
    }
}
