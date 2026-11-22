using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecTool.Forensic;

/// <summary>Tùy chọn chạy thu thập chứng cứ.</summary>
public sealed class ForensicOptions
{
    /// <summary>Thư mục lưu gói chứng cứ. Rỗng = tự tạo trong thư mục "Bao-cao" cạnh exe.</summary>
    public string OutputDirectory = "";
    /// <summary>Đường dẫn file quy tắc JSON. Rỗng = tự dò trong tools/rules/.</summary>
    public string RulesPath = "";
    /// <summary>Bỏ qua việc băm SHA-256 các file lớn (tăng tốc).</summary>
    public bool SkipLargeFileHashing;
    /// <summary>Giới hạn số file băm (0 = không giới hạn).</summary>
    public int MaxFilesToHash = 2000;
}

/// <summary>
/// Điều phối toàn bộ quy trình pháp y số.
///
/// <para>Luồng: Thu thập → Phân tích quy tắc → Dòng thời gian → Đóng gói báo cáo.</para>
/// </summary>
public static class ForensicEngine
{
    /// <summary>Phiên bản công cụ ghi trong báo cáo.</summary>
    public const string ToolVersion = "5.7.0";

    /// <summary>
    /// Chạy toàn bộ quy trình điều tra.
    /// </summary>
    public static async Task<EvidenceBundle> RunAsync(
        ForensicOptions opt,
        Action<string> log,
        IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var bundle = new EvidenceBundle
        {
            MachineName = Environment.MachineName,
            UserName = Environment.UserName,
            OperatingSystem = RuntimeInformation.OSDescription,
            CollectionUtc = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC",
            CollectionLocal = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + " (" + TimeZoneInfo.Local.Id + ")",
            ToolVersion = ToolVersion,
            CollectionMode = "local read-only / minimal footprint"
        };

        // --- Thu thập ---
        progress?.Report(5);
        log("Bước 1/4 — Thu thập chứng cứ (chế độ chỉ đọc)...");

        var errors = bundle.CollectorErrors;

        await Task.Run(() =>
        {
            log("  • Mạng: adapter, định tuyến, ARP, DNS cache, cổng, proxy...");
            bundle.Artifacts.AddRange(EvidenceCollector.CollectNetwork(errors));
            progress?.Report(20);
        }, ct).ConfigureAwait(false);

        await Task.Run(() =>
        {
            log("  • Registry: USBSTOR, MountedDevices, autorun, DNS policy...");
            bundle.Artifacts.AddRange(EvidenceCollector.CollectRegistry(errors));
            progress?.Report(40);
        }, ct).ConfigureAwait(false);

        await Task.Run(() =>
        {
            log("  • Hệ thống: tiến trình, scheduled task, event log, service...");
            bundle.Artifacts.AddRange(EvidenceCollector.CollectSystem(errors));
            progress?.Report(65);
        }, ct).ConfigureAwait(false);

        await Task.Run(() =>
        {
            log("  • Dấu vết file: Prefetch, Jump List, Recent, staging, setupapi...");
            bundle.Artifacts.AddRange(EvidenceCollector.CollectFileTraces(errors));
            progress?.Report(80);
        }, ct).ConfigureAwait(false);

        await Task.Run(() =>
        {
            log("  • Trình duyệt: History, cookies, downloads (Chrome/Edge/Firefox)...");
            bundle.Artifacts.AddRange(EvidenceCollector.CollectBrowserHistory(errors));
            progress?.Report(88);
        }, ct).ConfigureAwait(false);

        log($"  → Đã thu thập {bundle.Artifacts.Count} artifact.");

        // --- Phân tích quy tắc ---
        progress?.Report(90);
        log("Bước 2/4 — Phân tích theo bộ quy tắc...");
        RuleSet rules = RuleSet.Load(string.IsNullOrWhiteSpace(opt.RulesPath) ? null : opt.RulesPath);
        log($"  • Nguồn quy tắc: {RuleSet.LocateRulesFile() ?? "bộ mặc định tích hợp"} " +
            $"({rules.Rules.Count} quy tắc, phiên bản {rules.Version})");

        bundle.Findings.AddRange(RuleEngine.Analyze(bundle, rules));
        log($"  → Phát hiện {bundle.Findings.Count} chỉ báo " +
            $"(CRITICAL {bundle.Findings.Count(f => f.Severity == Severity.Critical)}, " +
            $"HIGH {bundle.Findings.Count(f => f.Severity == Severity.High)}).");

        // --- Dòng thời gian ---
        progress?.Report(94);
        log("Bước 3/4 — Dựng dòng thời gian & tương quan chuỗi hành vi...");
        bundle.Timeline.Clear();
        bundle.Timeline.AddRange(TimelineEngine.Build(bundle));
        log($"  → {bundle.Timeline.Count} sự kiện trên dòng thời gian.");

        // --- Đóng gói ---
        progress?.Report(97);
        log("Bước 4/4 — Xuất báo cáo & đóng gói chứng cứ...");

        string outDir = string.IsNullOrWhiteSpace(opt.OutputDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "Bao-cao",
                "Forensic_" + Environment.MachineName + "_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"))
            : opt.OutputDirectory;

        bundle.OutputDirectory = outDir;
        ReportWriter.WritePack(bundle, outDir);
        log($"  → Gói chứng cứ: {outDir}");
        log("     ├── Bao-cao-dieu-tra.html");
        log("     ├── Bao-cao-dieu-tra.md");
        log("     ├── Dong-thoi-gian.csv");
        log("     ├── raw/evidence.json");
        log("     └── manifest.sha256");

        // --- Hạn chế kỹ thuật ---
        bundle.Limitations.Add(
            "Công cụ chỉ đọc, không sửa bất kỳ dữ liệu nào trên máy đang điều tra.");
        bundle.Limitations.Add(
            "Dữ liệu trong RAM (tiến trình, kết nối mở, khóa phiên) không được thu thập " +
            "vì có thể gây gián đoạn — cần công cụ chuyên dụng (FTK Imager, DumpIt) nếu cần.");
        bundle.Limitations.Add(
            "$UsnJrnl chỉ được ghi nhận metadata, chưa parse nội dung journal. " +
            "Cần phân tích ngoại tuyến trên image ổ đĩa.");
        bundle.Limitations.Add(
            "Lịch sử trình duyệt được thu thập dưới dạng file SQLite nguyên trạng " +
            "(không query để không tạo file -wal/-shm). Cần mở bằng công cụ riêng để đọc nội dung.");
        bundle.Limitations.Add(
            "Một số khóa registry yêu cầu quyền SYSTEM chưa được đọc; " +
            "kết quả chỉ có giá trị trong phạm vi artifact đã thu thập.");

        // Điểm & kết luận
        bundle.TotalScore = RuleEngine.Score(bundle, out string verdict);
        bundle.Verdict = verdict;

        // Ghi lại báo cáo (đã có điểm + verdict)
        ReportWriter.WritePack(bundle, outDir);

        progress?.Report(100);
        return bundle;
    }

    /// <summary>
    /// Tạo file quy tắc mặc định trong tools/rules/forensic-rules.json
    /// (để đơn vị có thể tùy chỉnh).
    /// </summary>
    public static string WriteDefaultRulesFile()
    {
        string dir = Path.Combine(AppContext.BaseDirectory, "tools", "rules");
        Directory.CreateDirectory(dir);
        string path = Path.Combine(dir, "forensic-rules.json");
        File.WriteAllText(path, RuleSet.ToJson(RuleSet.DefaultRules()), Encoding.UTF8);
        return path;
    }
}
