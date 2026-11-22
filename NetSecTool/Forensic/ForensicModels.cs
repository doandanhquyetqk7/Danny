using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NetSecTool.Forensic;

/// <summary>Mức độ nghi ngờ của một phát hiện.</summary>
public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

/// <summary>Nhóm sự cố mà phát hiện thuộc về.</summary>
public enum IncidentCategory
{
    /// <summary>Kết nối ra Internet trái phép.</summary>
    UnauthorizedInternet,
    /// <summary>Lộ lọt tài liệu ra ngoài.</summary>
    DataExfiltration,
    /// <summary>Anti-forensics (xóa dấu vết).</summary>
    AntiForensics,
    /// <summary>Hành vi hệ thống bất thường.</summary>
    SuspiciousActivity
}

/// <summary>Một sự kiện trên dòng thời gian.</summary>
public sealed class TimelineEvent
{
    /// <summary>Thời điểm UTC.</summary>
        [JsonInclude] public DateTime TimestampUtc;
    /// <summary>Thời điểm UTC dạng ISO-8601 (thuận tiện cho công cụ phân tích).</summary>
    public string TimestampUtcIso
    {
        get => TimestampUtc == DateTime.MinValue ? "" : TimestampUtc.ToString("o");
        set { if (DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime d)) TimestampUtc = d; }
    }
    /// <summary>Nguồn thu thập (network / registry / eventlog / file / process).</summary>
        [JsonInclude] public string Source = "";
    /// <summary>Mô tả ngắn.</summary>
        [JsonInclude] public string Description = "";
    /// <summary>Đường dẫn / giá trị gốc của artifact.</summary>
        [JsonInclude] public string Artifact = "";
    /// <summary>Mức độ nghi ngờ.</summary>
        [JsonInclude] public Severity Severity = Severity.Info;
    /// <summary>Chuỗi hành vi (xem TimelineEngine).</summary>
        [JsonInclude] public string Chain = "";
    /// <summary>Dữ liệu bổ sung dạng key=value.</summary>
    public Dictionary<string, string> Attributes = new();
}

/// <summary>Một chỉ báo / phát hiện do rule engine sinh ra.</summary>
public sealed class Finding
{
        [JsonInclude] public string RuleId = "";
        [JsonInclude] public string Title = "";
        [JsonInclude] public string Explanation = "";
        [JsonInclude] public Severity Severity = Severity.Info;
        [JsonInclude] public IncidentCategory Category = IncidentCategory.SuspiciousActivity;
    /// <summary>Artifact gốc sinh ra phát hiện.</summary>
        [JsonInclude] public string Artifact = "";
        [JsonInclude] public DateTime TimestampUtc = DateTime.MinValue;
    /// <summary>Thời điểm UTC dạng ISO-8601.</summary>
    public string TimestampUtcIso
    {
        get => TimestampUtc == DateTime.MinValue ? "" : TimestampUtc.ToString("o");
        set { if (DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime d)) TimestampUtc = d; }
    }
    /// <summary>Điểm nghi ngờ (0-100).</summary>
        [JsonInclude] public int Score;
    /// <summary>Bằng chứng cụ thể.</summary>
    public readonly List<string> Evidence = new();
}

/// <summary>Một artifact đã thu thập kèm hash và metadata.</summary>
public sealed class Artifact
{
        [JsonInclude] public string Source = "";
        [JsonInclude] public string Path = "";
        [JsonInclude] public string Category = "";
        [JsonInclude] public long SizeBytes;
        [JsonInclude] public DateTime ModifiedUtc = DateTime.MinValue;
    /// <summary>Mốc thời gian sửa lần cuối dạng ISO-8601.</summary>
    public string ModifiedUtcIso
    {
        get => ModifiedUtc == DateTime.MinValue ? "" : ModifiedUtc.ToString("o");
        set { if (DateTime.TryParse(value, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime d)) ModifiedUtc = d; }
    }
        [JsonInclude] public string Sha256 = "";
    /// <summary>Loại: file / registry / command-output.</summary>
        [JsonInclude] public string Kind_ = "file";
        [JsonInclude] public string ContentPreview = "";
}

/// <summary>Kết quả thu thập chứng cứ của một máy.</summary>
public sealed class EvidenceBundle
{
    /// <summary>Thông tin máy thu thập.</summary>
        [JsonInclude] public string MachineName = "";
        [JsonInclude] public string UserName = "";
        [JsonInclude] public string OperatingSystem = "";
        [JsonInclude] public string CollectionUtc = "";
        [JsonInclude] public string CollectionLocal = "";
        [JsonInclude] public string ToolVersion = "";
        [JsonInclude] public string CollectionMode = "local";
    /// <summary>Đường dẫn gói chứng cứ đã ghi.</summary>
        [JsonInclude] public string OutputDirectory = "";

    // readonly + [JsonInclude]: System.Text.Json khong serialize field readonly
    // mac dinh -> phai chi dinh explicit moi giu duoc danh sach trong JSON.
    [JsonInclude] public readonly List<Artifact> Artifacts = new();
    [JsonInclude] public readonly List<Finding> Findings = new();
    [JsonInclude] public readonly List<TimelineEvent> Timeline = new();
    [JsonInclude] public readonly List<string> CollectorErrors = new();
    [JsonInclude] public readonly List<string> Limitations = new();

    /// <summary>Điểm nghi ngờ tổng thể (0-100).</summary>
        [JsonInclude] public int TotalScore;
    /// <summary>Kết luận.</summary>
        [JsonInclude] public string Verdict = "Chưa đủ dữ liệu";
}

/// <summary>Một quy tắc phát hiện (nạp từ rules.json hoặc dùng mặc định).</summary>
public sealed class ForensicRule
{
        [JsonInclude] public string Id = "";
        [JsonInclude] public string Title = "";
        [JsonInclude] public string Description = "";
        [JsonInclude] public Severity Severity = Severity.Medium;
        [JsonInclude] public IncidentCategory Category = IncidentCategory.SuspiciousActivity;
        [JsonInclude] public int Score = 10;
    /// <summary>Điều kiện: loại artifact nguồn (network/registry/eventlog/file/process).</summary>
        [JsonInclude] public string? ArtifactSource;
    /// <summary>Mẫu khớp (biểu thức chính quy, không phân biệt hoa thường).</summary>
        [JsonInclude] public string? Pattern;
    /// <summary>Điều kiện bổ sung: artifact phải chứa chuỗi này.</summary>
        [JsonInclude] public string? Contains;
    /// <summary>Điều kiện bổ sung: artifact phải KHÔNG chứa chuỗi này.</summary>
        [JsonInclude] public string? NotContains;
    /// <summary>Điều kiện bổ sung: artifact phải khớp mẫu này.</summary>
        [JsonInclude] public string? MatchPattern;
    /// <summary>Bật/tắt quy tắc.</summary>
        [JsonInclude] public bool Enabled = true;
    /// <summary>Khuyến nghị xử lý.</summary>
        [JsonInclude] public string Recommendation = "";
}

/// <summary>Cấu hình tập quy tắc.</summary>
public sealed class RuleSet
{
        [JsonInclude] public string Version = "1.0";
        [JsonInclude] public string Description = "";
    public readonly List<ForensicRule> Rules = new();

    /// <summary>Tìm đường dẫn file rules.json (ngoài exe hoặc trong tools).</summary>
    public static string? LocateRulesFile()
    {
        string[] candidates =
        {
            Path.Combine(AppContext.BaseDirectory, "tools", "rules", "forensic-rules.json"),
            Path.Combine(AppContext.BaseDirectory, "forensic-rules.json"),
            Path.Combine(AppContext.BaseDirectory, "tools", "forensic-rules.json"),
            Path.Combine(AppContext.BaseDirectory, "rules.json")
        };
        foreach (string c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    /// <summary>Nạp quy tắc từ file JSON; nếu không có thì dùng bộ mặc định tích hợp.</summary>
    public static RuleSet Load(string? path = null)
    {
        path ??= LocateRulesFile();
        if (path != null && File.Exists(path))
        {
            try
            {
                var opts = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    ReadCommentHandling = JsonCommentHandling.Skip,
                    AllowTrailingCommas = true
                };
                var set = JsonSerializer.Deserialize<RuleSet>(File.ReadAllText(path), opts);
                if (set != null && set.Rules.Count > 0)
                    return set;
            }
            catch (Exception ex)
            {
                RuleSet fallback = DefaultRules();
                fallback.Description += $" (không đọc được {path}: {ex.Message})";
                return fallback;
            }
        }
        return DefaultRules();
    }

    /// <summary>Bộ quy tắc mặc định tích hợp (ver5.7).</summary>
    public static RuleSet DefaultRules()
    {
        var s = new RuleSet
        {
            Version = "1.0",
            Description = "Bộ quy tắc mặc định Danny ver5.7 — kết nối Internet trái phép & lộ lọt tài liệu"
        };

        // --- Nhom A: Ket noi Internet trai phep ---
        s.Rules.Add(new ForensicRule
        {
            Id = "NET-001",
            Title = "Default gateway lạ (ngoài dải nội bộ)",
            Description = "Default gateway trỏ về dải IP không thuộc mạng nội bộ quân sự (86.x, 172.x nội bộ).",
            Severity = Severity.High,
            Category = IncidentCategory.UnauthorizedInternet,
            Score = 25,
            ArtifactSource = "network",
            MatchPattern = @"Gateway:\s*(?!86\.|172\.|10\.|192\.168\.)",
            Recommendation = "Kiểm tra lại cấu hình card mạng; đối chiếu danh sách gateway đơn vị."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "NET-002",
            Title = "DNS ngoài vùng cho phép",
            Description = "Máy dùng DNS server công cộng thay vì DNS quân sự 86.0.188.1.",
            Severity = Severity.Medium,
            Category = IncidentCategory.UnauthorizedInternet,
            Score = 15,
            ArtifactSource = "network",
            Contains = "DNS Servers",
            NotContains = "86.0.188.1",
            Recommendation = "Khôi phục DNS quân sự 86.0.188.1 và khóa thay đổi bằng Group Policy."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "NET-003",
            Title = "Adapter ảo / RNDIS / USB tethering",
            Description = "Phát hiện card mạng ảo hoặc thiết bị chia sẻ kết nối USB (RNDIS).",
            Severity = Severity.High,
            Category = IncidentCategory.UnauthorizedInternet,
            Score = 25,
            ArtifactSource = "network",
            MatchPattern = @"(?i)(RNDIS|Remote NDIS|Wireless|802\.11|Virtual|TAP-|VPN|Hyper-V|Loopback)",
            Recommendation = "Tắt và gỡ card mạng ảo/tethering không được phép; kiểm tra chính sách mạng."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "NET-004",
            Title = "Công cụ tunneling / proxy / remote",
            Description = "Tiến trình đáng ngờ thường dùng để đường vượt kiểm soát hoặc truy cập từ xa.",
            Severity = Severity.Critical,
            Category = IncidentCategory.UnauthorizedInternet,
            Score = 40,
            ArtifactSource = "process",
            MatchPattern = @"(?i)(ngrok|cloudflared|frpc|frps|localtunnel|chisel|socat|ncat|plink|proxychains|ssh -R|socks|tun2socks)",
            Recommendation = "Kết thúc tiến trình, thu giữ bộ nhớ và image đĩa, rà soát máy lân cận."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "NET-005",
            Title = "Cổng nghe bất thường",
            Description = "Dịch vụ đang lắng nghe trên cổng không thuộc danh sách thông thường.",
            Severity = Severity.Medium,
            Category = IncidentCategory.UnauthorizedInternet,
            Score = 15,
            ArtifactSource = "network",
            MatchPattern = @"(?i)LISTEN.*:(4444|5555|6666|7777|8888|1080|3128|8080|8443|9001|4443|1337)",
            Recommendation = "Xác định tiến trình sở hữu cổng; đóng nếu không có phép."
        });

        // --- Nhom B: Lo rot tai lieu ---
        s.Rules.Add(new ForensicRule
        {
            Id = "EXF-001",
            Title = "Dấu vết nén/mã hóa tập hợp tài liệu",
            Description = "Phát hiện file nén/mã hóa (7z, rar, zip, tar) — dấu hiệu chuẩn bị gửi dữ liệu ra ngoài.",
            Severity = Severity.Medium,
            Category = IncidentCategory.DataExfiltration,
            Score = 20,
            ArtifactSource = "file",
            MatchPattern = @"(?i)\.(7z|rar|zip|tar|gz|bz2|xz|enc|encrypted|crypt)\b",
            Recommendation = "Kiểm tra nội dung file nén; thu giữ nếu chứa tài liệu mật."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "EXF-002",
            Title = "Dấu vết dịch vụ đám mây lưu trữ",
            Description = "Có thư mục đồng bộ của cloud drive (OneDrive, Google Drive, Dropbox...).",
            Severity = Severity.Low,
            Category = IncidentCategory.DataExfiltration,
            Score = 10,
            ArtifactSource = "file",
            MatchPattern = @"(?i)(OneDrive|Google Drive|GoogleDrive|Dropbox|Box Sync|Mega|Nextcloud|Seafile)",
            Recommendation = "Đánh giá tài liệu đã đồng bộ lên dịch vụ lưu trữ ngoài Internet."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "EXF-003",
            Title = "Thiết bị lưu trữ gắn ngoài (USBSTOR)",
            Description = "Có dấu vết cắm USB — có thể dùng làm bước trung gian để mang tài liệu ra.",
            Severity = Severity.Medium,
            Category = IncidentCategory.DataExfiltration,
            Score = 15,
            ArtifactSource = "registry",
            Contains = "USBSTOR",
            Recommendation = "Đối chiếu danh sách USB được phép; thu giữ ổ USB gắn gần đó."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "EXF-004",
            Title = "Truy cập dịch vụ lưu trữ / gửi file trên web",
            Description = "Lịch sử trình duyệt có dấu hiệu truy cập dịch vụ upload tài liệu.",
            Severity = Severity.High,
            Category = IncidentCategory.DataExfiltration,
            Score = 25,
            ArtifactSource = "browser",
            MatchPattern = @"(?i)(drive\.google|dropbox\.com|onedrive\.live|box\.com|mega\.nz|wetransfer|sendspace|filebin|transfer\.sh|filecrypt|we\.transfer)",
            Recommendation = "Thu giữ lịch sử trình duyệt, cookie, profile và ảnh đĩa để xác định tài liệu đã tải lên."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "EXF-005",
            Title = "Ứng dụng nhắn tin / VoIP có gửi tệp",
            Description = "Có bản ghi của ứng dụng nhắn tin (Telegram, Zalo, Discord...).",
            Severity = Severity.Medium,
            Category = IncidentCategory.DataExfiltration,
            Score = 15,
            ArtifactSource = "file",
            MatchPattern = @"(?i)(Telegram Desktop|tdata|ZaloData|Discord|Element|Signal)",
            Recommendation = "Thu giữ thư mục dữ liệu ứng dụng nhắn tin để đối chiếu tệp đã gửi."
        });

        // --- Nhom C: Anti-forensics ---
        s.Rules.Add(new ForensicRule
        {
            Id = "AFR-001",
            Title = "Dấu vết xóa nhật ký sự kiện",
            Description = "Nhật ký Windows bị xóa hoặc không thể đọc — dấu hiệu anti-forensics.",
            Severity = Severity.Critical,
            Category = IncidentCategory.AntiForensics,
            Score = 40,
            ArtifactSource = "eventlog",
            MatchPattern = @"(?i)(EventLog.*Cleared|Event ID 104|1102|audit log cleared|nhat ky da bi xoa)",
            Recommendation = "Coi máy là hiện trường: thu giữ ổ đĩa, không khởi động lại, thu thập từ máy khác."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "AFR-002",
            Title = "Lịch sử trình duyệt bị xóa",
            Description = "Không tìm thấy tệp History của trình duyệt dù có dấu vết cài đặt.",
            Severity = Severity.High,
            Category = IncidentCategory.AntiForensics,
            Score = 30,
            ArtifactSource = "browser",
            MatchPattern = @"(?i)(History.*(khong ton tai|not found|missing)|da bi xoa)",
            Recommendation = "Đối chiếu với cache còn sót, $UsnJrnl, Jump Lists để tái dựng lịch sử."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "AFR-003",
            Title = "Dịch vụ giám sát bị tắt",
            Description = "Service EDR/AV không chạy — có thể đã bị vô hiệu hóa cố ý.",
            Severity = Severity.High,
            Category = IncidentCategory.AntiForensics,
            Score = 25,
            ArtifactSource = "service",
            MatchPattern = @"(?i)(MiAV|Defender|WinDefend|Sysmon|SentinelOne|CrowdStrike|Kaspersky).*(STOPPED|not running|dang tat)",
            Recommendation = "Khôi phục dịch vụ, kiểm tra trạng thái và cấu hình MiAV/EDR trên máy."
        });

        // --- Nhom D: Hoat dong bat thuong ---
        s.Rules.Add(new ForensicRule
        {
            Id = "SUS-001",
            Title = "Script PowerShell bị tắt hoặc có thao tác ẩn",
            Description = "PowerShell với bypass hoặc nội dung bị mã hóa.",
            Severity = Severity.High,
            Category = IncidentCategory.SuspiciousActivity,
            Score = 25,
            ArtifactSource = "process",
            MatchPattern = @"(?i)(powershell.*(-enc|-nop|-w hidden|-ep bypass)|FromBase64String|Invoke-Expression)",
            Recommendation = "Thu giữ script, prefetch, PowerShell Operational log và kiểm tra hash tệp."
        });
        s.Rules.Add(new ForensicRule
        {
            Id = "SUS-002",
            Title = "Tác vụ lên lịch không rõ nguồn gốc",
            Description = "Scheduled Task không thuộc phần mềm được phép.",
            Severity = Severity.Medium,
            Category = IncidentCategory.SuspiciousActivity,
            Score = 20,
            ArtifactSource = "process",
            MatchPattern = "(?i)\\\\[(Microsoft|Windows|System)\\\\]",
            Recommendation = "Đối chiếu danh sách task hợp lệ; lấy XML task để xác định lệnh thực thi."
        });

        return s;
    }

    /// <summary>Xuất quy tắc ra JSON (dùng để tạo file mặc định).</summary>
    public static string ToJson(RuleSet set)
    {
        var opts = new JsonSerializerOptions
        {
            WriteIndented = true,
            Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping
        };
        return JsonSerializer.Serialize(set, opts);
    }
}
