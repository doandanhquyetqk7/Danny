using System;
using System.Collections.Generic;
using System.Linq;

namespace NetSecTool.Forensic;

/// <summary>
/// Dòng thời gian & tương quan hành vi.
///
/// <para>Hợp nhất sự kiện từ nhiều nguồn về một trục thời gian chuẩn hóa
/// (mili-giây) và tự động làm nổi bật chuỗi hành vi đáng ngờ:</para>
///
/// <para>[Truy cập / sửa tài liệu] → [Đóng gói / nén / đổi tên]
/// → [Thiết lập kết nối ra ngoài] → [Truyền dữ liệu đi]</para>
/// </summary>
public static class TimelineEngine
{
    /// <summary>Các chặng trong chuỗi hành vi đáng ngờ.</summary>
    private static readonly (string Chain, string Label)[] ChainStages =
    {
        ("ACCESS", "Truy cập / sửa tài liệu"),
        ("STAGE", "Đóng gói / nén / đổi tên"),
        ("CONNECT", "Thiết lập kết nối ra ngoài"),
        ("EXFIL", "Truyền dữ liệu đi")
    };

    /// <summary>
    /// Xây dựng dòng thời gian từ bundle và gắn nhãn chuỗi hành vi.
    /// </summary>
    public static List<TimelineEvent> Build(EvidenceBundle bundle)
    {
        var events = new List<TimelineEvent>();

        // 1. Artifact có mốc thời gian (file) -> sự kiện
        foreach (Artifact art in bundle.Artifacts)
        {
            if (art.ModifiedUtc == DateTime.MinValue) continue;

            string chain = ClassifyArtifact(art);
            events.Add(new TimelineEvent
            {
                TimestampUtc = art.ModifiedUtc,
                Source = art.Source,
                Description = art.Category,
                Artifact = art.Path,
                Severity = Severity.Info,
                Chain = chain
            });
        }

        // 2. Phát hiện (findings) -> sự kiện mức nghi ngờ
        foreach (Finding f in bundle.Findings)
        {
            if (f.TimestampUtc == DateTime.MinValue) continue;
            events.Add(new TimelineEvent
            {
                TimestampUtc = f.TimestampUtc,
                Source = "finding",
                Description = "[" + f.RuleId + "] " + f.Title,
                Artifact = f.Artifact,
                Severity = f.Severity,
                Chain = f.Category == IncidentCategory.DataExfiltration ? "EXFIL"
                      : f.Category == IncidentCategory.UnauthorizedInternet ? "CONNECT"
                      : f.Category == IncidentCategory.AntiForensics ? "ACCESS"
                      : ""
            });
        }

        // 3. Sắp xếp theo thời gian
        events = events.OrderBy(e => e.TimestampUtc).ToList();

        // 4. Gắn nhãn chuỗi hành vi — tìm chuỗi đầy đủ 4 chặng trong cửa sổ thời gian
        MarkBehaviorChains(events);

        return events;
    }

    /// <summary>Phân loại artifact theo chặng hành vi.</summary>
    private static string ClassifyArtifact(Artifact art)
    {
        string text = art.Category + " " + art.Path;

        if (text.IndexOf("Archive", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf("staging", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf(".7z", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf(".rar", StringComparison.OrdinalIgnoreCase) >= 0 ||
            text.IndexOf(".zip", StringComparison.OrdinalIgnoreCase) >= 0)
            return "STAGE";

        if (art.Source == "network" || art.Source == "browser")
            return "EXFIL";

        if (art.Source == "file" && (text.IndexOf("Prefetch", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     text.IndexOf("Jump List", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                     text.IndexOf("Recent", StringComparison.OrdinalIgnoreCase) >= 0))
            return "ACCESS";

        if (art.Source == "registry" && text.IndexOf("USBSTOR", StringComparison.OrdinalIgnoreCase) >= 0)
            return "ACCESS";

        return "";
    }

    /// <summary>
    /// Tìm và đánh dấu các chuỗi hành vi hoàn chỉnh
    /// (ACCESS → STAGE → CONNECT → EXFIL) trong một cửa sổ thời gian.
    /// </summary>
    private static void MarkBehaviorChains(List<TimelineEvent> events)
    {
        // Cửa sổ tối đa giữa hai sự kiện trong chuỗi: 24 giờ
        TimeSpan window = TimeSpan.FromHours(24);

        var byChain = events
            .Where(e => e.Chain.Length > 0)
            .GroupBy(e => e.Chain)
            .ToDictionary(g => g.Key, g => g.OrderBy(e => e.TimestampUtc).ToList());

        if (!byChain.ContainsKey("ACCESS") || !byChain.ContainsKey("STAGE") ||
            !byChain.ContainsKey("CONNECT") || !byChain.ContainsKey("EXFIL"))
            return;

        var access = byChain["ACCESS"];
        var stage = byChain["STAGE"];
        var connect = byChain["CONNECT"];
        var exfil = byChain["EXFIL"];

        foreach (TimelineEvent a in access)
        {
            foreach (TimelineEvent s in stage)
            {
                if (s.TimestampUtc <= a.TimestampUtc) continue;
                if (s.TimestampUtc - a.TimestampUtc > window) continue;

                foreach (TimelineEvent c in connect)
                {
                    if (c.TimestampUtc <= s.TimestampUtc) continue;
                    if (c.TimestampUtc - s.TimestampUtc > window) continue;

                    foreach (TimelineEvent e in exfil)
                    {
                        if (e.TimestampUtc <= c.TimestampUtc) continue;
                        if (e.TimestampUtc - c.TimestampUtc > window) continue;

                        // Tìm thấy chuỗi đầy đủ — đánh dấu cả 4 sự kiện
                        string tag = "CHUỖI NGHI NGỜ: " + string.Join(" → ", ChainStages.Select(x => x.Label));
                        a.Chain = tag; a.Severity = Severity.High;
                        s.Chain = tag; s.Severity = Severity.High;
                        c.Chain = tag; c.Severity = Severity.Critical;
                        e.Chain = tag; e.Severity = Severity.Critical;
                        return;
                    }
                }
            }
        }
    }

    /// <summary>Chuyển timeline ra dạng văn bản (Markdown / CSV).</summary>
    public static string ToMarkdown(List<TimelineEvent> events)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("| Thời gian (UTC) | Nguồn | Mức độ | Chuỗi | Mô tả | Artifact |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (TimelineEvent e in events)
        {
            string ts = e.TimestampUtc == DateTime.MinValue ? "-" : e.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss");
            string sev = e.Severity.ToString();
            string chain = e.Chain.Length > 0 ? e.Chain : "-";
            sb.AppendLine($"| {ts} | {e.Source} | {sev} | {chain} | {Escape(e.Description)} | `{Escape(e.Artifact)}` |");
        }
        return sb.ToString();
    }

    /// <summary>Chuyển timeline ra CSV.</summary>
    public static string ToCsv(List<TimelineEvent> events)
    {
        var sb = new System.Text.StringBuilder();
        sb.AppendLine("TimestampUtc,Source,Severity,Chain,Description,Artifact");
        foreach (TimelineEvent e in events)
        {
            string ts = e.TimestampUtc == DateTime.MinValue ? "" : e.TimestampUtc.ToString("o");
            sb.AppendLine(string.Join(",",
                Csv(ts), Csv(e.Source), Csv(e.Severity.ToString()),
                Csv(e.Chain), Csv(e.Description), Csv(e.Artifact)));
        }
        return sb.ToString();
    }

    private static string Csv(string s)
    {
        if (s == null) return "";
        if (s.Contains(',') || s.Contains('"') || s.Contains('\n'))
            return "\"" + s.Replace("\"", "\"\"") + "\"";
        return s;
    }

    private static string Escape(string s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("|", "\\|").Replace("\n", " ").Replace("\r", "");
    }
}
