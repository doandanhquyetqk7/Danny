using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace NetSecTool.Forensic;

/// <summary>
/// Xuất báo cáo và đóng gói gói chứng cứ.
///
/// <para>Định dạng hỗ trợ:
///   • HTML    — báo cáo trực quan, mở bằng trình duyệt, in được
///   • Markdown — phục vụ bàn giao / dán vào hồ sơ
///   • JSON    — dữ liệu có cấu trúc cho máy phân tích
///   • CSV     — timeline dạng bảng tính</para>
///
/// <para>Gói chứng cứ gồm: dữ liệu thô + báo cáo + <c>manifest.sha256</c>
/// (danh sách hash chống sửa đổi).</para>
/// </summary>
public static class ReportWriter
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping
    };

    /// <summary>Ghi toàn bộ báo cáo + manifest vào thư mục gói chứng cứ.</summary>
    public static void WritePack(EvidenceBundle bundle, string outputDir)
    {
        Directory.CreateDirectory(outputDir);
        string rawDir = Path.Combine(outputDir, "raw");
        Directory.CreateDirectory(rawDir);

        File.WriteAllText(Path.Combine(rawDir, "evidence.json"),
            JsonSerializer.Serialize(bundle, JsonOpts), Encoding.UTF8);

        File.WriteAllText(Path.Combine(outputDir, "Bao-cao-dieu-tra.html"),
            ToHtml(bundle), Encoding.UTF8);
        File.WriteAllText(Path.Combine(outputDir, "Bao-cao-dieu-tra.md"),
            ToMarkdown(bundle), Encoding.UTF8);
        File.WriteAllText(Path.Combine(outputDir, "Dong-thoi-gian.csv"),
            TimelineEngine.ToCsv(bundle.Timeline), Encoding.UTF8);

        WriteManifest(outputDir);
    }

    /// <summary>Tạo manifest.sha256 cho mọi tệp trong gói chứng cứ.</summary>
    public static void WriteManifest(string outputDir)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# Danny ver5.7 - Manifest chung cu (SHA-256)");
        sb.AppendLine("# Dinh dang: <SHA256>  <duong dan tuong doi>");
        sb.AppendLine($"# Tao luc (UTC): {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"# May thu thap: {Environment.MachineName}");
        sb.AppendLine();

        foreach (string file in Directory.EnumerateFiles(outputDir, "*", SearchOption.AllDirectories)
                                          .OrderBy(f => f, StringComparer.OrdinalIgnoreCase))
        {
            if (Path.GetFileName(file).Equals("manifest.sha256", StringComparison.OrdinalIgnoreCase))
                continue;
            string? hash = EvidenceCollector.Sha256File(file);
            if (hash == null) continue;
            string rel = Path.GetRelativePath(outputDir, file).Replace('\\', '/');
            sb.AppendLine($"{hash}  {rel}");
        }

        File.WriteAllText(Path.Combine(outputDir, "manifest.sha256"), sb.ToString(), Encoding.UTF8);
    }

    // ==================================================================
    //  MARKDOWN
    // ==================================================================
    /// <summary>Sinh báo cáo Markdown.</summary>
    public static string ToMarkdown(EvidenceBundle bundle)
    {
        var sb = new StringBuilder();

        sb.AppendLine("# BÁO CÁO ĐIỀU TRA CHỨNG CỨ SỐ");
        sb.AppendLine();
        sb.AppendLine("**Công cụ:** Danny ver5.7 — Kiểm tra An Toàn Thông Tin (Forensic DFIR)  ");
        sb.AppendLine($"**Máy thu thập:** {bundle.MachineName} (`{bundle.UserName}`)  ");
        sb.AppendLine($"**Hệ điều hành:** {bundle.OperatingSystem}  ");
        sb.AppendLine($"**Thời điểm thu thập (UTC):** {bundle.CollectionUtc}  ");
        sb.AppendLine($"**Thời điểm thu thập (giờ máy):** {bundle.CollectionLocal}  ");
        sb.AppendLine($"**Chế độ:** {bundle.CollectionMode}  ");
        sb.AppendLine($"**Điểm nghi ngờ:** **{bundle.TotalScore}/100**");
        sb.AppendLine();

        sb.AppendLine("## 1. TÓM TẮT ĐIỀU HÀNH");
        sb.AppendLine();
        sb.AppendLine(bundle.Verdict);
        sb.AppendLine();
        sb.AppendLine("| Chỉ số | Giá trị |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| Tổng số phát hiện | {bundle.Findings.Count} |");
        sb.AppendLine($"| Phát hiện CRITICAL | {bundle.Findings.Count(f => f.Severity == Severity.Critical)} |");
        sb.AppendLine($"| Phát hiện HIGH | {bundle.Findings.Count(f => f.Severity == Severity.High)} |");
        sb.AppendLine($"| Phát hiện MEDIUM | {bundle.Findings.Count(f => f.Severity == Severity.Medium)} |");
        sb.AppendLine($"| Phát hiện LOW | {bundle.Findings.Count(f => f.Severity == Severity.Low)} |");
        sb.AppendLine($"| Số artifact thu thập | {bundle.Artifacts.Count} |");
        sb.AppendLine($"| Số sự kiện trên timeline | {bundle.Timeline.Count} |");
        sb.AppendLine();

        sb.AppendLine("## 2. HỒ SƠ MÁY TÍNH & MÔI TRƯỜNG MẠNG");
        sb.AppendLine();
        sb.AppendLine("| Thuộc tính | Giá trị |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| Tên máy | {bundle.MachineName} |");
        sb.AppendLine($"| Người đang đăng nhập | {bundle.UserName} |");
        sb.AppendLine($"| Hệ điều hành | {bundle.OperatingSystem} |");
        sb.AppendLine();

        sb.AppendLine("## 3. DANH SÁCH CHỈ BÁO (IOC) & PHÁT HIỆN");
        sb.AppendLine();
        if (bundle.Findings.Count == 0)
        {
            sb.AppendLine("_Không có phát hiện nào khớp quy tắc._");
        }
        else
        {
            foreach (Finding f in bundle.Findings)
            {
                sb.AppendLine($"### [{f.RuleId}] {f.Title}");
                sb.AppendLine();
                sb.AppendLine($"- **Mức độ:** {f.Severity}");
                sb.AppendLine($"- **Nhóm:** {f.Category}");
                sb.AppendLine($"- **Mô tả:** {f.Explanation}");
                sb.AppendLine($"- **Artifact gốc:** `{f.Artifact}`");
                sb.AppendLine($"- **Thời điểm (UTC):** {(f.TimestampUtc == DateTime.MinValue ? "—" : f.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss"))}");
                sb.AppendLine();
                sb.AppendLine("**Bằng chứng:**");
                sb.AppendLine();
                foreach (string e in f.Evidence)
                    sb.AppendLine($"- {e}");
                sb.AppendLine();
            }
        }

        sb.AppendLine("## 4. DÒNG THỜI GIAN SỰ KIỆN");
        sb.AppendLine();
        sb.AppendLine(TimelineEngine.ToMarkdown(bundle.Timeline));
        sb.AppendLine();

        sb.AppendLine("## 5. DANH MỤC ARTIFACT ĐÃ THU THẬP");
        sb.AppendLine();
        sb.AppendLine("| Nguồn | Phân loại | Đường dẫn | Kích thước | Sửa lần cuối (UTC) | SHA-256 |");
        sb.AppendLine("|---|---|---|---|---|---|");
        foreach (Artifact a in bundle.Artifacts.Take(500))
        {
            sb.AppendLine($"| {a.Source} | {a.Category} | `{a.Path}` | {a.SizeBytes} | " +
                          $"{(a.ModifiedUtc == DateTime.MinValue ? "—" : a.ModifiedUtc.ToString("yyyy-MM-dd HH:mm:ss"))} | " +
                          $"{(a.Sha256.Length >= 16 ? a.Sha256.Substring(0, 16) + "…" : a.Sha256)} |");
        }
        if (bundle.Artifacts.Count > 500)
            sb.AppendLine($"\n_… và {bundle.Artifacts.Count - 500} artifact khác (xem raw/evidence.json)_");
        sb.AppendLine();

        sb.AppendLine("## 6. KHUYẾN NGHỊ XỬ LÝ TIẾP THEO");
        sb.AppendLine();
        var recs = bundle.Findings
            .SelectMany(f => f.Evidence.Where(e => e.StartsWith("Khuyến nghị:")))
            .Select(e => e.Substring("Khuyến nghị:".Length).Trim())
            .Distinct().ToList();

        if (recs.Count == 0)
        {
            sb.AppendLine("- Tiếp tục theo dõi định kỳ; bổ sung quy tắc trong `tools/rules/forensic-rules.json` theo đặc thù đơn vị.");
        }
        else
        {
            foreach (string r in recs) sb.AppendLine($"- {r}");
        }
        sb.AppendLine();
        sb.AppendLine("**Hành động chuẩn khi có dấu hiệu nghi ngờ cao:**");
        sb.AppendLine();
        sb.AppendLine("1. **Cô lập máy** — ngắt mạng (không cắt nguồn), giữ nguyên trạng thái để giữ volatile data.");
        sb.AppendLine("2. **Thu giữ ổ đĩa** — chụp image bằng dd/Guymager, không khởi động lại máy.");
        sb.AppendLine("3. **Rà soát máy lân cận** — cùng dải mạng, cùng đơn vị, đặc biệt các máy dùng chung tài khoản.");
        sb.AppendLine("4. **Ghi nhận chuỗi bảo toàn** — lưu manifest.sha256 kèm hồ sơ bàn giao.");
        sb.AppendLine();

        sb.AppendLine("## 7. HẠN CHẾ KỸ THUẬT");
        sb.AppendLine();
        foreach (string l in bundle.Limitations) sb.AppendLine($"- {l}");
        sb.AppendLine();

        if (bundle.CollectorErrors.Count > 0)
        {
            sb.AppendLine("## 8. LỖI THU THẬP");
            sb.AppendLine();
            foreach (string e in bundle.CollectorErrors.Take(50)) sb.AppendLine($"- {e}");
            if (bundle.CollectorErrors.Count > 50)
                sb.AppendLine($"- … và {bundle.CollectorErrors.Count - 50} lỗi khác.");
            sb.AppendLine();
        }

        return sb.ToString();
    }

    // ==================================================================
    //  HTML
    // ==================================================================
    /// <summary>Sinh báo cáo HTML (tự chứa, mở trực tiếp bằng trình duyệt).</summary>
    public static string ToHtml(EvidenceBundle bundle)
    {
        var sb = new StringBuilder();
        sb.AppendLine("<!DOCTYPE html>");
        sb.AppendLine("<html lang=\"vi\"><head><meta charset=\"utf-8\">");
        sb.AppendLine("<title>Báo cáo điều tra chứng cứ — " + Html(bundle.MachineName) + "</title>");
        sb.AppendLine("<style>");
        sb.AppendLine("body{font-family:'Segoe UI',Arial,sans-serif;margin:0;padding:24px;background:#f4f6f2;color:#1c221d;}");
        sb.AppendLine("h1{color:#174a2c;border-bottom:3px solid #d6b03a;padding-bottom:8px;}");
        sb.AppendLine("h2{color:#22683e;margin-top:28px;border-left:5px solid #d6b03a;padding-left:10px;}");
        sb.AppendLine("h3{color:#9e1616;margin-top:20px;}");
        sb.AppendLine("table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px;background:#fff;}");
        sb.AppendLine("th,td{border:1px solid #cfd6cc;padding:6px 8px;text-align:left;vertical-align:top;}");
        sb.AppendLine("th{background:#174a2c;color:#fff;}");
        sb.AppendLine("tr:nth-child(even) td{background:#fafbf8;}");
        sb.AppendLine("code{background:#eef1ea;padding:1px 5px;border-radius:3px;font-family:Consolas,monospace;font-size:12px;}");
        sb.AppendLine(".verdict{background:#fff;border-left:6px solid #d6b03a;padding:14px 18px;margin:16px 0;font-size:15px;}");
        sb.AppendLine(".score{font-size:34px;font-weight:bold;color:#9e1616;}");
        sb.AppendLine(".badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:bold;color:#fff;}");
        sb.AppendLine(".sev-Critical{background:#9e1616;}.sev-High{background:#c4621e;}.sev-Medium{background:#b09418;}.sev-Low{background:#4a7c50;}");
        sb.AppendLine(".chain{background:#f8d7d7;font-weight:bold;}");
        sb.AppendLine("ul{padding-left:22px;}li{margin:4px 0;}");
        sb.AppendLine("</style></head><body>");

        sb.AppendLine("<h1>BÁO CÁO ĐIỀU TRA CHỨNG CỨ SỐ</h1>");
        sb.AppendLine("<table><tr><th>Thuộc tính</th><th>Giá trị</th></tr>");
        sb.AppendLine("<tr><td>Công cụ</td><td>Danny ver5.7 — Kiểm tra An Toàn Thông Tin (Forensic DFIR)</td></tr>");
        sb.AppendLine($"<tr><td>Máy thu thập</td><td>{Html(bundle.MachineName)} ({Html(bundle.UserName)})</td></tr>");
        sb.AppendLine($"<tr><td>Hệ điều hành</td><td>{Html(bundle.OperatingSystem)}</td></tr>");
        sb.AppendLine($"<tr><td>Thời điểm thu thập (UTC)</td><td>{Html(bundle.CollectionUtc)}</td></tr>");
        sb.AppendLine($"<tr><td>Thời điểm thu thập (giờ máy)</td><td>{Html(bundle.CollectionLocal)}</td></tr>");
        sb.AppendLine($"<tr><td>Chế độ</td><td>{Html(bundle.CollectionMode)}</td></tr>");
        sb.AppendLine($"<tr><td>Gói chứng cứ</td><td><code>{Html(bundle.OutputDirectory)}</code></td></tr>");
        sb.AppendLine("</table>");

        sb.AppendLine("<div class=\"verdict\">");
        sb.AppendLine($"<div class=\"score\">{bundle.TotalScore}<span style=\"font-size:16px\">/100</span></div>");
        sb.AppendLine("<p>" + Html(bundle.Verdict) + "</p>");
        sb.AppendLine("</div>");

        sb.AppendLine("<h2>1. Tóm tắt điều hành</h2>");
        sb.AppendLine("<table><tr><th>Mức độ</th><th>Số phát hiện</th></tr>");
        foreach (Severity sev in new[] { Severity.Critical, Severity.High, Severity.Medium, Severity.Low })
        {
            int n = bundle.Findings.Count(f => f.Severity == sev);
            sb.AppendLine($"<tr><td><span class=\"badge sev-{sev}\">{sev}</span></td><td>{n}</td></tr>");
        }
        sb.AppendLine($"<tr><td>Tổng artifact</td><td>{bundle.Artifacts.Count}</td></tr>");
        sb.AppendLine($"<tr><td>Sự kiện timeline</td><td>{bundle.Timeline.Count}</td></tr>");
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>2. Danh sách chỉ báo (IOC) và phát hiện</h2>");
        if (bundle.Findings.Count == 0)
        {
            sb.AppendLine("<p><i>Không có phát hiện nào khớp quy tắc.</i></p>");
        }
        else
        {
            foreach (Finding f in bundle.Findings)
            {
                sb.AppendLine($"<h3><span class=\"badge sev-{f.Severity}\">{f.Severity}</span> " +
                              $"[{Html(f.RuleId)}] {Html(f.Title)}</h3>");
                sb.AppendLine($"<p>{Html(f.Explanation)}</p>");
                sb.AppendLine("<ul>");
                sb.AppendLine($"<li><b>Nhóm:</b> {Html(f.Category.ToString())}</li>");
                sb.AppendLine($"<li><b>Artifact gốc:</b> <code>{Html(f.Artifact)}</code></li>");
                sb.AppendLine($"<li><b>Thời điểm (UTC):</b> " +
                              $"{(f.TimestampUtc == DateTime.MinValue ? "—" : f.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss"))}</li>");
                foreach (string e in f.Evidence) sb.AppendLine("<li>" + Html(e) + "</li>");
                sb.AppendLine("</ul>");
            }
        }

        sb.AppendLine("<h2>3. Dòng thời gian sự kiện</h2>");
        sb.AppendLine("<table><tr><th>UTC</th><th>Nguồn</th><th>Mức độ</th><th>Chuỗi</th><th>Mô tả</th><th>Artifact</th></tr>");
        foreach (TimelineEvent e in bundle.Timeline.Take(800))
        {
            string ts = e.TimestampUtc == DateTime.MinValue ? "—" : e.TimestampUtc.ToString("yyyy-MM-dd HH:mm:ss");
            string chain = e.Chain.Length > 0
                ? $"<span class=\"chain\">{Html(e.Chain)}</span>" : "—";
            sb.AppendLine($"<tr><td>{ts}</td><td>{Html(e.Source)}</td>" +
                          $"<td><span class=\"badge sev-{e.Severity}\">{e.Severity}</span></td>" +
                          $"<td>{chain}</td><td>{Html(e.Description)}</td>" +
                          $"<td><code>{Html(e.Artifact)}</code></td></tr>");
        }
        if (bundle.Timeline.Count > 800)
            sb.AppendLine($"<tr><td colspan=\"6\"><i>… và {bundle.Timeline.Count - 800} sự kiện khác</i></td></tr>");
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>4. Danh mục artifact</h2>");
        sb.AppendLine("<table><tr><th>Nguồn</th><th>Phân loại</th><th>Đường dẫn</th><th>Size</th><th>UTC</th><th>SHA-256</th></tr>");
        foreach (Artifact a in bundle.Artifacts.Take(500))
        {
            sb.AppendLine($"<tr><td>{Html(a.Source)}</td><td>{Html(a.Category)}</td>" +
                          $"<td><code>{Html(a.Path)}</code></td><td>{a.SizeBytes}</td>" +
                          $"<td>{(a.ModifiedUtc == DateTime.MinValue ? "—" : a.ModifiedUtc.ToString("yyyy-MM-dd HH:mm:ss"))}</td>" +
                          $"<td><code>{(a.Sha256.Length >= 16 ? a.Sha256.Substring(0, 16) + "…" : a.Sha256)}</code></td></tr>");
        }
        if (bundle.Artifacts.Count > 500)
            sb.AppendLine($"<tr><td colspan=\"6\"><i>… và {bundle.Artifacts.Count - 500} artifact khác</i></td></tr>");
        sb.AppendLine("</table>");

        sb.AppendLine("<h2>5. Khuyến nghị xử lý tiếp theo</h2><ul>");
        var recs = bundle.Findings
            .SelectMany(f => f.Evidence.Where(e => e.StartsWith("Khuyến nghị:")))
            .Select(e => e.Substring("Khuyến nghị:".Length).Trim())
            .Distinct().ToList();
        if (recs.Count == 0)
            sb.AppendLine("<li>Tiếp tục theo dõi định kỳ; bổ sung quy tắc trong <code>tools/rules/forensic-rules.json</code>.</li>");
        foreach (string r in recs) sb.AppendLine("<li>" + Html(r) + "</li>");
        sb.AppendLine("<li><b>Cô lập máy</b> — ngắt mạng, giữ nguyên trạng thái để giữ volatile data.</li>");
        sb.AppendLine("<li><b>Thu giữ ổ đĩa</b> — chụp image bằng dd/Guymager, không khởi động lại máy.</li>");
        sb.AppendLine("<li><b>Rà soát máy lân cận</b> — cùng dải mạng, cùng đơn vị.</li>");
        sb.AppendLine("</ul>");

        sb.AppendLine("<h2>6. Hạn chế kỹ thuật</h2><ul>");
        foreach (string l in bundle.Limitations) sb.AppendLine("<li>" + Html(l) + "</li>");
        sb.AppendLine("</ul>");

        if (bundle.CollectorErrors.Count > 0)
        {
            sb.AppendLine("<h2>7. Lỗi thu thập</h2><ul>");
            foreach (string e in bundle.CollectorErrors.Take(50)) sb.AppendLine("<li>" + Html(e) + "</li>");
            sb.AppendLine("</ul>");
        }

        sb.AppendLine("</body></html>");
        return sb.ToString();
    }

    private static string Html(string? s)
    {
        if (string.IsNullOrEmpty(s)) return "";
        return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;")
                .Replace("\"", "&quot;").Replace("\r", "").Replace("\n", "<br>");
    }
}
