using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace NetSecTool.Forensic;

/// <summary>
/// Phân tích và phát hiện bất thường theo bộ quy tắc cấu hình ngoài.
///
/// <para>Quy tắc lấy từ <c>tools/rules/forensic-rules.json</c> (nếu có) —
/// cho phép đơn vị tự bổ sung quy tắc mà không cần sửa mã nguồn.
/// Nếu không có file thì dùng bộ mặc định tích hợp.</para>
///
/// <para>Mỗi phát hiện đều kèm bằng chứng cụ thể (artifact + đoạn khớp)
/// để điều tra viên có thể kiểm chứng.</para>
/// </summary>
public static class RuleEngine
{
    /// <summary>Phân tích toàn bộ artifact theo bộ quy tắc, trả về danh sách phát hiện.</summary>
    public static List<Finding> Analyze(EvidenceBundle bundle, RuleSet rules)
    {
        var findings = new List<Finding>();

        foreach (ForensicRule rule in rules.Rules)
        {
            if (!rule.Enabled) continue;

            foreach (Artifact art in bundle.Artifacts)
            {
                if (rule.ArtifactSource != null &&
                    !art.Source.Equals(rule.ArtifactSource, StringComparison.OrdinalIgnoreCase))
                    continue;

                string haystack = BuildHaystack(art);
                if (haystack.Length == 0) continue;

                if (rule.Contains != null &&
                    haystack.IndexOf(rule.Contains, StringComparison.OrdinalIgnoreCase) < 0)
                    continue;
                if (rule.NotContains != null &&
                    haystack.IndexOf(rule.NotContains, StringComparison.OrdinalIgnoreCase) >= 0)
                    continue;

                List<string> matches = new();
                try
                {
                    string pat = rule.MatchPattern ?? rule.Pattern ?? "";
                    if (pat.Length > 0)
                    {
                        var rx = new Regex(pat,
                            RegexOptions.IgnoreCase | RegexOptions.Multiline,
                            TimeSpan.FromSeconds(2));
                        foreach (Match m in rx.Matches(haystack))
                        {
                            string snippet = m.Value.Trim();
                            if (snippet.Length > 200) snippet = snippet.Substring(0, 200) + "...";
                            matches.Add(snippet);
                            if (matches.Count >= 5) break;
                        }
                    }
                    else
                    {
                        matches.Add("Khớp theo điều kiện Contains/NotContains");
                    }
                }
                catch (Exception ex)
                {
                    findings.Add(new Finding
                    {
                        RuleId = rule.Id,
                        Title = "LỖI QUY TẮC: " + rule.Title,
                        Explanation = "Không biên dịch được biểu thức chính quy: " + ex.Message,
                        Severity = Severity.Info,
                        Category = IncidentCategory.SuspiciousActivity,
                        Artifact = art.Path,
                        Score = 0
                    });
                    continue;
                }

                if (matches.Count == 0) continue;

                // Tránh báo trùng: cùng rule + cùng artifact → chỉ giữ 1 phát hiện
                if (findings.Any(f => f.RuleId == rule.Id && f.Artifact == art.Path))
                    continue;

                var finding = new Finding
                {
                    RuleId = rule.Id,
                    Title = rule.Title,
                    Explanation = rule.Description,
                    Severity = rule.Severity,
                    Category = rule.Category,
                    Artifact = string.IsNullOrEmpty(art.Path) ? art.Category : art.Path,
                    TimestampUtc = art.ModifiedUtc,
                    Score = rule.Score
                };
                finding.Evidence.Add("Artifact: " + art.Category +
                    (string.IsNullOrEmpty(art.Path) ? "" : " → " + art.Path));
                finding.Evidence.Add("SHA-256: " +
                    (art.Sha256.Length > 0 ? art.Sha256 : "(không băm được)"));
                foreach (string m in matches)
                    finding.Evidence.Add("Khớp: " + m);
                if (rule.Recommendation.Length > 0)
                    finding.Evidence.Add("Khuyến nghị: " + rule.Recommendation);

                findings.Add(finding);
            }
        }

        return findings;
    }

    /// <summary>Tạo chuỗi để quét quy tắc từ artifact.</summary>
    private static string BuildHaystack(Artifact art)
    {
        if (art.Kind_ == "file") return art.Path;
        return art.Category + "\n" + art.ContentPreview;
    }

    /// <summary>Tính điểm nghi ngờ tổng thể (0-100) và kết luận.</summary>
    public static int Score(EvidenceBundle bundle, out string verdict)
    {
        int raw = 0;
        foreach (Finding f in bundle.Findings)
        {
            int weight = f.Severity switch
            {
                Severity.Critical => 40,
                Severity.High => 25,
                Severity.Medium => 12,
                Severity.Low => 5,
                _ => 0
            };
            raw += Math.Max(weight, f.Score);
        }

        // Chuẩn hóa để tránh một lỗi nhỏ làm điểm vượt ngưỡng
        int score = bundle.Findings.Count == 0
            ? 0
            : (int)Math.Min(100, Math.Round(100 * (1 - 1.0 / (1 + raw / 25.0))));

        int critical = bundle.Findings.Count(f => f.Severity == Severity.Critical);
        int high = bundle.Findings.Count(f => f.Severity == Severity.High);

        if (bundle.Findings.Count == 0)
            verdict = "KHÔNG phát hiện dấu hiệu bất thường từ các nguồn đã thu thập. " +
                      "Lưu ý: kết luận chỉ có giá trị trong phạm vi artifact đã thu thập.";
        else if (critical > 0)
            verdict = "NGHI NGỜ CAO — có phát hiện mức CRITICAL. Cần cô lập máy ngay và thu giữ chứng cứ.";
        else if (high > 0)
            verdict = "NGHI NGỜ TRUNG BỌ-CAO — có phát hiện mức HIGH. Cần điều tra sâu và rà soát máy lân cận.";
        else
            verdict = "NGHI NGỜ THẤP — chỉ có phát hiện mức Medium/Low. Tiếp tục theo dõi.";

        return score;
    }
}
