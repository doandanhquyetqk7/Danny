using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace NetSecTool;

/// <summary>
/// Tim kiem don vi theo ten, ho tro tieng Viet co dau va khong dau.
///
/// Van de: nguoi dung nhap "Ban CHQS xa Lao Cai" (khong dau) trong khi ten
/// trong bang quy hoach la "Ban CHQS xa Lạc Dương" (co dau). Neu so sanh
/// chuoi thuong thi khong bao gio khop.
///
/// Giai phap: chuan hoa chuoi (bo dau, lower-case, rut gon khoang trang thua)
/// o ca hai ve: ten don vi va tu khoa nguoi dung. Sau do so sanh trên chuoi
/// da chuan hoa.
///
/// Ngoai ra con ho tro:
///
///   - Viet tat: "bchqs" -> "Ban CHQS", "td994a" -> "Trung doan 994A"
///   - Ghi chu tat: "td 994 a" -> "Trung doan 994A"
///   - Tu khoa rong: "xa", "phuong", "doan", "chqs" -> khop nhieu don vi
/// </summary>
internal static class UnitSearch
{
    /// <summary>Ket qua tim kiem: don vi + muc do khop.</summary>
    internal sealed class Hit
    {
        public IpPlan.Unit? Unit { get; init; }
        public int Score { get; init; }
        public string Reason { get; init; } = "";

        /// <summary>Ten hien thi.</summary>
        public string Name => Unit?.Name ?? "";

        /// <summary>Don vi nay co quy hoach LAN (duoc dung cho cau hinh IP) hay khong.</summary>
        public bool HasLanPlan => Unit != null;
    }

    // --- Bang tra dau tieng Viet ---
    // Khoa la chu CÓ dấu -> gia tri khong dau tuong duong.
    private static readonly Dictionary<char, string> VietnameseDiacritics = new()
    {
        // Chuyen thuong
        ['à'] = "a", ['á'] = "a", ['ả'] = "a", ['ã'] = "a", ['ạ'] = "a",
        ['ằ'] = "a", ['ắ'] = "a", ['ẳ'] = "a", ['ẵ'] = "a", ['ặ'] = "a",
        ['â'] = "a", ['ầ'] = "a", ['ấ'] = "a", ['ẩ'] = "a", ['ẫ'] = "a", ['ậ'] = "a",
        ['ă'] = "a", ['ằ'] = "a", ['ắ'] = "a", ['ẳ'] = "a", ['ẵ'] = "a", ['ặ'] = "a",
        ['è'] = "e", ['é'] = "e", ['ẻ'] = "e", ['ẽ'] = "e", ['ẹ'] = "e",
        ['ề'] = "e", ['ế'] = "e", ['ể'] = "e", ['ễ'] = "e", ['ệ'] = "e",
        ['ê'] = "e", ['î'] = "i", ['ì'] = "i", ['í'] = "i", ['ỉ'] = "i", ['ĩ'] = "i", ['ị'] = "i",
        ['ò'] = "o", ['ó'] = "o", ['ỏ'] = "o", ['õ'] = "o", ['ọ'] = "o",
        ['ồ'] = "o", ['ố'] = "o", ['ổ'] = "o", ['ỗ'] = "o", ['ộ'] = "o",
        ['ô'] = "o", ['ơ'] = "o", ['ờ'] = "o", ['ớ'] = "o", ['ở'] = "o", ['ỡ'] = "o", ['ợ'] = "o",
        ['ù'] = "u", ['ú'] = "u", ['ủ'] = "u", ['ũ'] = "u", ['ụ'] = "u",
        ['ừ'] = "u", ['ứ'] = "u", ['ử'] = "u", ['ữ'] = "u", ['ự'] = "u",
        ['ư'] = "u", ['ỳ'] = "y", ['ý'] = "y", ['ỷ'] = "y", ['ỹ'] = "y", ['ỵ'] = "y",
        ['đ'] = "d",

        // Tu phu
        ['á'] = "a", ['à'] = "a", ['ả'] = "a", ['ã'] = "a", ['ạ'] = "a",
        ['ấ'] = "a", ['ầ'] = "a", ['ẩ'] = "a", ['ẫ'] = "a", ['ậ'] = "a",
        ['ắ'] = "a", ['ằ'] = "a", ['ẳ'] = "a", ['ẵ'] = "a", ['ặ'] = "a",
        ['é'] = "e", ['è'] = "e", ['ẻ'] = "e", ['ẽ'] = "e", ['ẹ'] = "e",
        ['ế'] = "e", ['ề'] = "e", ['ể'] = "e", ['ễ'] = "e", ['ệ'] = "e",
        ['í'] = "i", ['ì'] = "i", ['ỉ'] = "i", ['ĩ'] = "i", ['ị'] = "i",
        ['ó'] = "o", ['ò'] = "o", ['ỏ'] = "o", ['õ'] = "o", ['ọ'] = "o",
        ['ố'] = "o", ['ồ'] = "o", ['ổ'] = "o", ['ỗ'] = "o", ['ộ'] = "o",
        ['ớ'] = "o", ['ờ'] = "o", ['ở'] = "o", ['ỡ'] = "o", ['ợ'] = "o",
        ['ú'] = "u", ['ù'] = "u", ['ủ'] = "u", ['ũ'] = "u", ['ụ'] = "u",
        ['ứ'] = "u", ['ừ'] = "u", ['ử'] = "u", ['ữ'] = "u", ['ự'] = "u",
        ['ý'] = "y", ['ỳ'] = "y", ['ỷ'] = "y", ['ỹ'] = "y", ['ỵ'] = "y",
        ['Đ'] = "D"
    };

    // Viet tat pho bien trong don vi quan su
    private static readonly (string Abbr, string Full)[] Abbreviations =
    {
        ("bchqs", "ban chqs"),
        ("chqs", "chqs"),
        ("bộ chqs", "bo chqs"),
        ("td", "trung doan"),
        ("trd", "trung doan"),
        ("cs", "co so"),
        ("tsqmn", "truong tsqmn"),
        ("bq", "bieu quyet"),
        ("tt", "to"),
        ("p", "phuong"),
        ("x", "xa"),
        ("dd", "don duong"),
    };

    /// <summary>
    /// Chuan hoa chuoi: bo dau tieng Viet, lower-case, rut gon khoang trang.
    /// </summary>
    public static string Normalize(string? input)
    {
        if (string.IsNullOrWhiteSpace(input)) return "";

        var sb = new StringBuilder(input.Length + 8);
        bool lastSpace = true;   // bo khoang trang dau

        foreach (char raw in input!)
        {
            char c = char.ToLower(raw);

            // Chuyen co dau -> khong dau
            if (VietnameseDiacritics.TryGetValue(c, out string? plain))
                c = plain.Length > 0 ? plain[0] : c;

            // Giu chu cai / chu so / khoang trang
            if (!char.IsLetterOrDigit(c) && c != ' ') continue;

            if (c == ' ')
            {
                if (!lastSpace) { sb.Append(' '); lastSpace = true; }
                continue;
            }

            sb.Append(c);
            lastSpace = false;
        }

        return sb.ToString().Trim();
    }

    /// <summary>
    /// Bien chuoi da chuan hoa thanh dang khong co khoang trang.
    /// Dung de so sanh khi nguoi dung nhap lien khong cach (vi du "banchqslacduong").
    /// </summary>
    private static string Compact(string normalized) =>
        normalized.Replace(" ", "");

    /// <summary>
    /// Chuan hoa co giai tri viet tat (vi du "bchqs xa lac duong" -> "ban chqs xa lac duong").
    /// </summary>
    private static string ExpandAbbreviations(string normalized)
    {
        if (normalized.Length == 0) return normalized;

        // Moi tu: tach ra, giai tri, ghep lai
        string[] words = normalized.Split(' ');
        for (int i = 0; i < words.Length; i++)
        {
            foreach (var (abbr, full) in Abbreviations)
            {
                if (words[i] != abbr) continue;

                // "bchqs" -> "ban chqs"
                if (abbr == "bchqs") { words[i] = "ban chqs"; break; }

                // "td" -> "trung doan" (chi khi khong phai dau/cuoi tu lam sai)
                if (abbr == "td" || abbr == "trd")
                {
                    words[i] = "trung doan";
                    break;
                }

                // "cs" -> "co so"
                if (abbr == "cs")
                {
                    words[i] = "co so";
                    break;
                }

                words[i] = full;
                break;
            }
        }

        return string.Join(' ', words);
    }

    /// <summary>
    /// Tra ve toan bo danh sach don vi (130 don vi co quy hoach LAN + 4 don vi chi co modem WAN).
    /// </summary>
    public static List<Hit> AllUnits(int limit = 500)
    {
        var hits = new List<Hit>();
        foreach (var u in IpPlan.All) hits.Add(new Hit { Unit = u, Score = 0, Reason = "toan bo danh sach" });
        return hits.Take(limit).ToList();
    }

    /// <summary>
    /// Tim cac don vi khop tu khoa, sap xep theo muc do phu hop giam dan.
    ///
    /// Bao gom ca don vi chi co modem WAN (khong co quy hoach LAN) de nguoi dung
    /// tim kiem khong bi bo sot don vi.
    /// </summary>
    public static List<Hit> Search(string? keyword, int limit = 50)
    {
        var raw = (keyword ?? "").Trim();
        if (raw.Length == 0) return AllUnits(limit);

        string norm = Normalize(raw);
        if (norm.Length == 0) return AllUnits(limit);

        string expanded = ExpandAbbreviations(norm);
        string normCompact = Compact(norm);
        string expCompact = Compact(expanded);

        var hits = new List<Hit>();

        foreach (var u in IpPlan.All)
        {
            string name = Normalize(u.Name);

            var (score, reason) = ScoreMatch(name, norm, expanded, normCompact, expCompact);
            if (score > 0)
            {
                hits.Add(new Hit { Unit = u, Score = score, Reason = reason });
            }
        }

        // Sap xep: diem giam dan, roi theo ten
        return hits
            .OrderByDescending(h => h.Score)
            .ThenBy(h => h.Name, StringComparer.CurrentCultureIgnoreCase)
            .Take(limit)
            .ToList();
    }

    /// <summary>
    /// Tinh diem khop giua ten don vi da chuan hoa va tu khoa da chuan hoa.
    /// </summary>
    private static (int Score, string Reason) ScoreMatch(
        string name, string norm, string expanded, string normCompact, string expCompact)
    {
        string nameCompact = Compact(name);

        // 1. Khop chinh xac toan bo ten
        if (name == norm || name == expanded ||
            nameCompact == normCompact || nameCompact == expCompact)
            return (1000, "khớp chính xác");

        // 2. Ten bat dau bang tu khoa
        if (name.StartsWith(norm, StringComparison.Ordinal) ||
            name.StartsWith(expanded, StringComparison.Ordinal) ||
            nameCompact.StartsWith(normCompact, StringComparison.Ordinal) ||
            nameCompact.StartsWith(expCompact, StringComparison.Ordinal))
            return (900, "bắt đầu bằng từ khóa");

        // 3. Tu khoa nam trong ten (theo ranh giới tu)
        if (ContainsWord(name, norm) || ContainsWord(name, expanded) ||
            ContainsWord(nameCompact, normCompact) || ContainsWord(nameCompact, expCompact))
            return (800, "từ khóa nằm trong tên");

        // 4. Ten nam trong tu khoa (nguoi dung nhap them)
        if (ContainsWord(expanded, name) || ContainsWord(norm, name))
            return (750, "tên nằm trong từ khóa");

        // 5. Moi tu trong tu khoa deu xuat hien trong ten
        if (AllWordsMatch(name, expanded) || AllWordsMatch(nameCompact, expCompact))
            return (650, "các từ đều khớp");

        // 6. Khop mot phan (vi du nhap "994" cho "Trung doan 994A")
        if (name.Contains(norm, StringComparison.Ordinal) ||
            nameCompact.Contains(normCompact, StringComparison.Ordinal))
            return (600, "khớp một phần");

        // 7. Khop so ky tu
        int common = CountCommonSubstring(nameCompact, expCompact);
        if (common >= 4)
            return (300 + common, "khớp một phần chuỗi");

        return (0, "");
    }

    /// <summary>
    /// Kiem tra xem chuoi lon (text) co chua mot tu trong (word) hay khong.
    /// Tu khong dung dau cach (vi du "xa" trong "xakao" thi false).
    /// </summary>
    private static bool ContainsWord(string text, string word)
    {
        if (word.Length == 0) return false;
        int idx = text.IndexOf(word, StringComparison.Ordinal);
        while (idx >= 0)
        {
            bool leftOk = idx == 0 || !char.IsLetterOrDigit(text[idx - 1]);
            int end = idx + word.Length;
            bool rightOk = end >= text.Length || !char.IsLetterOrDigit(text[end]);
            if (leftOk && rightOk) return true;

            idx = text.IndexOf(word, idx + 1, StringComparison.Ordinal);
        }
        return false;
    }

    /// <summary>
    /// Tat ca tu trong keyword deu xuat hien trong ten don vi hay khong.
    /// </summary>
    private static bool AllWordsMatch(string name, string keyword)
    {
        var kwWords = keyword.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (kwWords.Length == 0) return false;

        foreach (var w in kwWords)
        {
            if (w.Length < 2) continue;      // bo qua tu quá ngan
            if (!name.Contains(w, StringComparison.Ordinal)) return false;
        }
        return true;
    }

    /// <summary>
    /// Dem do dai chuoi con chung dai nhat giua hai chuoi (de so khop "mo hon").
    /// </summary>
    private static int CountCommonSubstring(string a, string b)
    {
        int best = 0;
        for (int i = 0; i < a.Length; i++)
        {
            for (int j = 0; j < b.Length; j++)
            {
                int len = 0;
                while (i + len < a.Length && j + len < b.Length &&
                       a[i + len] == b[j + len])
                {
                    len++;
                }
                if (len > best) best = len;
            }
        }
        return best;
    }

    /// <summary>
    /// Tra ve danh sach don vi duoc xep vao dropdown, kem diem khop.
    /// </summary>
    public static List<Hit> Suggestions(string? keyword, int limit = 30) =>
        Search(keyword, limit);
}
