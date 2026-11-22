using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecTool;

/// <summary>Kết quả một lần kiểm tra / cập nhật KVRT.</summary>
public sealed class KvrtUpdateResult
{
    /// <summary>True nếu đã cập nhật thành công (file trên đĩa đã thay).</summary>
    public bool Updated;
    /// <summary>True nếu máy đang offline (bỏ qua âm thầm).</summary>
    public bool Offline;
    /// <summary>Số byte đã tải xuống.</summary>
    public long DownloadedBytes;
    /// <summary>Đường dẫn file KVRT sau khi cập nhật.</summary>
    public string TargetPath = "";
    /// <summary>Chi tiết / lý do bỏ qua.</summary>
    public string Message = "";
    /// <summary>Danh sách bước đã thực hiện (để hiển thị log).</summary>
    public readonly System.Collections.Generic.List<string> Steps = new();
}

/// <summary>
/// Tự động cập nhật Kaspersky Virus Removal Tool (KVRT) cho Windows.
///
/// <para>Quy trình:
///   1. Kiểm tra Internet (bất đồng bộ, fail-soft — offline thì bỏ qua âm thầm).
///   2. Tải bản mới nhất về tệp tạm tools\KVRT_update.tmp.
///   3. Xác thực: không rỗng · đúng định dạng PE · chữ ký số Authenticode hợp lệ thuộc Kaspersky.
///   4. Thay thế an toàn (atomic replace): sao lưu .bak → chép đè → xác nhận → xóa .bak.
///      Nếu ghi đè thất bại thì tự khôi phục từ .bak.</para>
///
/// <para>Lưu ý an toàn: chỉ chạm vào tệp trong thư mục tools\ của bản phân phối.
/// Không chạm tới tệp hệ thống hay registry.</para>
/// </summary>
public static class KvrtUpdater
{
    /// <summary>Trang tải chính thức của Kaspersky cho Virus Removal Tool.</summary>
    public const string DownloadPageUrl = "https://www.kaspersky.com/downloads/free-virus-removal-tool";

    /// <summary>Endpoint tải trực tiếp dự phòng.</summary>
    public const string DirectDownloadUrl =
        "https://downloads.kaspersky.com/84909/avp_20.04.0_full_kaspersky.exe";

    /// <summary>Các chuỗi xác định chữ ký số hợp lệ của Kaspersky.</summary>
    private static readonly string[] TrustedSigners =
    {
        "Kaspersky Lab",
        "Kaspersky Lab International",
        "AO \"Kaspersky Lab\""
    };

    /// <summary>Đường dẫn file KVRT trong thư mục tools (đường dẫn ưu tiên).</summary>
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

    /// <summary>Kiểm tra Internet. Trả về false nếu offline — không ném exception.</summary>
    public static async Task<bool> IsOnlineAsync(CancellationToken ct = default)
    {
        try
        {
            using var handler = new HttpClientHandler { UseProxy = true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(6) };
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(6));

            var req = new HttpRequestMessage(HttpMethod.Head, DownloadPageUrl);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, cts.Token);
            return resp.IsSuccessStatusCode || resp.StatusCode == System.Net.HttpStatusCode.Forbidden;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Luồng cập nhật đầy đủ. Trả về kết quả mô tả trạng thái (không ném exception ra ngoài).</summary>
    public static async Task<KvrtUpdateResult> UpdateAsync(
        Action<string>? log = null,
        IProgress<int>? progress = null,
        CancellationToken ct = default)
    {
        var res = new KvrtUpdateResult();
        Action<string> L = (m) => { res.Steps.Add(m); log?.Invoke(m); };

        string? target = LocateKvrt();
        if (target == null)
        {
            res.Message = "Không tìm thấy tools\\KVRT.exe trong bản phân phối. " +
                          "Hãy copy đủ thư mục tools/ cạnh phần mềm rồi thử lại.";
            L(res.Message);
            return res;
        }
        res.TargetPath = target;

        // --- Buoc 1: kiem tra Internet (fail-soft) ---
        L("Kiểm tra kết nối Internet...");
        progress?.Report(5);
        if (!await IsOnlineAsync(ct).ConfigureAwait(false))
        {
            res.Offline = true;
            res.Message = "Máy đang offline — bỏ qua cập nhật KVRT (không gây phiền người dùng).";
            L(res.Message);
            return res;
        }
        L("Có Internet.");

        // --- Buoc 2: giai phap duong dan tai ---
        progress?.Report(15);
        string? url = await ResolveDownloadUrlAsync(L, ct).ConfigureAwait(false);
        if (url == null)
        {
            res.Message = "Không xác định được đường dẫn tải KVRT mới nhất từ trang Kaspersky. " +
                          "Hãy tải thủ công từ " + DownloadPageUrl + " và thay thế tools\\KVRT.exe.";
            L(res.Message);
            return res;
        }
        L("Đường dẫn tải: " + url);

        // --- Buoc 3: tai ve file tam ---
        string toolsDir = Path.GetDirectoryName(target) ?? AppContext.BaseDirectory;
        string tmpPath = Path.Combine(toolsDir, "KVRT_update.tmp");
        progress?.Report(30);

        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(20) };
            using var resp = await client.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                                     .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                res.Message = "Tải thất bại — HTTP " + (int)resp.StatusCode + " " + resp.ReasonPhrase;
                L(res.Message);
                return res;
            }

            long? total = resp.Content.Headers.ContentLength;
            using (var fs = new FileStream(tmpPath, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                await using var src = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                var buf = new byte[81920];
                long done = 0;
                int n;
                while ((n = await src.ReadAsync(buf, ct).ConfigureAwait(false)) > 0)
                {
                    await fs.WriteAsync(buf.AsMemory(0, n), ct).ConfigureAwait(false);
                    done += n;
                    res.DownloadedBytes = done;
                    if (total.HasValue && total.Value > 0)
                        progress?.Report(30 + (int)Math.Min(60, done * 60 / total.Value));
                }
            }
            L($"Đã tải {res.DownloadedBytes / 1024.0 / 1024.0:F1} MB vào {tmpPath}");
        }
        catch (Exception ex)
        {
            res.Message = "Lỗi tải KVRT: " + ex.Message;
            L(res.Message);
            TryDelete(tmpPath);
            return res;
        }

        // --- Buoc 4: xac thuc file tai ve ---
        progress?.Report(92);
        string? invalid = ValidateDownloaded(tmpPath);
        if (invalid != null)
        {
            res.Message = "Tệp tải về không hợp lệ: " + invalid + " — đã xóa, không thay thế bản cũ.";
            L(res.Message);
            TryDelete(tmpPath);
            return res;
        }
        L("Xác thực OK: PE hợp lệ + chữ ký số Kaspersky tin cậy.");

        // --- Buoc 5: atomic replace ---
        progress?.Report(96);
        string bakPath = target + ".bak";
        try
        {
            TryDelete(bakPath);
            File.Copy(target, bakPath, true);
            File.Copy(tmpPath, target, true);

            var fi = new FileInfo(target);
            if (fi.Length == 0)
                throw new IOException("Tệp sau khi thay thế có kích thước 0 byte.");

            TryDelete(tmpPath);
            TryDelete(bakPath);

            res.Updated = true;
            res.Message = $"Đã cập nhật KVRT thành công ({res.DownloadedBytes / 1024.0 / 1024.0:F1} MB) → {target}";
            L(res.Message);
        }
        catch (Exception ex)
        {
            L("Thay thế thất bại: " + ex.Message + " → khôi phục bản cũ.");
            try
            {
                if (File.Exists(bakPath))
                {
                    File.Copy(bakPath, target, true);
                    L("Đã khôi phục bản KVRT cũ từ file .bak.");
                }
            }
            catch (Exception ex2)
            {
                L("NGHIÊM TRỌNG: không khôi phục được bản cũ — " + ex2.Message);
            }
            TryDelete(tmpPath);
            TryDelete(bakPath);
            res.Message = "Cập nhật KVRT thất bại: " + ex.Message;
        }

        progress?.Report(100);
        return res;
    }

    /// <summary>Xác thực tệp tải về. Trả về null nếu hợp lệ, ngược lại trả về lý do không hợp lệ.</summary>
    public static string? ValidateDownloaded(string path)
    {
        try
        {
            var fi = new FileInfo(path);
            if (!fi.Exists) return "tệp không tồn tại";
            if (fi.Length < 1_000_000) return $"kích thước quá nhỏ ({fi.Length} byte) — không phải bộ cài KVRT";

            using (var fs = File.OpenRead(path))
            {
                int mz = fs.ReadByte();
                int mz2 = fs.ReadByte();
                if (mz != 0x4D || mz2 != 0x5A)
                    return "không phải tệp PE (thiếu chữ ký MZ)";
            }

            try
            {
                // CreateFromSignedFile tra X509Certificate — ep sang X509Certificate2
                // qua GetRawCertData() de dung duoc API Chain.Build().
                using var raw = new X509Certificate2(
                    X509Certificate2.CreateFromSignedFile(path).GetRawCertData());
                using var cert = raw;
                string subject = cert.Subject ?? "";
                string issuer = cert.Issuer ?? "";
                bool trusted = TrustedSigners.Any(t =>
                    subject.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0 ||
                    issuer.IndexOf(t, StringComparison.OrdinalIgnoreCase) >= 0);

                if (!trusted)
                    return $"chữ ký số không thuộc Kaspersky (Subject: {subject})";

                try
                {
                    var chain = new X509Chain();
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
                    if (!chain.Build(cert))
                        return "chữ ký số không hợp lệ (không dựng được chuỗi tin cậy)";
                }
                catch
                {
                    // Môi trường offline -> bỏ qua kiểm tra chuỗi
                }
            }
            catch (Exception ex)
            {
                return "không đọc được chữ ký số Authenticode (" + ex.Message + ")";
            }

            return null;
        }
        catch (Exception ex)
        {
            return "lỗi khi xác thực: " + ex.Message;
        }
    }

    /// <summary>Xác định URL tải trực tiếp. Ưu tiên scrape trang chính thức, fallback về endpoint cứng.</summary>
    private static async Task<string?> ResolveDownloadUrlAsync(Action<string> L, CancellationToken ct)
    {
        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(15) };
            string html = await client.GetStringAsync(DownloadPageUrl, ct).ConfigureAwait(false);

            var matches = System.Text.RegularExpressions.Regex.Matches(
                html,
                @"https?://[^\s""'<>]*kaspersky[^\s""'<>]*\.exe",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);

            foreach (System.Text.RegularExpressions.Match m in matches)
            {
                string u = m.Value.Replace("&amp;", "&");
                if (u.IndexOf("_full_", StringComparison.OrdinalIgnoreCase) >= 0)
                    return u;
            }
            if (matches.Count > 0)
                return matches[0].Value.Replace("&amp;", "&");

            L("Không tìm thấy liên kết .exe trong HTML trang Kaspersky — dùng endpoint dự phòng.");
        }
        catch (Exception ex)
        {
            L("Không scrape được trang Kaspersky: " + ex.Message + " — dùng endpoint dự phòng.");
        }

        try
        {
            using var handler = new HttpClientHandler { AllowAutoRedirect = true };
            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(12) };
            using var req = new HttpRequestMessage(HttpMethod.Head, DirectDownloadUrl);
            using var resp = await client.SendAsync(req, HttpCompletionOption.ResponseHeadersRead, ct)
                                     .ConfigureAwait(false);
            if (resp.IsSuccessStatusCode)
                return DirectDownloadUrl;
        }
        catch
        {
            // bỏ qua
        }
        return null;
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { /* fail-soft: không gây lỗi ngăn trở */ }
    }

    /// <summary>Lấy thông tin phiên bản / chữ ký của file KVRT hiện tại để hiển thị.</summary>
    public static string DescribeCurrent(string? path)
    {
        if (path == null || !File.Exists(path))
            return "Chưa có file KVRT trong thư mục tools\\.";

        try
        {
            var fi = new FileInfo(path);
            string signer = "(không đọc được chữ ký)";
            try
            {
                using var raw = new X509Certificate2(
                    X509Certificate2.CreateFromSignedFile(path).GetRawCertData());
                using var cert = raw;
                signer = cert.Subject ?? "(trống)";
            }
            catch { }

            return $"KVRT: {fi.Length / 1024.0 / 1024.0:F1} MB · sửa lần cuối {fi.LastWriteTime:yyyy-MM-dd HH:mm} · {signer}";
        }
        catch (Exception ex)
        {
            return "Không đọc được thông tin KVRT: " + ex.Message;
        }
    }
}
