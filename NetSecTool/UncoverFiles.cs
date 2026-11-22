using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace NetSecTool;

/// <summary>Một tệp/thư mục ẩn đã được khôi phục (hoặc bỏ qua).</summary>
public sealed class UncoverItem
{
    public string FullPath = "";
    public bool IsDirectory;
    public long SizeBytes;
    public DateTime Modified;
    public string OriginalAttributes = "";
    public bool Restored;
    public string? Note;
}

/// <summary>Kết quả quét khôi phục file ẩn.</summary>
public sealed class UncoverResult
{
    public int Scanned;
    public int Restored;
    public int Failed;
    public int Skipped;
    public long BytesScanned;
    public readonly List<UncoverItem> Items = new();
    public readonly List<string> Errors = new();
    public string Root = "";
    public TimeSpan Elapsed => _elapsed;
    private TimeSpan _elapsed;
    public void SetElapsed(TimeSpan t) => _elapsed = t;
}

/// <summary>
/// Khôi phục thuộc tính ẩn / system cho file và thư mục.
///
/// <para>Cơ chế: gỡ cờ Hidden + System + ReadOnly bằng
/// <c>File.SetAttributes</c> (tương đương <c>attrib -h -s</c>) và
/// <c>DirectoryInfo.Attributes</c>.</para>
///
/// <para>Không dùng <c>attrib</c> vì:
///   - Không trả về mã lỗi chi tiết theo từng tệp.
///   - Với đường dẫn có ký tự lạ (dấu nháy, ký tự điều khiển) rất dễ lỗi.
///   - Không báo cáo được tiến độ.</para>
/// </summary>
public static class UncoverFiles
{
    /// <summary>Các thuộc tính bị gỡ bỏ khi khôi phục.</summary>
    private const FileAttributes ClearMask =
        FileAttributes.Hidden | FileAttributes.System | FileAttributes.ReadOnly;

    /// <summary>
    /// Quét và khôi phục trong một lần.
    /// </summary>
    /// <param name="root">Thư mục gốc (ví dụ "C:\\" hoặc "D:\\Data").</param>
    /// <param name="recursive">Quét đệ quy.</param>
    /// <param name="dryRun">Chỉ liệt kê, không thay đổi thuộc tính.</param>
    /// <param name="ct">Token hủy.</param>
    /// <param name="onItem">Callback báo tiến độ (đếm số tệp đã xét).</param>
    public static UncoverResult Scan(
        string root,
        bool recursive,
        bool dryRun,
        Action<int, string>? onItem = null,
        CancellationToken ct = default)
    {
        var res = new UncoverResult { Root = root };
        var sw = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            if (!Directory.Exists(root))
            {
                res.Errors.Add("Không tìm thấy thư mục: " + root);
                return res;
            }

            // Lay danh sach phu hop (bo qua junction/sympoint de tranh loop vo han)
            IEnumerable<string> dirs;
            IEnumerable<string> files;
            try
            {
                var di = new DirectoryInfo(root);
                dirs = recursive ? EnumerateSafeDirs(di) : new[] { root };
                files = EnumerateSafeFiles(di);
            }
            catch (Exception ex)
            {
                res.Errors.Add("Không quét được thư mục gốc: " + ex.Message);
                return res;
            }

            foreach (string dir in dirs)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var di = new DirectoryInfo(dir);
                    FileAttributes attr = di.Attributes;
                    if ((attr & ClearMask) != 0)
                    {
                        var item = new UncoverItem
                        {
                            FullPath = di.FullName,
                            IsDirectory = true,
                            Modified = SafeLastWrite(di),
                            OriginalAttributes = attr.ToString()
                        };

                        if (dryRun)
                        {
                            item.Restored = false;
                            item.Note = "DRY-RUN — sẽ gỡ cờ ẩn";
                            res.Skipped++;
                        }
                        else
                        {
                            try
                            {
                                di.Attributes = attr & ~ClearMask;
                                item.Restored = true;
                                res.Restored++;
                            }
                            catch (Exception ex)
                            {
                                item.Restored = false;
                                item.Note = ex.Message;
                                res.Failed++;
                                res.Errors.Add(dir + " → " + ex.Message);
                            }
                        }
                        res.Items.Add(item);
                        res.Scanned++;
                        onItem?.Invoke(res.Scanned, item.FullPath);
                    }
                }
                catch (Exception ex)
                {
                    res.Errors.Add(dir + " → " + ex.Message);
                }
            }

            foreach (string file in files)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    var fi = new FileInfo(file);
                    FileAttributes attr = fi.Attributes;
                    if ((attr & ClearMask) == 0) continue;

                    var item = new UncoverItem
                    {
                        FullPath = fi.FullName,
                        IsDirectory = false,
                        SizeBytes = SafeLength(fi),
                        Modified = SafeLastWrite(fi),
                        OriginalAttributes = attr.ToString()
                    };
                    res.BytesScanned += item.SizeBytes;

                    if (dryRun)
                    {
                        item.Restored = false;
                        item.Note = "DRY-RUN — sẽ gỡ cờ ẩn";
                        res.Skipped++;
                    }
                    else
                    {
                        try
                        {
                            fi.Attributes = attr & ~ClearMask;
                            item.Restored = true;
                            res.Restored++;
                        }
                        catch (Exception ex)
                        {
                            item.Restored = false;
                            item.Note = ex.Message;
                            res.Failed++;
                            res.Errors.Add(file + " → " + ex.Message);
                        }
                    }
                    res.Items.Add(item);
                    res.Scanned++;
                    onItem?.Invoke(res.Scanned, item.FullPath);
                }
                catch (Exception ex)
                {
                    res.Errors.Add(file + " → " + ex.Message);
                }
            }
        }
        finally
        {
            sw.Stop();
            res.SetElapsed(sw.Elapsed);
        }

        return res;
    }

    /// <summary>Liệt kê toàn bộ tệp/thư mục ẩn mà không thay đổi gì (dùng cho chế độ xem trước).</summary>
    public static UncoverResult Preview(string root, bool recursive, CancellationToken ct = default)
        => Scan(root, recursive, dryRun: true, onItem: null, ct);

    private static IEnumerable<string> EnumerateSafeFiles(DirectoryInfo root)
    {
        // Duyệt từng thư mục con (BFS) thay vì SearchOption.AllDirectories de tranh
        // chay qua reparse point (junction) va gap loi "Access denied".
        var stack = new Stack<DirectoryInfo>();
        stack.Push(root);

        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            FileInfo[] files;
            try { files = cur.GetFiles(); }
            catch { continue; }

            foreach (FileInfo f in files)
            {
                yield return f.FullName;
            }

            if (cur.FullName.Length > 3000) continue; // tránh path quá dài
            DirectoryInfo[] subs;
            try { subs = cur.GetDirectories(); }
            catch { continue; }

            foreach (DirectoryInfo d in subs)
            {
                try
                {
                    if ((d.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }
                stack.Push(d);
            }
        }
    }

    private static IEnumerable<string> EnumerateSafeDirs(DirectoryInfo root)
    {
        yield return root.FullName;

        var stack = new Stack<DirectoryInfo>();
        stack.Push(root);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        while (stack.Count > 0)
        {
            var cur = stack.Pop();
            DirectoryInfo[] subs;
            try { subs = cur.GetDirectories(); }
            catch { continue; }

            foreach (DirectoryInfo d in subs)
            {
                try
                {
                    if ((d.Attributes & FileAttributes.ReparsePoint) != 0) continue;
                }
                catch { continue; }

                if (!seen.Add(d.FullName)) continue;
                yield return d.FullName;
                stack.Push(d);
            }
        }
    }

    private static long SafeLength(FileInfo fi)
    {
        try { return fi.Length; } catch { return 0; }
    }

    private static DateTime SafeLastWrite(FileSystemInfo fi)
    {
        try { return fi.LastWriteTime; } catch { return DateTime.MinValue; }
    }
}
