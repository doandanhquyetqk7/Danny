using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace NetSecTool;

/// <summary>
/// Ket qua cua buoc dinh dang lai o dia (format).
/// </summary>
internal sealed class FormatResult
{
    /// <summary>True neu thao tac thanh cong (ke ca truong hop da la NTFS va bo qua).</summary>
    public bool Success { get; set; }

    /// <summary>True neu thuc su da chay format.</summary>
    public bool Formatted { get; set; }

    /// <summary>True neu bo qua vi o da san la NTFS.</summary>
    public bool Skipped { get; set; }

    /// <summary>He thong file truoc khi format (vd: "FAT32", "exFAT", "NTFS").</summary>
    public string FileSystemBefore { get; set; } = "";

    /// <summary>He thong file sau khi format.</summary>
    public string FileSystemAfter { get; set; } = "";

    /// <summary>Thong bao thu ngan cho nguoi dung.</summary>
    public string Message { get; set; } = "";

    /// <summary>Exit code cua format.com (0 = thanh cong).</summary>
    public int ExitCode { get; set; } = -1;

    /// <summary>Toan bo output cua format.com de cham loi.</summary>
    public string Output { get; set; } = "";

    /// <summary>Cac buoc da thuc hien (de ghi vao nhat ky).</summary>
    public List<string> Steps { get; } = new();
}

/// <summary>
/// Format o dia ve NTFS - buoc BAT BUOC de co the gan DACL.
///
/// Ly do: MiAV kiem tra bang AccessCheck voi FILE_GENERIC_WRITE (0x120116) tren
/// &lt;drive&gt;:\. Chi he thong file NTFS moi ho tro DACL kieu ACL (Windows ACL).
/// FAT32 / exFAT khong co kha nang nay, nen SetAccessControl se khong tao duoc
/// hoac bi bo qua -&gt; user van ghi duoc -&gt; MiAV phan loai "Khong an toan"
/// -&gt; khoa o o tang kernel.
///
/// === KHOA HOC DUNG SAI: format.com THAT BAI tren USB khi chuyen FAT32 -&gt; NTFS ===
///
/// Voi USB 7.8 GB, lenh
///     format.com J: /FS:NTFS /V:USB-AT2.6 /Y /Q
/// in ra "Format complete." roi "Format failed." (exit code 4).
/// Event Log (Ntfs, Id 55) bao "The Master File Table (MFT) contains a
/// corrupted file record".
///
/// Nguyen nhan: NTFS viet MFT zone (Mft Zone Size) can mot VUNG LIEN TUC
/// lon o dau dia. tren o 7.8 GB yeu cau cau truc MFT khong du dieu kien, nen
/// format that bai. THU NGHIEM: cung chinh USB do, tao partition 2 GB ->
/// format NTFS THANH CONG, roi "extend" partition len toan bo 7.81 GB ->
/// van NTFS binh thuong.
///
/// Vay CHIEN LUOC DUNG cho o USB:
///   1. Xoa partition cu, tao partition PRIMARY MOI kich thuoc nho (~2 GB).
///   2. Format partition nho do thanh NTFS.
///   3. "extend" partition de no lan toi het dia.
///   4. Gan lai drive letter va dat nhan volume.
///
/// Cach nay giong hinh thuc san pham USB_ATTT.exe (BTL86) chay
///     c:\windows\system32\format.com /FS:NTFS /V:USB-AT2.6 /Y /Q
/// nhung them buoc tao-partition-nho truoc de tranh loi "Format failed".
/// </summary>
internal static class UsbFormatter
{
    private const string FormatExe = @"C:\Windows\System32\format.com";
    private const string DiskPartExe = @"C:\Windows\System32\diskpart.exe";

    /// <summary>Kich thuoc partition tao tam (MB) khi can dung chien luoc 2 giai doan.</summary>
    private const uint StagingPartitionMB = 2000;

    static UsbFormatter()
    {
        // .NET Core khong co san codepage OEM (437) - can dang ky provider
        // de doc duoc output tieng Viet/Anh cua format.com.
        try { Encoding.RegisterProvider(CodePagesEncodingProvider.Instance); }
        catch { /* bo qua */ }
    }

    /// <summary>Encoding de doc output cua format.com (OEM 437).</summary>
    private static Encoding OemEncoding
    {
        get
        {
            try { return Encoding.GetEncoding(437); }
            catch { return Encoding.Latin1; }
        }
    }

    /// <summary>
    /// Doc he thong file cua o. Tra ve chuoi rong neu khong doc duoc.
    /// </summary>
    public static string GetFileSystem(string root)
    {
        try
        {
            if (!Directory.Exists(root)) return "";
            var di = new DriveInfo(Path.GetFullPath(root));
            return di.DriveFormat ?? "";
        }
        catch
        {
            return "";
        }
    }

    /// <summary>True neu o da san la NTFS.</summary>
    public static bool IsNtfs(string root)
    {
        return GetFileSystem(root).Equals("NTFS", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Dam bao o duoc dinh dang NTFS. Neu da la NTFS thi bo qua.
    /// Neu khong phai, se XOA TOAN BO DU LIEU va dinh dang lai.
    ///
    /// Chien luoc 2 giai doan (xem ghi chu dau file): tao partition nho ->
    /// format NTFS -> extend. Neu that bai, fallback ve format.com thuan.
    /// </summary>
    public static FormatResult EnsureNtfs(string root, string volumeLabel)
    {
        var res = new FormatResult();
        string drive = NormalizeDriveLetter(root);

        res.FileSystemBefore = GetFileSystem(root);

        if (res.FileSystemBefore.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
        {
            res.Success = true;
            res.Skipped = true;
            res.FileSystemAfter = res.FileSystemBefore;
            res.Message = "O da dung NTFS - khong can dinh dang lai.";
            return res;
        }

        if (drive.Length == 0)
        {
            res.Message = "Khong xac dinh duoc ky tu o dia.";
            return res;
        }

        if (!File.Exists(FormatExe))
        {
            res.Message = "Khong tim thay format.com trong he thong.";
            return res;
        }

        // --- Chien luoc 1: format.com thuan (nhanh, giu nguyen partition) ---
        res = RunFormat(drive, volumeLabel, res.FileSystemBefore);
        if (res.Success)
        {
            res.Steps.Add("Dinh bang format.com (FAT/exFAT -> NTFS truc tiep).");
            return res;
        }

        res.Steps.Add("format.com that bai (" + res.Message + ")");
        res.Steps.Add("Chuyen sang chien luoc 2 giai doan: tao partition nho -> format NTFS -> extend.");

        // --- Chien luoc 2: tao partition nho -> format -> extend ---
        var res2 = RunStagedFormat(root, drive, volumeLabel, res.FileSystemBefore);
        foreach (string s in res2.Steps) res.Steps.Add(s);

        res2.FileSystemBefore = res.FileSystemBefore;
        res2.ExitCode = res2.ExitCode == -1 ? res.ExitCode : res2.ExitCode;
        if (!string.IsNullOrWhiteSpace(res.Output) && string.IsNullOrWhiteSpace(res2.Output))
            res2.Output = res.Output;

        return res2;
    }

    // ==================================================================
    // Chien luoc 1: format.com thuan
    // ==================================================================

    private static FormatResult RunFormat(string drive, string volumeLabel, string fsBefore)
    {
        var res = new FormatResult { FileSystemBefore = fsBefore };

        var psi = new ProcessStartInfo
        {
            FileName = FormatExe,
            // /FS:NTFS  - he thong file
            // /V:<nhan> - ten nhan volume
            // /Y       - tu dong dong y (khong hoi "Insert new disk label")
            // /Q       - quick format
            Arguments = $"{drive} /FS:NTFS /V:{volumeLabel} /Y /Q",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            StandardOutputEncoding = OemEncoding,
            StandardErrorEncoding = OemEncoding
        };

        try
        {
            using var p = Process.Start(psi)!;
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();

            res.ExitCode = p.ExitCode;
            res.Output = (stdout + "\n" + stderr).Trim();
            res.FileSystemAfter = GetFileSystem(drive + "\\");

            if (p.ExitCode == 0 && res.FileSystemAfter.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
            {
                res.Success = true;
                res.Formatted = true;
                res.Message = $"Da dinh dang {drive} sang NTFS thanh cong.";
                return res;
            }

            res.Success = false;
            res.Message = ExplainError(res.ExitCode, res.Output);
            return res;
        }
        catch (Exception ex)
        {
            res.Success = false;
            res.Message = "Loi khi chay format.com: " + ex.Message;
            return res;
        }
    }

    // ==================================================================
    // Chien luoc 2: tao partition nho -> format NTFS -> extend
    // ==================================================================

    private static FormatResult RunStagedFormat(string root, string drive, string volumeLabel, string fsBefore)
    {
        var res = new FormatResult { FileSystemBefore = fsBefore };

        string diskNumber = FindDiskNumber(root);
        if (diskNumber.Length == 0)
        {
            res.Success = false;
            res.Message = "Khong xac dinh duoc so thu tu dia (disk) cua o.";
            res.Steps.Add("Khong xac dinh duoc disk number.");
            return res;
        }

        res.Steps.Add($"Xac dinh: {drive} thuoc disk {diskNumber}.");

        // Buoc 1: clean + tao partition nho
        var dp1 = RunDiskPart(new[]
        {
            $"select disk {diskNumber}",
            "clean",
            $"create partition primary size={StagingPartitionMB}",
            "exit"
        }, out string out1);
        res.Steps.Add("Buoc 1 (clean + tao partition " + StagingPartitionMB + "MB): " + Summarize(out1));

        // Buoc 2: format partition nho thanh NTFS
        var dp2 = RunDiskPart(new[]
        {
            $"select disk {diskNumber}",
            "select partition 1",
            $"format fs=ntfs label={volumeLabel} quick",
            "exit"
        }, out string out2);
        res.Steps.Add("Buoc 2 (format partition nho sang NTFS): " + Summarize(out2));

        if (!out2.Contains("successfully formatted", StringComparison.OrdinalIgnoreCase))
        {
            res.Success = false;
            res.ExitCode = -1;
            res.Output = out2;
            res.Message = "Khong format duoc partition tam sang NTFS. " + Summarize(out2);
            return res;
        }

        // Buoc 3: extend partition len toan bo dia
        var dp3 = RunDiskPart(new[]
        {
            $"select disk {diskNumber}",
            "select partition 1",
            "extend",
            "exit"
        }, out string out3);
        res.Steps.Add("Buoc 3 (extend partition len toan bo dia): " + Summarize(out3));

        // Buoc 4: gan lai drive letter
        var dp4 = RunDiskPart(new[]
        {
            $"select disk {diskNumber}",
            "select partition 1",
            $"assign letter={drive.TrimEnd(':', '\\')}",
            "exit"
        }, out string out4);
        res.Steps.Add("Buoc 4 (gan lai drive letter): " + Summarize(out4));

        Thread.Sleep(2500);

        res.FileSystemAfter = GetFileSystem(root);
        if (res.FileSystemAfter.Equals("NTFS", StringComparison.OrdinalIgnoreCase))
        {
            res.Success = true;
            res.Formatted = true;
            res.Message = $"Da dinh dang {drive} sang NTFS thanh cong (tao partition moi + extend).";
            return res;
        }

        res.Success = false;
        res.ExitCode = -1;
        res.Output = out3 + "\n" + out4;
        res.Message = "Khong xac nhan duoc NTFS sau khi format. FS hien tai: "
                      + (res.FileSystemAfter.Length == 0 ? "(khong doc duoc)" : res.FileSystemAfter);
        return res;
    }

    /// <summary>Chay diskpart voi danh sach lenh, tra ve exit code va output.</summary>
    private static int RunDiskPart(string[] commands, out string output)
    {
        string scriptPath = Path.Combine(Path.GetTempPath(),
            "nst_diskpart_" + Guid.NewGuid().ToString("N").Substring(0, 8) + ".txt");

        try
        {
            File.WriteAllLines(scriptPath, commands, Encoding.ASCII);

            var psi = new ProcessStartInfo
            {
                FileName = DiskPartExe,
                Arguments = $"/s \"{scriptPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                StandardOutputEncoding = OemEncoding,
                StandardErrorEncoding = OemEncoding
            };

            using var p = Process.Start(psi)!;
            string stdout = p.StandardOutput.ReadToEnd();
            string stderr = p.StandardError.ReadToEnd();
            p.WaitForExit();

            output = (stdout + "\n" + stderr).Trim();
            return p.ExitCode;
        }
        catch (Exception ex)
        {
            output = "Loi khi chay diskpart: " + ex.Message;
            return -1;
        }
        finally
        {
            try { File.Delete(scriptPath); } catch { }
        }
    }

    /// <summary>Tom tat 1 dong ket qua cua diskpart.</summary>
    private static string Summarize(string diskpartOutput)
    {
        if (string.IsNullOrWhiteSpace(diskpartOutput)) return "(khong co output)";

        if (diskpartOutput.Contains("successfully formatted", StringComparison.OrdinalIgnoreCase))
            return "thanh cong";
        if (diskpartOutput.Contains("successfully extended", StringComparison.OrdinalIgnoreCase))
            return "thanh cong";
        if (diskpartOutput.Contains("successfully cleaned", StringComparison.OrdinalIgnoreCase))
            return "thanh cong";
        if (diskpartOutput.Contains("has encountered an error", StringComparison.OrdinalIgnoreCase))
        {
            foreach (string line in diskpartOutput.Split('\n'))
            {
                if (line.Contains("error", StringComparison.OrdinalIgnoreCase)
                    && !line.Contains("encountered an error"))
                {
                    return "LOI: " + line.Trim();
                }
            }
            return "LOI (xem Event Log)";
        }
        return "xem output chi tiet";
    }

    /// <summary>
    /// Tim so thu tu disk cua mot drive letter (vd: "J:" -> "8").
    /// Dung "diskpart /s detail volume" va parse dong "* Disk N".
    /// </summary>
    private static string FindDiskNumber(string root)
    {
        try
        {
            string letter = NormalizeDriveLetter(root).TrimEnd(':');
            if (letter.Length == 0) return "";

            RunDiskPart(new[]
            {
                $"select volume {letter}:",
                "detail volume",
                "exit"
            }, out string output);

            foreach (string raw in output.Split('\n'))
            {
                string line = raw.Trim().TrimStart('*').Trim();
                // Dang: "Disk 8    Online    8000 MB   ..."
                if (!line.StartsWith("Disk ", StringComparison.OrdinalIgnoreCase)) continue;

                string rest = line.Substring("Disk ".Length).Trim();
                int space = rest.IndexOf(' ');
                string num = space > 0 ? rest.Substring(0, space).Trim() : rest;
                if (num.Length > 0 && int.TryParse(num, out _)) return num;
            }
        }
        catch
        {
            // bo qua
        }
        return "";
    }

    /// <summary>Dich ma exit code cua format.com thanh thong diep de hieu.</summary>
    private static string ExplainError(int exitCode, string output)
    {
        string detail = ExtractMeaningfulLine(output);

        string baseMsg = exitCode switch
        {
            0 => "Thanh cong.",
            1 => "Tham so sai.",
            2 => "O dia khong hop le.",
            3 => "Khong tim thay o dia.",
            4 => "That bai khi ghi cau truc file system (thuong do MFT zone khong du dieu kien tren o dia nho).",
            5 => "Truy cap bi tu choi - o dang duoc su dung (mo cua so Explorer tren o) hoac bi khoa boi phan mem khac.",
            _ => "Khong ro loi (format.com exit " + exitCode + ")."
        };

        return string.IsNullOrEmpty(detail)
            ? baseMsg
            : baseMsg + " Chi tiet: " + detail;
    }

    /// <summary>Loc dong thong bao co y nghia tu output cua format.com (tieng Viet/English).</summary>
    private static string ExtractMeaningfulLine(string output)
    {
        if (string.IsNullOrWhiteSpace(output)) return "";

        string[] lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
        foreach (string raw in lines)
        {
            string l = raw.Trim();
            if (l.Length == 0) continue;
            // bo qua cac dong khong mang thong tin
            if (l.StartsWith("Insert new disk label", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Format complete", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Volume label", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Quick", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Processing", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Bytes", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("Creating file system", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("The type of the file system", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.StartsWith("The new file system", StringComparison.OrdinalIgnoreCase)) continue;
            if (l.Length < 8) continue;
            return l;
        }
        return "";
    }

    /// <summary>Chuyen "K:\\" thanh "K:"</summary>
    private static string NormalizeDriveLetter(string root)
    {
        try
        {
            string full = Path.GetFullPath(root);
            return full.Length >= 2 && char.IsLetter(full[0]) && full[1] == ':'
                ? full.Substring(0, 2)
                : "";
        }
        catch
        {
            return "";
        }
    }
}
