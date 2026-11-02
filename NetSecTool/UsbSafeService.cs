using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace NetSecTool;

/// <summary>
/// Dich vu tao / kiem tra "USB An Toan 2.6".
/// Dung chung cho ca giao dien WinForms va che do CLI (headless).
/// </summary>
internal static class UsbSafeService
{
    /// <summary>
    /// Tao bo cuc "USB An Toan 2.6" tren o dia.
    /// Ket qua tra ve chuoi nhieu dong (log) de hien thi trong UI hoac ghi ra STDOUT.
    /// </summary>
    public static string MakeSafeUsb(string root, string version, string vendor, string seed, bool doFormat)
    {
        var sb = new StringBuilder();
        var log = new List<string>();

        // O dia phai ton tai va san sang truoc khi lam bat cua thao tac
        try
        {
            if (!Directory.Exists(root))
            {
                sb.AppendLine("O dia " + root + " KHONG TON TAI hoac khong san sang.");
                sb.AppendLine("Hay cam lai USB roi thu.");
                return sb.ToString();
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("Khong truy cap duoc o dia " + root + ": " + ex.Message);
            return sb.ToString();
        }

        // 0. Do lai trang thai goc - neu o da bi khoa ghi tu lan truoc thi
        //    phai mo khoa truoc, vi khong the tao/ghi file o thu muc goc.
        bool rootWritable = TryWrite(Path.Combine(root, ".nst_probe.tmp"));
        if (!rootWritable)
        {
            log.Add("Thu muc goc dang bi khoa ghi (do lan tao truoc) - mo khoa tam thoi de ghi lai bo file chi dau.");
            try
            {
                UsbSafeMaker.RestoreWriteAccess(root);
                log.Add("Da mo khoa tam thoi.");
            }
            catch (Exception ex)
            {
                log.Add("KHONG mo khoa duoc thu muc goc: " + ex.Message);
            }
        }
        // 1. Dinh dang NTFS (tien de cho DACL)
        if (doFormat)
        {
            var fmt = UsbFormatter.EnsureNtfs(root, UsbSafeMaker.DefaultVolumeLabel);
            log.Add(fmt.Success ? fmt.Message : "KHONG dinh dang duoc: " + fmt.Message);

            if (!fmt.Success)
            {
                sb.AppendLine("KHONG THE TAO USB AN TOAN tren " + root);
                sb.AppendLine();
                foreach (string l in log) sb.AppendLine("  " + l);
                sb.AppendLine();
                sb.AppendLine("Ly do: khong dinh dang duoc NTFS thi khong gan duoc DACL,");
                sb.AppendLine("nguoi dung van ghi duoc va MiAV se khoa o o tang kernel.");
                return sb.ToString();
            }

            foreach (string s in fmt.Steps) log.Add("  " + s);
            System.Threading.Thread.Sleep(2500);
        }

        // 2. Bo 5 file chi dau ma MiAV dem
        //    XOA file cu truoc khi ghi lai: file tao tu lan truoc co the
        //    mang DACL "corrupt" (explicit Deny Write + inherited Allow) khiến
        //    khong ghi de duoc, dù thu muc goc van ghi duoc.
        foreach (string f in new[] { UsbSafeMaker.FileInf, UsbSafeMaker.FileMtext, UsbSafeMaker.FileAutorun, UsbSafeMaker.FileIco })
        {
            string old = Path.Combine(root, f);
            try
            {
                if (File.Exists(old))
                {
                    // Bat thuoc tinh Hidden/System truoc khi xoa
                    File.SetAttributes(old, File.GetAttributes(old) & ~(FileAttributes.Hidden | FileAttributes.System));
                }
                if (File.Exists(old)) File.Delete(old);
            }
            catch (Exception ex)
            {
                // File co the dang bi "khoa" boi ACE Deny cu -> go khoa roi xoa lai
                if (UsbSafeMaker.ForceResetFileAcl(old))
                {
                    try
                    {
                        if (File.Exists(old)) File.Delete(old);
                        log.Add($"Da go khoa DACL cu va xoa file cu {f}.");
                    }
                    catch (Exception ex2)
                    {
                        log.Add("Khong xoa duoc file cu " + f + ": " + ex2.Message);
                    }
                }
                else
                {
                    log.Add("Khong xoa duoc file cu " + f + ": " + ex.Message);
                }
            }
        }

        byte[] infBin = UsbSafeMaker.BuildInfBin(version, vendor, seed);
        File.WriteAllBytes(Path.Combine(root, UsbSafeMaker.FileInf), infBin);
        log.Add($"{UsbSafeMaker.FileInf} ({infBin.Length} byte)");

        byte[] mtext = new byte[1024];
        RandomNumberGenerator.Fill(mtext);
        File.WriteAllBytes(Path.Combine(root, UsbSafeMaker.FileMtext), mtext);
        log.Add(UsbSafeMaker.FileMtext + " (1024 byte)");

        File.WriteAllText(Path.Combine(root, UsbSafeMaker.FileAutorun),
            "[AutoRun]\r\nicon=ATTT.ico\r\n", Encoding.ASCII);
        log.Add(UsbSafeMaker.FileAutorun);

        File.WriteAllBytes(Path.Combine(root, UsbSafeMaker.FileIco), UsbSafeMaker.BuildTinyIcon());
        log.Add(UsbSafeMaker.FileIco);

        Directory.CreateDirectory(Path.Combine(root, UsbSafeMaker.DirRecycle));
        log.Add(UsbSafeMaker.DirRecycle + "/");

        // 3. Nhan volume (MiAV khong kiem tra - chi de nguoi dung nhan biet)
        try
        {
            new DriveInfo(root).VolumeLabel = UsbSafeMaker.DefaultVolumeLabel;
            log.Add("Nhan volume = " + UsbSafeMaker.DefaultVolumeLabel);
        }
        catch (Exception ex)
        {
            log.Add("Khong dat duoc nhan volume: " + ex.Message);
        }

        // 4. An + System cho cac file chi dau
        foreach (string f in new[] { UsbSafeMaker.FileInf, UsbSafeMaker.FileMtext, UsbSafeMaker.FileAutorun, UsbSafeMaker.FileIco })
        {
            try
            {
                File.SetAttributes(Path.Combine(root, f),
                    File.GetAttributes(Path.Combine(root, f)) | FileAttributes.Hidden | FileAttributes.System);
            }
            catch { /* bo qua */ }
        }

        // 5. Bo cuc an toan:
        //    - DATA/ : doc/ghi/xoa duoc, KHONG chay duoc file thuc thi
        //    - root  : khoa ghi (dieu kien bat buoc de MiAV khong khoa o)
        UsbSafeMaker.ApplySafeLayout(root);
        log.Add($"Thu muc {UsbSafeMaker.DirData}/ - doc/ghi/xoa duoc, KHONG chay duoc file thuc thi (.exe/.bat/.cmd/.ps1)");
        log.Add("Da khoa quyen ghi/xoa o thu muc goc (dieu kien bat buoc de MiAV khong khoa o)");

        // 6. Tu kiem tra bang dung thuat toan MiAV
        byte[] check = File.ReadAllBytes(Path.Combine(root, UsbSafeMaker.FileInf));
        bool ok = UsbSafeMaker.VerifyInfBin(check, out string ver, out string ven);
        log.Add(ok
            ? $"Kiem tra inf.bin theo dung thuat toan MiAV: HOP LE (phien ban \"{ver}\", hang \"{ven}\")"
            : "Kiem tra inf.bin: KHONG hop le");

        bool markerOk = HasAllMarkers(root);
        log.Add(markerOk ? "Du 5 file chi dau (MiAV yeu cau dung 5)" : "THIEU file chi dau");

        bool dataOk = Directory.Exists(Path.Combine(root, UsbSafeMaker.DirData));
        bool dataWritable = dataOk && TryWrite(Path.Combine(root, UsbSafeMaker.DirData, ".nst_probe.tmp"));
        log.Add(dataOk && dataWritable
            ? $"Thu muc du lieu {UsbSafeMaker.DirData}/ san sang - nguoi dung ghi duoc"
            : "KHONG tao duoc thu muc du lieu hoac khong ghi duoc vao no");

        bool rootLocked = !TryWrite(Path.Combine(root, ".nst_probe.tmp"));
        log.Add(rootLocked
            ? "Thu muc goc da khoa ghi - MiAV se cong nhan o la an toan"
            : "CANH BAO: thu muc goc van ghi duoc - MiAV se KHOA o o tang kernel!");

        sb.AppendLine("Da thiet lap USB An Toan 2.6 tren " + root);
        sb.AppendLine();
        foreach (string l in log) sb.AppendLine("  " + l);
        sb.AppendLine();
        bool success = markerOk && ok && dataOk && dataWritable && rootLocked;
        sb.AppendLine(success
            ? "Ket qua: o da du dieu kien de MiAV phan loai \"An toan 2.6\" va KHONG bi khoa o o tang kernel."
            : "Ket qua: CHUA du dieu kien. Vui long kiem tra lai nhat ky o tren.");
        return sb.ToString();
    }

    /// <summary>Kiem tra trang thai cua o dia.</summary>
    public static string InspectUsbSafe(string root)
    {
        var sb = new StringBuilder();

        // O dia co ton tai va san sang de doc khong?
        try
        {
            if (!Directory.Exists(root))
            {
                sb.AppendLine("O dia " + root + " KHONG TON TAI hoac khong san sang.");
                sb.AppendLine("Hay cam lai USB roi thu.");
                return sb.ToString();
            }
        }
        catch (Exception ex)
        {
            sb.AppendLine("Khong truy cap duoc o dia " + root + ": " + ex.Message);
            return sb.ToString();
        }

        string infPath = Path.Combine(root, UsbSafeMaker.FileInf);
        if (File.Exists(infPath))
        {
            byte[] data = File.ReadAllBytes(infPath);
            bool ok = UsbSafeMaker.VerifyInfBin(data, out string ver, out string ven);
            sb.AppendLine(ok
                ? $"inf.bin: HOP LE (phien ban \"{ver}\", hang \"{ven}\", {data.Length} byte)"
                : $"inf.bin: KHONG hop le ({data.Length} byte)");
        }
        else
        {
            sb.AppendLine("inf.bin: KHONG ton tai");
        }

        string[] markers = { UsbSafeMaker.FileInf, UsbSafeMaker.FileMtext, UsbSafeMaker.FileAutorun, UsbSafeMaker.FileIco };
        foreach (string m in markers)
            sb.AppendLine($"{m}: {(File.Exists(Path.Combine(root, m)) ? "co" : "THIEU")}");
        sb.AppendLine(UsbSafeMaker.DirRecycle + "/: " + (Directory.Exists(Path.Combine(root, UsbSafeMaker.DirRecycle)) ? "co" : "THIEU"));

        string dataPath = Path.Combine(root, UsbSafeMaker.DirData);
        bool dataExists = Directory.Exists(dataPath);
        sb.AppendLine(UsbSafeMaker.DirData + "/: " + (dataExists ? "co" : "THIEU"));
        if (dataExists)
        {
            bool w = TryWrite(Path.Combine(dataPath, ".nst_probe.tmp"));
            sb.AppendLine($"  ghi duoc trong {UsbSafeMaker.DirData}/: {(w ? "CO (dung thiet ke)" : "KHONG (bat thuong)")}");
        }

        bool writable = TryWrite(Path.Combine(root, ".nst_probe.tmp"));
        sb.AppendLine(writable
            ? "Quyen ghi thu muc goc: DANG GHI DUOC -> MiAV se phan loai \"Khong an toan\" va KHOA o."
            : "Quyen ghi thu muc goc: da chan -> MiAV se cong nhan o la an toan.");

        string fs = UsbFormatter.GetFileSystem(root);
        sb.AppendLine($"Dinh dang he thong file: {fs}"
            + (fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase)
                ? " (ho tro DACL - OK)"
                : " (KHONG ho tro DACL - MiAV se khoa o)"));

        try { sb.AppendLine($"Nhan volume: \"{new DriveInfo(root).VolumeLabel}\""); } catch { }

        return sb.ToString();
    }

    private static bool HasAllMarkers(string root)
    {
        string[] required =
        {
            UsbSafeMaker.FileInf,
            UsbSafeMaker.FileMtext,
            UsbSafeMaker.FileAutorun,
            UsbSafeMaker.FileIco,
            UsbSafeMaker.DirRecycle
        };
        foreach (string r in required)
        {
            if (Directory.Exists(Path.Combine(root, r))) continue;
            if (File.Exists(Path.Combine(root, r))) continue;
            return false;
        }
        return true;
    }

    /// <summary>Thu ghi thu mot file thu nghiem de kiem tra quyen ghi.</summary>
    private static bool TryWrite(string path)
    {
        try
        {
            File.WriteAllText(path, "x");
            File.Delete(path);
            return true;
        }
        catch { return false; }
    }
}
