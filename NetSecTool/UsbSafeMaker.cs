using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;

namespace NetSecTool;

/// <summary>
/// Tao "USB An Toan 2.6" phu hop voi co che kiem tra cua MiAV 4.1.1.2.
///
/// Cong thuc sinh/kiem tra inf.bin da duoc xac nhan BYTE-EXACT voi san pham
/// USB_ATTT.exe (BTL86) tren mau that 69 byte - xem evidence/E-005.md.
///
///   K    = Lines[2]                      (seed, lay tu chinh file dang kiem tra)
///   k1   = Lower(MD5(K))
///   k2   = Lower(MD5(k1))
///   E(X) = X XOR k2 XOR k1 XOR K        (keo dai, khoa lap theo CHI SO KY TU)
///   V0   = E(Base64Decode(Lines[0]))    (phien ban)
///   V1   = E(Base64Decode(Lines[1]))    (hang SX)
///   L3   = Lower(MD5(V0 + V1 + K))
///   Hop le <=> Lower(Lines[3]) == L3
///
/// MD5 tinh tren byte ANSI (Latin-1), KHONG phai UTF-16.
///
/// ======================== CO CHE KHOA QUYEN GHI ========================
///
/// MiAV kiem tra quyen ghi bang AccessCheck voi FILE_GENERIC_WRITE (0x120116)
/// tren CHINH THU MUC GOC "&lt;drive&gt;:\". Xac nhan: chuoi tai 0x915320 la
/// ":\\" va duong dan duoc dung o 0x915048 -> 0x915061.
///
///   - User CO quyen ghi tren root  => "Khong an toan" => khoa o o tang kernel
///   - User KHONG co quyen ghi      => du 5 file chi dau => "An toan 2.6"
///
/// => De nguoi dung van ghi duoc du lieu, ta tao thu muc con "DATA" voi
///    DACL rieng: cho PHEP DOC/GHI/XOA nhung CAM chay file thuc thi.
///    Do AccessCheck chi lay o root nen thu muc con nay khong anh huong
///    viec MiAV phan loai o.
///
/// LUU Y BAO MAT: bo kiem tra cua MiAV la "tu tham chieu" - K lay tu chinh
/// file, khong co khoa cong khai, khong co chu ky so. Do do "USB an toan" 2.6
/// chi la MARKER do nguoi dung tu khai, khong phai co che xac thuc.
/// RANG BUOC THAT SU DUY NHAT la DACL.
/// </summary>
internal static class UsbSafeMaker
{
    // --- Tham so mac dinh cua "USB An Toan Cap do II (2.6)" ---
    public const string DefaultSeed = "XZ3O4HN5GDKRS3G95";
    public const string DefaultVersion = "2.6";
    public const string DefaultVendor = "BTL86";
    public const string DefaultVolumeLabel = "USB-AT2.6";

    // --- Ten bo file chi dau ma MiAV dem (nhom B, phai du dung 5) ---
    public const string FileInf = "inf.bin";
    public const string FileMtext = "mtext.bin";
    public const string FileAutorun = "autorun.inf";
    public const string FileIco = "attt.ico";
    public const string DirRecycle = "RECYCLER";

    // --- Thu muc du lieu cua nguoi dung ---
    public const string DirData = "DATA";

    private static readonly SecurityIdentifier EveryoneSid =
        new SecurityIdentifier(WellKnownSidType.WorldSid, null);

    // Quyen doc + ghi + xoa, KHONG bao gom ExecuteFile (0x1)
    private const FileSystemRights DataRights =
        FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete |
        FileSystemRights.Synchronize;

    // FileSystemRights.Write = WriteData|AppendData|WriteExtendedAttributes|WriteAttributes
    // = 0x116 = phan "viet" cua FILE_GENERIC_WRITE (0x120116) - dung de khoa.
    private const FileSystemRights WriteMask =
        FileSystemRights.Write | FileSystemRights.Delete | FileSystemRights.DeleteSubdirectoriesAndFiles;

    // Quyen khi MO KHOA: cho phep ghi lai bo file chi dau, nhung van cam
    // chay file thuc thi o thu muc goc.
    private const FileSystemRights UnlockRights =
        FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete |
        FileSystemRights.Synchronize;

    // ==================================================================
    // 1. CONG THUC inf.bin
    // ==================================================================

    /// <summary>MD5 hex lowercase tren byte ANSI.</summary>
    public static string Md5Hex(string s)
    {
        byte[] h = MD5.HashData(Encoding.Latin1.GetBytes(s));
        return Convert.ToHexString(h).ToLowerInvariant();
    }

    /// <summary>
    /// XOR keo doi - tuong duong ham 0x9219F8 (MiAV) va 0x428F20 (USB_ATTT).
    /// Khoa lap theo CHI SO KY TU (code unit), khong phai theo byte.
    /// </summary>
    private static string Xor(string data, string key)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentException("Khoa rong", nameof(key));

        var sb = new StringBuilder(data.Length);
        for (int i = 0; i < data.Length; i++)
            sb.Append((char)(data[i] ^ key[i % key.Length]));
        return sb.ToString();
    }

    /// <summary>
    /// Tao noi dung 4 dong cua inf.bin (ket thuc bang CRLF), y hiuot byte-exact
    /// voi san pham USB_ATTT.exe.
    /// </summary>
    public static byte[] BuildInfBin(string version, string vendor, string seed)
    {
        string k1 = Md5Hex(seed);          // hex da lowercase san
        string k2 = Md5Hex(k1);

        string E(string x) => Xor(Xor(Xor(x, k2), k1), seed);

        // XOR la phan tu khong doi (E(E(x)) = x):
        //   - E(version) = ciphertext  -> Base64  => Lines[0], Lines[1]
        string v0 = E(version);
        string v1 = E(vendor);

        string l0 = Convert.ToBase64String(Encoding.Latin1.GetBytes(v0));
        string l1 = Convert.ToBase64String(Encoding.Latin1.GetBytes(v1));

        // L3 = MD5(plaintext_version + plaintext_vendor + K)
        string l3 = Md5Hex(version + vendor + seed);

        string text = l0 + "\r\n" + l1 + "\r\n" + seed + "\r\n" + l3 + "\r\n";
        return Encoding.Latin1.GetBytes(text);
    }

    /// <summary>
    /// Kiem tra lai inf.bin theo dung thu tu Ma MiAV (CheckFileUSB @ 0x914440).
    /// </summary>
    public static bool VerifyInfBin(byte[] data, out string version, out string vendor)
    {
        version = string.Empty;
        vendor = string.Empty;
        if (data == null || data.Length == 0) return false;

        string text = Encoding.Latin1.GetString(data);
        string[] lines = text.Split(new[] { "\r\n" }, StringSplitOptions.None);
        if (lines.Length < 4) return false;

        string l0 = lines[0], l1 = lines[1], seed = lines[2], l3 = lines[3];
        if (string.IsNullOrEmpty(seed)) return false;

        byte[] a, b;
        try
        {
            a = Convert.FromBase64String(l0.Trim());
            b = Convert.FromBase64String(l1.Trim());
        }
        catch (FormatException) { return false; }

        string k1 = Md5Hex(seed);
        string k2 = Md5Hex(k1);
        string E(string x) => Xor(Xor(Xor(x, k2), k1), seed);

        // Giai ma ciphertext -> plaintext
        string v0 = E(Encoding.Latin1.GetString(a));
        string v1 = E(Encoding.Latin1.GetString(b));

        // L3 = MD5(plaintext_version + plaintext_vendor + K)
        string expect = Md5Hex(v0 + v1 + seed);

        version = v0;
        vendor = v1;
        return string.Equals(expect, l3.Trim().ToLowerInvariant(), StringComparison.Ordinal);
    }

    // ==================================================================
    // 2. ICON TOI THIEU (cho attt.ico)
    // ==================================================================

    /// <summary>Sinh file .ico 16x16 hop le (32bpp) cho attt.ico.</summary>
    public static byte[] BuildTinyIcon()
    {
        const int W = 16, H = 16;
        int xorSize = W * H * 4;
        int andSize = 4 * H;               // 1bpp, moi hang lam tron 4 byte
        int dibSize = 40 + xorSize + andSize;

        using var ms = new MemoryStream();
        using var w = new BinaryWriter(ms);

        // ICONDIR
        w.Write((ushort)0);                // reserved
        w.Write((ushort)1);                // 1 = icon
        w.Write((ushort)1);                // so anh

        // ICONDIRENTRY
        w.Write((byte)W);
        w.Write((byte)H);
        w.Write((byte)0);                  // so mau
        w.Write((byte)0);                  // reserved
        w.Write((ushort)1);                // planes
        w.Write((ushort)32);               // bitcount
        w.Write(dibSize);
        w.Write(22);                       // offset

        // BITMAPINFOHEADER
        w.Write(40);
        w.Write(W);
        w.Write(H * 2);                    // chieu cao x2 (XOR + AND)
        w.Write((ushort)1);
        w.Write((ushort)32);
        w.Write(0);                        // compression = BI_RGB
        w.Write(xorSize + andSize);
        w.Write(0); w.Write(0);
        w.Write(0); w.Write(0);

        // XOR bitmap (BGRA) - mau xanh la hai
        for (int y = 0; y < H; y++)
            for (int x = 0; x < W; x++)
            {
                w.Write((byte)0xB0);
                w.Write((byte)0x80);
                w.Write((byte)0x30);
                w.Write((byte)0xFF);
            }

        // AND mask
        for (int i = 0; i < andSize; i++) w.Write((byte)0);

        w.Flush();
        return ms.ToArray();
    }

    // ==================================================================
    // 3. DACL - BO CUC AN TOAN
    // ==================================================================

    /// <summary>
    /// Dat DACL tren thu muc goc: CAM moi nguoi co quyen GHI/XOA, cho phep DOC.
    /// Day la dieu kien bat buoc - MiAV goi AccessCheck voi FILE_GENERIC_WRITE
    /// tren &lt;drive&gt;:\ va neu user CO quyen ghi => phan loai "Khong an toan" => KHOA.
    ///
    /// ACE Deny phai la EXPLICIT (khong inherited) va phai dat TRUOC khi
    /// gan ACE Allow, vi Windows so sanh ACE theo thu tu (Deny truoc Allow).
    /// </summary>
    public static void ApplyDenyWriteToDirectory(string dirPath)
    {
        var dir = new DirectoryInfo(dirPath);
        var sec = dir.GetAccessControl(AccessControlSections.Access);

        // Xoa cac ACE Deny Everyone cu (neu co) de tranh trung lap
        RemoveExplicitDenyEveryone(sec);

        // DENY ghi/xoa - explicit, ke thua xuong con
        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            WriteMask,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Deny));

        // ALLOW doc + doc/chay (de doc duoc file chidau)
        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            FileSystemRights.ReadAndExecute | FileSystemRights.Synchronize,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        dir.SetAccessControl(sec);
    }

    /// <summary>Dat DACL tren mot file: cam ghi/xoa, cho phep doc.</summary>
    public static void ApplyDenyWriteToFile(string filePath)
    {
        var fi = new FileInfo(filePath);
        var sec = fi.GetAccessControl(AccessControlSections.Access);

        RemoveExplicitDenyEveryone(sec);

        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            FileSystemRights.Write | FileSystemRights.Delete,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Deny));

        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            FileSystemRights.Read | FileSystemRights.Synchronize,
            InheritanceFlags.None,
            PropagationFlags.None,
            AccessControlType.Allow));

        fi.SetAccessControl(sec);
    }

    /// <summary>
    /// Khoa quyen ghi/xoa cho thu muc goc VAI toan bo file/thu muc con
    /// (tru thu muc DATA - no co DACL rieng, xem ApplySafeLayout).
    /// </summary>
    public static void ApplyDenyWriteRecursive(string dirPath)
    {
        var dir = new DirectoryInfo(dirPath);

        // 1. Khoa cac file con truoc
        foreach (FileInfo f in dir.GetFiles())
        {
            try { ApplyDenyWriteToFile(f.FullName); }
            catch (Exception) { /* bo qua file nao khong sua duoc */ }
        }

        // 2. Khoa cac thu muc con (de chan ghi xuong cay)
        foreach (DirectoryInfo sub in dir.GetDirectories())
        {
            // Khong xu ly thu muc DATA - no co DACL rieng (doc/ghi, cam chay exe)
            if (sub.Name.Equals(DirData, StringComparison.OrdinalIgnoreCase)) continue;
            try { ApplyDenyWriteRecursive(sub.FullName); }
            catch (Exception) { /* bo qua */ }
        }

        // 3. Khoa thu muc goc - day la dieu MiAV AccessCheck
        try { ApplyDenyWriteToDirectory(dirPath); }
        catch (Exception) { /* bo qua */ }
    }

    /// <summary>
    /// Gan DACL cho thu muc DATA: PHEP DOC/GHI/XOA nhung CAM CHAY file thuc thi.
    ///
    /// - SetAccessRuleProtection(true, false): CAT ke thua tu thu muc cha
    ///   (bo Deny Write ke thua tu root) - bat buoc, vi Deny thang Allow.
    /// - Allow Everyone: Read|Write|Delete|Synchronize (KHONG co ExecuteFile).
    /// - Deny  Everyone: ExecuteFile (0x1), ke thua xuong moi file con
    ///   => file .exe/.bat/.cmd/.ps1 trong DATA khong the chay,
    ///      nhung van copy qua lai va doc binh thuong.
    /// </summary>
    public static void ApplyDataFolderAcl(string dataPath)
    {
        var dir = new DirectoryInfo(dataPath);
        var sec = dir.GetAccessControl(AccessControlSections.Access);

        // Cat ke thua: bo cac ACE inherited (Deny Write tu root)
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        RemoveExplicitDenyEveryone(sec);

        // Cho phep doc/ghi/xoa - KHONG cap ExecuteFile
        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            DataRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        // Cam chay file thuc thi
        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            FileSystemRights.ExecuteFile,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Deny));

        dir.SetAccessControl(sec);

        // Cac file/thu muc con co san tu truoc -> sua lai cho nhat quan
        ApplyDataAclToChildren(dataPath);
    }

    /// <summary>Ap dung lai DACL DATA cho toan bo cay con (bo Deny Write ke thua).</summary>
    private static void ApplyDataAclToChildren(string dirPath)
    {
        var dir = new DirectoryInfo(dirPath);

        foreach (FileInfo f in dir.GetFiles())
        {
            try
            {
                var sec = f.GetAccessControl(AccessControlSections.Access);
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                RemoveExplicitDenyEveryone(sec);
                sec.AddAccessRule(new FileSystemAccessRule(
                    EveryoneSid, DataRights,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(
                    EveryoneSid, FileSystemRights.ExecuteFile,
                    InheritanceFlags.None, PropagationFlags.None, AccessControlType.Deny));
                f.SetAccessControl(sec);
            }
            catch (Exception) { /* bo qua */ }
        }

        foreach (DirectoryInfo sub in dir.GetDirectories())
        {
            try
            {
                var sec = sub.GetAccessControl(AccessControlSections.Access);
                sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
                RemoveExplicitDenyEveryone(sec);
                sec.AddAccessRule(new FileSystemAccessRule(
                    EveryoneSid, DataRights,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Allow));
                sec.AddAccessRule(new FileSystemAccessRule(
                    EveryoneSid, FileSystemRights.ExecuteFile,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None, AccessControlType.Deny));
                sub.SetAccessControl(sec);
            }
            catch (Exception) { /* bo qua */ }

            ApplyDataAclToChildren(sub.FullName);
        }
    }

    /// <summary>
    /// Bo cuc an toan day du. THU TU QUAN TRONG:
    ///
    ///   1. Tao thu muc DATA TRUOC (khi goc chua bi khoa - can quyen tao
    ///      thu muc con, ma Deny Write cua goc che het quyen nay).
    ///   2. Khoa ghi tren thu muc GOC (dieu kien bat buoc de MiAV khong khoa o),
    ///      BO QUA cay DATA.
    ///   3. Gan DACL RIENG cho DATA: cat ke thua Deny Write tu goc, cap quyen
    ///      doc/ghi/xoa, cam chay file thuc thi.
    ///
    /// Vì sao DATA phai gan SAU khi khoa goc? Vì khi gan Deny co ke thua
    /// (OI|CI) len thu muc goc, Windows TU DONG day ACE Deny do xuong moi
    /// thu muc con DA TON TAI - ke ca DATA. Deny thang Allow => DATA bi chan
    /// ghi. Gan sau + SetAccessRuleProtection(true,false) se cat ke thua va
    /// thay bang DACL rieng cua DATA.
    /// </summary>
    public static void ApplySafeLayout(string root)
    {
        // 1. Tao thu muc DATA truoc khi khoa goc
        string dataPath = Path.Combine(root, DirData);
        Directory.CreateDirectory(dataPath);

        // 2. Khoa ghi o thu muc goc + file chi dau (dieu kien MiAV), bo qua DATA
        ApplyDenyWriteRecursive(root);

        // 3. Gan DACL rieng cho DATA: doc/ghi duoc, cam chay exe
        ApplyDataFolderAcl(dataPath);
    }

    // ==================================================================
    // 4. GIAI PHOA
    // ==================================================================

    /// <summary>
    /// Go khoa quyen ghi: bo ACE Deny cua Everyone, cat ke thua, tra quyen
    /// doc/ghi cho moi nguoi (nhung van khong cho chay file thuc thi o goc).
    ///
    /// LUU Y: sau khi go, MiAV se KHONG con cong nhan o la "USB an toan"
    /// (user co quyen ghi => "Khong an toan").
    ///
    /// QUAN TRONG: phai dung SetAccessRuleProtection(true,false) de CAT ke thua.
    /// Neu chi go ACE Deny explicit ma giu nguyen ke thua, thi ACE Deny
    /// ke thua tu thu muc cha van con hieu luc va ghi van bi chan.
    /// </summary>
    public static void RestoreWriteAccess(string dirPath)
    {
        RestoreWriteAccessRecursive(dirPath);
    }

    private static void RestoreWriteAccessRecursive(string dirPath)
    {
        var dir = new DirectoryInfo(dirPath);
        SecurityIdentifier? me = WindowsIdentity.GetCurrent().User;

        // Owner luon co WRITE_DAC implicit nen sua duoc DACL du bi DENY.
        try
        {
            var owner = dir.GetAccessControl(AccessControlSections.None);
            if (me != null) owner.SetOwner(me);
            dir.SetAccessControl(owner);
        }
        catch (UnauthorizedAccessException) { /* thu tiep ben duoi */ }
        catch (Exception) { /* bo qua */ }

        var sec = dir.GetAccessControl(AccessControlSections.Access);

        // CAT ke thua (bo Deny Write ke thua tu thu muc cha)
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        RemoveExplicitDenyEveryone(sec);

        // Cho phep doc/ghi/xoa cho moi nguoi
        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid,
            UnlockRights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        // Owner luon co quyen day du (de quan tri)
        if (me != null)
        {
            sec.SetAccessRule(new FileSystemAccessRule(
                me,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        }

        dir.SetAccessControl(sec);

        // Cac file con cung co deny rule rieng -> sua tiep
        foreach (FileInfo f in dir.GetFiles())
        {
            try { RestoreWriteAccessToFile(f.FullName, me); }
            catch (Exception)
            {
                // File bi "khoa" boi ACE Deny -> thu ghi de bang quyen WRITE_DAC
                ForceResetFileAcl(f.FullName);
            }
        }

        foreach (DirectoryInfo sub in dir.GetDirectories())
        {
            try { RestoreWriteAccessRecursive(sub.FullName); }
            catch (Exception) { /* bo qua */ }
        }
    }

    private static void RestoreWriteAccessToFile(string filePath, SecurityIdentifier? me)
    {
        var fi = new FileInfo(filePath);
        var sec = fi.GetAccessControl(AccessControlSections.Access);
        sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        RemoveExplicitDenyEveryone(sec);

        sec.AddAccessRule(new FileSystemAccessRule(
            EveryoneSid, UnlockRights,
            InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

        if (me != null)
            sec.SetAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));

        fi.SetAccessControl(sec);
    }

    /// <summary>
    /// Ghi de DACL cua file theo quyen WRITE_DAC cua owner.
    /// Dung khi file bi "khoa" boi ACE Deny explicit ma SetAccessControl
    /// thong thuong bi tu choi (access denied).
    /// </summary>
    public static bool ForceResetFileAcl(string filePath)
    {
        try
        {
            var fi = new FileInfo(filePath);
            SecurityIdentifier? me = WindowsIdentity.GetCurrent().User;
            if (me == null) return false;

            // Owner luon co WRITE_DAC implicit
            var owner = fi.GetAccessControl(AccessControlSections.None);
            owner.SetOwner(me);
            fi.SetAccessControl(owner);

            var sec = fi.GetAccessControl(AccessControlSections.Access);
            sec.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            RemoveExplicitDenyEveryone(sec);
            sec.AddAccessRule(new FileSystemAccessRule(
                EveryoneSid, UnlockRights,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            sec.SetAccessRule(new FileSystemAccessRule(me, FileSystemRights.FullControl,
                InheritanceFlags.None, PropagationFlags.None, AccessControlType.Allow));
            fi.SetAccessControl(sec);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>Xoa tat ca ACE Deny explicit cua Everyone khoi DACL.</summary>
    private static void RemoveExplicitDenyEveryone(FileSystemSecurity sec)
    {
        var rules = sec.GetAccessRules(true, true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule r in rules)
        {
            if (!r.IsInherited
                && r.AccessControlType == AccessControlType.Deny
                && r.IdentityReference.Equals(EveryoneSid))
            {
                sec.RemoveAccessRule(r);
            }
        }
    }
}
