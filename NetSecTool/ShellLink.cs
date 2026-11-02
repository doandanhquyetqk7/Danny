using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace NetSecTool;

/// <summary>
///  Tao file shortcut Windows (.lnk) ho tro TEN FILE UNICODE (tieng Viet co dau).
///
///  <para>Khong the dung <c>WScript.Shell</c> (COM Automation) vi no chuyen
///  chuoi sang ANSI: ten file "Lắng nghe" se bi bien thanh "L?ng nghe" va
///  khong tao duoc shortcut. Boi day phai dung truc tiep COM
///  <c>IShellLinkW</c> (ban Unicode) + <c>IPersistFile</c>.</para>
///
///  <para>Neu can fallback, dung <c>CreateWithWsScript</c> (chi dat duoc khi ten
///  file ASCII).</para>
/// </summary>
internal static class ShellLink
{
    // ==================================================================
    //  COM interop
    // ==================================================================

    [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
    private class ShellLinkCoClass { }

    [ComImport, Guid("000214F9-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile,
                     int cch, IntPtr pfd, uint fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName,
                            int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir,
                                 int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs,
                          int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath,
                             int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
        void Resolve(IntPtr hwnd, uint fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport, Guid("0000010b-0000-0000-C000-000000000046"),
     InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistFile
    {
        void GetClassID(out Guid pClassID);
        [PreserveSig] int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string pszFileName);
        void GetCurFile([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder ppszFileName);
    }

    private const int SW_SHOWMINIMIZED = 7;

    // ==================================================================
    //  Tao shortcut Unicode
    // ==================================================================

    /// <summary>
    ///  Tạo shortcut .lnk. Trả về true nếu thành công.
    /// </summary>
    public static bool Create(string linkPath, string targetPath, string arguments,
                             string workingDir, string description,
                             int showCmd = SW_SHOWMINIMIZED,
                             string? iconLocation = null)
    {
        object? linkObj = null;
        try
        {
            linkObj = new ShellLinkCoClass();
            var link = (IShellLinkW)linkObj;

            link.SetPath(targetPath);
            if (!string.IsNullOrEmpty(arguments))
                link.SetArguments(arguments);
            if (!string.IsNullOrEmpty(workingDir))
                link.SetWorkingDirectory(workingDir);
            if (!string.IsNullOrEmpty(description))
                link.SetDescription(description);
            link.SetShowCmd(showCmd);
            if (!string.IsNullOrEmpty(iconLocation))
            {
                int iIcon = 0;
                int comma = iconLocation.LastIndexOf(',');
                if (comma > 0 && int.TryParse(iconLocation.Substring(comma + 1), out int parsed))
                    iIcon = parsed;
                link.SetIconLocation(iconLocation, iIcon);
            }

            var persist = (IPersistFile)link;
            persist.Save(linkPath, true);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
        finally
        {
            if (linkObj != null)
                Marshal.ReleaseComObject(linkObj);
        }
    }

    /// <summary>
    ///  Cách dự phòng bằng WScript.Shell. CHỈ dùng được khi tên file ASCII
    ///  (COM này dùng ANSI nên tiếng Việt có dấu sẽ hỏng).
    /// </summary>
    public static bool CreateWithWsScript(string linkPath, string targetPath, string arguments,
                                         string workingDir, string description,
                                         string? iconLocation = null)
    {
        try
        {
            var shellType = Type.GetTypeFromProgID("WScript.Shell");
            if (shellType == null) return false;

            dynamic shell = Activator.CreateInstance(shellType)!;
            dynamic lnk = shell.CreateShortcut(linkPath);
            lnk.TargetPath = targetPath;
            lnk.Arguments = arguments;
            lnk.WorkingDirectory = workingDir;
            lnk.Description = description;
            lnk.WindowStyle = SW_SHOWMINIMIZED;
            if (!string.IsNullOrEmpty(iconLocation))
                lnk.IconLocation = iconLocation;
            lnk.Save();

            return File.Exists(linkPath);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    ///  Tạo shortcut với tên file ASCII an toàn (dùng khi tên Unicode thất bại).
    /// </summary>
    public static bool CreateSafeAscii(string linkPath, string targetPath, string arguments,
                                       string workingDir, string description,
                                       string? iconLocation = null)
    {
        return Create(linkPath, targetPath, arguments, workingDir, description,
                      SW_SHOWMINIMIZED, iconLocation);
    }
}
