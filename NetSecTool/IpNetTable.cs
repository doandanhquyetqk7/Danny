using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Net;

namespace NetSecTool;

/// <summary>
/// Doc truc tiep bang ARP (GetIpNetTable) cua Windows de biet dia chi IP nao
/// dang "co mat" trong LAN.
///
/// Muc dich: KIEM TRA IP TRONG ma khong gui goi tin ra mang. Day la yeu cau
/// an toan trong moi truong quan su - khong duoc tao traffic lan nhom co the
/// lam canh bao IDS/IPS. ARP chi doc bang, khong gui broadcast.
///
/// Layout da XAC MINH doi chieu voi lenh "arp -a" (7/7 dia chi khop):
///   buffer: [dwNumEntries][dwTableSize]  roi den cac row, moi row 24 byte
///   row:    +0  dwPhysAddrLen
///           +4  bPhysAddr[8]
///           +12 dwAddr   (network byte order - dung truc tiep cho IPAddress)
///           +16 dwType    (3 = dynamic, 4 = static)
///           +20 dwIndex
/// </summary>
internal static class IpNetTable
{
    /// <summary>Mot dong trong bang ARP.</summary>
    internal readonly record struct Entry(string Address, string Mac, int Type);

    private const int HeaderSize = 8;
    private const int RowSize = 24;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr pIpNetTable, ref int pdwSize, bool bOrder);

    /// <summary>Lay toan bo dong trong bang ARP cua may.</summary>
    public static List<Entry> GetIpNetTable()
    {
        var result = new List<Entry>();

        try
        {
            int size = 0;
            // Lan 1: xin kich thuoc buffer (ERROR_INSUFFICIENT_BUFFER = 122)
            int ret = GetIpNetTable(IntPtr.Zero, ref size, false);
            if (ret != 122 || size <= 0) return result;

            IntPtr buf = Marshal.AllocHGlobal(size);
            try
            {
                ret = GetIpNetTable(buf, ref size, false);
                if (ret != 0) return result;

                byte[] all = new byte[size];
                Marshal.Copy(buf, all, 0, size);

                int count = BitConverter.ToInt32(all, 0);

                for (int i = 0; i < count; i++)
                {
                    int off = HeaderSize + i * RowSize;
                    if (off + RowSize > all.Length) break;

                    uint physLen = BitConverter.ToUInt32(all, off);

                    byte[] mac = new byte[6];
                    Array.Copy(all, off + 4, mac, 0, 6);

                    byte[] addr = new byte[4];
                    Array.Copy(all, off + 12, addr, 0, 4);

                    uint type = BitConverter.ToUInt32(all, off + 16);

                    result.Add(new Entry(
                        new IPAddress(addr).ToString(),
                        BitConverter.ToString(mac),
                        (int)type));
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buf);
            }
        }
        catch
        {
            // Khong doc duoc -> tra ve rong, caller dung fallback
        }

        return result;
    }

    /// <summary>
    /// Tra ve danh sach dia chi IP dang "co that" trong bang ARP.
    /// Chi lay dong co MAC hop le (khac 00-00-00-00-00-00) va loai dia chi
    /// multicast/broadcast (224.x, 239.x, 255.255.255.255) - vi day khong
    /// phai may thuong trong LAN.
    /// </summary>
    public static HashSet<string> GetActiveAddresses()
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var e in GetIpNetTable())
        {
            bool allZero = true;
            foreach (string part in e.Mac.Split('-'))
            {
                if (part.Length == 0) continue;
                if (byte.TryParse(part, System.Globalization.NumberStyles.HexNumber,
                                  null, out byte b) && b != 0)
                {
                    allZero = false;
                    break;
                }
            }

            if (allZero) continue;

            // Loai dia chi multicast (224.0.0.0/4) va broadcast toan cuc
            if (e.Address.StartsWith("224.", StringComparison.Ordinal) ||
                e.Address.StartsWith("239.", StringComparison.Ordinal) ||
                e.Address.StartsWith("255.", StringComparison.Ordinal))
                continue;

            set.Add(e.Address);
        }

        return set;
    }
}
