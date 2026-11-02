using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace NetSecTool;

/// <summary>
/// Dich vu "Cau hinh IP mot cham" - tu dong gan dia chi IP tinh dung dai
/// da duoc cap cho don vi, cho ca nguoi dung khong co kien thuc ve IP.
///
/// Quy trinh (theo "Cau hinh IP mot cham.md"):
///   1. Tim card mang vat ly dang Link Up (bo qua card ao, card da co IP hop le)
///   2. Xac dinh dai mang LAN cua don vi (tu bang quy hoach trong IpPlan)
///   3. Chon IP trong khoang an toan (.150 - .200) va kiem tra bang ARP
///   4. Luu cau hinh cu de co the hoan tac (rollback)
///   5. Gan IP + DNS = 86.0.188.1 bang netsh
///   6. Kiem tra ping gateway; fail -> tu dong khoi phuc cau hinh cu
/// </summary>
internal static class OneClickIpService
{
    /// <summary>Trang thai trong qua cua quy trinh.</summary>
    internal enum Stage
    {
        Idle,
        DetectAdapter,
        ResolveUnit,
        FindFreeIp,
        Backup,
        Apply,
        Verify,
        Done,
        Failed,
        RolledBack
    }

    /// <summary>Ket qua cua mot lan chay.</summary>
    internal sealed class Outcome
    {
        public bool Success { get; init; }
        public Stage FinalStage { get; init; }
        public string AdapterName { get; init; } = "";
        public string IpAddress { get; init; } = "";
        public string SubnetMask { get; init; } = "";
        public string Gateway { get; init; } = "";
        public string Dns { get; init; } = "";
        public string UnitName { get; init; } = "";
        public string UnitLan { get; init; } = "";
        public string UnitWan { get; init; } = "";
        public string Message { get; init; } = "";
        public bool RolledBack { get; init; }
        public string BackupPath { get; init; } = "";
    }

    /// <summary>Thong tin cau hinh cu duoc luu de hoan tac.</summary>
    private sealed class Backup
    {
        public string AdapterName { get; init; } = "";
        public string OldIp { get; init; } = "";
        public string OldMask { get; init; } = "";
        public string OldGateway { get; init; } = "";
        public string OldDns { get; init; } = "";
        public bool WasDhcp { get; init; }
    }

    // --- Khoang IP an toan: tranh .1-.50 (thiet bi) va .250-.254 (gateway) ---
    private const int SafeHostLow = 150;
    private const int SafeHostHigh = 200;

    /// <summary>Chay day quy trinh cau hinh IP mot cham.</summary>
    /// <param name="unit">Don vi duoc chon (null = tu phat hien theo gateway hien tai).</param>
    /// <param name="progress">Callback bao trang thai theo tung buoc.</param>
    /// <param name="cancellation">Token huy tac.</param>
    public static async Task<Outcome> RunAsync(
        IpPlan.Unit? unit,
        Action<Stage, string>? progress = null,
        CancellationToken cancellation = default)
    {
        void Report(Stage s, string msg) => progress?.Invoke(s, msg);

        // ============================================================
        // BUOC 1 - TIM CARD MANG VAT LY DANG LINK UP
        // ============================================================
        Report(Stage.DetectAdapter, "Dang tim card mang vat ly...");

        var nics = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType == NetworkInterfaceType.Ethernet
                     || n.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet
                     || n.NetworkInterfaceType == NetworkInterfaceType.FastEthernetT
                     || n.NetworkInterfaceType == NetworkInterfaceType.FastEthernetFx)
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .ToList();

        // Bo qua card ao (VMware / VirtualBox / Hyper-V / Loopback)
        nics = nics
            .Where(n => !IsVirtual(n))
            .ToList();

        if (nics.Count == 0)
        {
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.DetectAdapter,
                Message = "Khong tim thay card mang vat ly dang co cap (Link Up).\n\n" +
                          "Hay kiem tra cap mang va cong switch, roi thu lai."
            };
        }

        // Uu tien card Ethernet ten "Ethernet" (Ten moi trong Windows 11)
        var nic = nics.FirstOrDefault(n =>
                    n.Name.Equals("Ethernet", StringComparison.OrdinalIgnoreCase))
               ?? nics[0];

        string adapterName = nic.Name;

        // ============================================================
        // BUOC 2 - XAC DINH DON VI (dai LAN)
        // ============================================================
        Report(Stage.ResolveUnit, $"Dang xac dinh don vi qua card '{adapterName}'...");

        string currentIp = GetPrimaryIp(nic);
        string currentGateway = GetGateway(nic);

        IpPlan.Unit? target = unit;

        if (target == null)
        {
            // Thu tu uu tien:
            //   1. Theo dai LAN cua IP hien tai (chinh xac nhat)
            //   2. Theo gateway LAN - CHI khop khi gateway do chi dung cho 1 don vi
            var gwCandidates = IpPlan.FindByGatewayCandidates(currentGateway);

            target = IpPlan.FindByLanIp(currentIp);
            target ??= (gwCandidates.Count == 1 ? gwCandidates[0] : null);

            if (target == null && gwCandidates.Count > 1)
            {
                return new Outcome
                {
                    Success = false,
                    FinalStage = Stage.ResolveUnit,
                    AdapterName = adapterName,
                    Message = $"Gateway {currentGateway} được dùng chung cho {gwCandidates.Count} đơn vị:\n" +
                              $"   {string.Join("\n   ", gwCandidates.Select(u => u.Name))}\n\n" +
                              "Không thể tự xác định. Hãy chọn đơn vị trong danh sách phía trên."
                };
            }
        }

        if (target == null)
        {
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.ResolveUnit,
                AdapterName = adapterName,
                Message = "Khong xac dinh duoc don vi nao tu cau hinh hien tai.\n\n" +
                          $"IP hien tai      : {(string.IsNullOrEmpty(currentIp) ? "(chua co)" : currentIp)}\n" +
                          $"Default gateway  : {(string.IsNullOrEmpty(currentGateway) ? "(khong co)" : currentGateway)}\n\n" +
                          "Hay chon don vi trong danh sach roi bam 'Cau hinh IP mot cham'."
            };
        }

        Report(Stage.ResolveUnit,
            $"Don vi: {target.Name}\n" +
            $"  Dai LAN : {target.LanCidr} (mask {target.SubnetMask})\n" +
            $"  Gateway : {target.LanGateway}\n" +
            $"  IP WAN  : {target.WanIp}");

        // ============================================================
        // BUOC 3 - TIM IP TRONG (trong khoang an toan)
        // ============================================================
        Report(Stage.FindFreeIp, "Dang tim dia chi IP trong khoang an toan...");

        string subnet = target.SubnetMask;
        int prefix = MaskToPrefix(subnet);

        // Canh dai: lay tu CIDR chu khong phai tu gateway.
        //
        // Ly do: dung CIDR la nguon su that cua bang quy hoach. (Neu gateway
        // cua don vi nao do nam ngoai dai LAN, thi tinh theo gateway se sinh
        // ra IP nam NGOAI dai - sai. Thong tin gateway chi dung de gan, con
        // IP duoc chon theo dai LAN.)
        int block = 256 >> Math.Max(prefix - 24, 0);
        string[] gwParts = target.LanGateway.Split('.');

        if (!IpPlan.TryGetNetwork(target.LanCidr, out var netAddr))
        {
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.FindFreeIp,
                AdapterName = adapterName,
                UnitName = target.Name,
                Message = $"Dai LAN '{target.LanCidr}' khong hop le."
            };
        }

        var netBytes = netAddr.GetAddressBytes();
        string netPrefix = $"{netBytes[0]}.{netBytes[1]}.{netBytes[2]}";
        int baseHost = netBytes[3];

        // Tao danh sach offset host theo thu tu uu tien.
        //
        // Luu y quan trong: dai /27 chi co 32 dia chi (host duoc dung la
        // offset 1..30), nen khoang ".150 - .200" (theo y tuong ban an) KHONG
        // ton tai trong dai /27. Phai tinh offset TUONG DOI so voi canh dai.
        var candidates = new List<int>();
        if (block >= 64)
        {
            // Dai lon (>= /24): uu tien khoang giua 150-200, tranh .1-.50 va .250-.254
            for (int h = SafeHostLow; h <= SafeHostHigh; h++) candidates.Add(h);
            for (int h = 51; h < SafeHostLow; h++) candidates.Add(h);
            for (int h = 2; h <= 50; h++) candidates.Add(h);
        }
        else
        {
            // Dai nho (vd /27 = 32 dia chi): uu tien nua tren, tranh gateway va broadcast
            for (int h = block / 2; h <= block - 2; h++) candidates.Add(h);
            for (int h = 2; h < block / 2; h++) candidates.Add(h);
        }

        string chosenIp = "";
        foreach (int offset in candidates)
        {
            cancellation.ThrowIfCancellationRequested();

            int host = baseHost + offset;
            if (host >= baseHost + block) continue;     // vuot dai
            if (offset == 0) continue;                 // network address
            if (offset == block - 1) continue;         // broadcast
            if (host > 255) continue;

            string ip = $"{netPrefix}.{host}";

            // Bo qua dia chi dang chay tren may nay
            if (ip == currentIp) continue;

            if (!IsIpInUse(ip, currentIp))
            {
                chosenIp = ip;
                break;
            }
        }

        if (chosenIp == "")
        {
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.FindFreeIp,
                AdapterName = adapterName,
                UnitName = target.Name,
                Message = "Khong tim duoc dia chi IP trong khoang an toan.\n\n" +
                          $"Dai LAN {target.LanCidr} co the da day. " +
                          "Hay chon dia chi IP thu cong."
            };
        }

        Report(Stage.FindFreeIp, $"Da chon IP: {chosenIp} (kiem tra ARP: khong co phan hoi).");

        // ============================================================
        // BUOC 4 - LUU CAU HINH CU (rollback)
        // ============================================================
        Report(Stage.Backup, "Dang luu cau hinh cu de co the hoan tac...");

        var backup = new Backup
        {
            AdapterName = adapterName,
            OldIp = currentIp,
            OldMask = GetMask(nic),
            OldGateway = currentGateway,
            OldDns = GetDns(nic),
            WasDhcp = IsDhcp(nic)
        };

        string backupPath = SaveBackup(backup, target);
        Report(Stage.Backup, $"Da luu cau hinh cu: {backupPath}");

        // ============================================================
        // BUOC 5 - AP DUNG IP + DNS
        // ============================================================
        Report(Stage.Apply, $"Dang gan IP tinh {chosenIp} cho '{adapterName}'...");

        string dns = IpPlan.MilitaryDns;

        bool ok = RunNetsh($"interface ip set address \"{adapterName}\" static " +
                            $"{chosenIp} {subnet} {target.LanGateway}");
        if (!ok)
        {
            RestoreBackup(backup);
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.Failed,
                RolledBack = true,
                AdapterName = adapterName,
                IpAddress = chosenIp,
                SubnetMask = subnet,
                Gateway = target.LanGateway,
                Dns = dns,
                UnitName = target.Name,
                BackupPath = backupPath,
                Message = "Khong gan duoc IP tinh. Da khoi phuc cau hinh cu."
            };
        }

        // DNS: dat ca DNS quan su va DNS phu (neu dat duoc)
        RunNetsh($"interface ip set dns \"{adapterName}\" static {dns} primary");
        RunNetsh($"interface ip set dns \"{adapterName}\" static 8.8.8.8 secondary");

        // ============================================================
        // BUOC 6 - KIEM TRA PING GATEWAY (rollback neu fail)
        // ============================================================
        Report(Stage.Verify, "Dang kiem tra ket noi toi gateway...");

        var gwPing = NetDiagnostics.Ping(target.LanGateway, 4, 5);
        if (!gwPing.Reachable)
        {
            Report(Stage.RolledBack, "Khong ping duoc gateway - dang khoi phuc cau hinh cu...");
            RestoreBackup(backup);
            return new Outcome
            {
                Success = false,
                FinalStage = Stage.RolledBack,
                RolledBack = true,
                AdapterName = adapterName,
                IpAddress = chosenIp,
                SubnetMask = subnet,
                Gateway = target.LanGateway,
                Dns = dns,
                UnitName = target.Name,
                UnitLan = target.LanCidr,
                UnitWan = target.WanIp,
                BackupPath = backupPath,
                Message = "Da gan IP nhung KHONG PING DUOC gateway.\n\n" +
                          "Phan mềm đã tự động khôi phục cấu hình cũ để tránh mất kết nối."
            };
        }

        Report(Stage.Done, "Hoan tat.");

        return new Outcome
        {
            Success = true,
            FinalStage = Stage.Done,
            AdapterName = adapterName,
            IpAddress = chosenIp,
            SubnetMask = subnet,
            Gateway = target.LanGateway,
            Dns = dns,
            UnitName = target.Name,
            UnitLan = target.LanCidr,
            UnitWan = target.WanIp,
            BackupPath = backupPath,
            Message = $"Đã cấu hình IP tinh cho '{adapterName}'.\n\n" +
                      $"Đơn vị   : {target.Name}\n" +
                      $"IP       : {chosenIp}/{subnet}\n" +
                      $"Gateway  : {target.LanGateway}\n" +
                      $"DNS      : {dns}\n" +
                      $"Độ trễ GW : {gwPing.AvgMs} ms | Mất gói: {gwPing.LossPercent}%"
        };
    }

    // ==================================================================
    // TIEN ICH
    // ==================================================================

    /// <summary>Card ao (VMware / VirtualBox / Hyper-V / TAP) hay khong.</summary>
    private static bool IsVirtual(NetworkInterface nic)
    {
        string d = nic.Description.ToLowerInvariant();
        string n = nic.Name.ToLowerInvariant();

        string[] virtualHints =
        {
            "vmware", "virtualbox", "vbox", "hyper-v", "microsoft hyper",
            "tap-windows", "loopback", "teredo", "isatap", "npcap", "bluetooth",
            "tailscale", "zerotier", "wireguard"
        };

        return virtualHints.Any(h => d.Contains(h) || n.Contains(h));
    }

    /// <summary>Lay IP IPv4 chinh cua card (bo qua link-local 169.254.x.x).</summary>
    private static string GetPrimaryIp(NetworkInterface nic)
    {
        try
        {
            var addrs = nic.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.Address)
                .ToList();

            // Uu tien IP khong phai APIPA
            var normal = addrs.FirstOrDefault(a => !IsApipa(a));
            if (normal != null) return normal.ToString();

            if (addrs.Count > 0) return addrs[0].ToString();
        }
        catch { }
        return "";
    }

    private static bool IsApipa(IPAddress a)
    {
        var b = a.GetAddressBytes();
        return b.Length == 4 && b[0] == 169 && b[1] == 254;
    }

    /// <summary>Lay default gateway cua card.</summary>
    public static string GetGateway(NetworkInterface nic)
    {
        try
        {
            var gw = nic.GetIPProperties().GatewayAddresses
                .Where(g => g.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(g => g.Address.ToString())
                .FirstOrDefault();
            if (!string.IsNullOrEmpty(gw)) return gw;
        }
        catch { }
        return "";
    }

    /// <summary>Lay subnet mask cua card.</summary>
    private static string GetMask(NetworkInterface nic)
    {
        try
        {
            var mask = nic.GetIPProperties().UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.IPv4Mask)
                .FirstOrDefault(m => m != null);
            if (mask != null) return mask.ToString();
        }
        catch { }
        return "255.255.255.0";
    }

    /// <summary>Lay DNS server dang cau hinh.</summary>
    private static string GetDns(NetworkInterface nic)
    {
        try
        {
            var dns = nic.GetIPProperties().DnsAddresses
                .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                .Select(a => a.ToString())
                .FirstOrDefault();
            if (!string.IsNullOrEmpty(dns)) return dns;
        }
        catch { }
        return "";
    }

    /// <summary>Card dang dung DHCP hay khong.</summary>
    private static bool IsDhcp(NetworkInterface nic)
    {
        try
        {
            using var searcher = new System.Management.ManagementObjectSearcher(
                "SELECT DHCPEnabled FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
            foreach (System.Management.ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    string? v = obj["DHCPEnabled"]?.ToString();
                    if (string.Equals(v, "True", StringComparison.OrdinalIgnoreCase))
                        return true;
                }
            }
        }
        catch { }
        return false;
    }

    /// <summary>
    /// Kiem tra dia chi IP co dang duoc dung hay khong.
    /// Uu tien doc bang ARP (chi doc, khong gui goi tin - an toan cho moi truong
    /// co IDS/IPS). Chi khi doc khong duoc moi fallback sang ping nhe.
    /// </summary>
    private static bool IsIpInUse(string ip, string ownIp)
    {
        if (ip == ownIp) return true;

        try
        {
            var active = IpNetTable.GetActiveAddresses();
            if (active.Count > 0)
                return active.Contains(ip);
        }
        catch { }

        // Fallback: ping nhe - it goi tin, van dung cho muc dich
        try
        {
            var r = NetDiagnostics.Ping(ip, 1, 1);
            return r.Reachable;
        }
        catch { return false; }
    }

    /// <summary>Chay netsh va tra ve true neu thanh cong.</summary>
    private static bool RunNetsh(string args)
    {
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = args,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi);
            if (p == null) return false;

            string output = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(15000);

            // netsh bao loi bang "Loi ..." / "There is an error"
            if (output.Contains("Lỗi", StringComparison.OrdinalIgnoreCase) ||
                output.Contains("Error", StringComparison.OrdinalIgnoreCase))
                return false;

            return p.ExitCode == 0;
        }
        catch { return false; }
    }

    /// <summary>Luu cau hinh cu ra file de hoan tac hoac doi chieu.</summary>
    private static string SaveBackup(Backup b, IpPlan.Unit unit)
    {
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Danny", "backup");
            Directory.CreateDirectory(dir);

            string path = Path.Combine(dir,
                $"ip-backup-{DateTime.Now:yyyyMMdd-HHmmss}.txt");

            var sb = new StringBuilder();
            sb.AppendLine("# Sao luu cau hinh IP - Danny ver3.0");
            sb.AppendLine($"Thoi gian   : {DateTime.Now:dd/MM/yyyy HH:mm:ss}");
            sb.AppendLine($"May         : {Environment.MachineName}");
            sb.AppendLine($"Card mang   : {b.AdapterName}");
            sb.AppendLine($"Don vi      : {unit.Name} ({unit.LanCidr})");
            sb.AppendLine($"Che do cu   : {(b.WasDhcp ? "DHCP" : "Static")}");
            sb.AppendLine($"IP cu       : {b.OldIp}");
            sb.AppendLine($"Mask cu     : {b.OldMask}");
            sb.AppendLine($"Gateway cu  : {b.OldGateway}");
            sb.AppendLine($"DNS cu      : {b.OldDns}");
            sb.AppendLine();
            sb.AppendLine("# Lenh khoi phuc (mo CMD voi quyen Administrator):");
            if (b.WasDhcp)
            {
                sb.AppendLine($"netsh interface ip set address \"{b.AdapterName}\" source=dhcp");
                sb.AppendLine($"netsh interface ip set dns \"{b.AdapterName}\" source=dhcp");
            }
            else
            {
                sb.AppendLine($"netsh interface ip set address \"{b.AdapterName}\" static {b.OldIp} {b.OldMask} {b.OldGateway}");
                sb.AppendLine($"netsh interface ip set dns \"{b.AdapterName}\" static {b.OldDns}");
            }

            File.WriteAllText(path, sb.ToString(), new UTF8Encoding(true));
            return path;
        }
        catch { return ""; }
    }

    /// <summary>Khoi phuc cau hinh cu.</summary>
    private static void RestoreBackup(Backup b)
    {
        try
        {
            if (b.WasDhcp)
            {
                RunNetsh($"interface ip set address \"{b.AdapterName}\" source=dhcp");
                RunNetsh($"interface ip set dns \"{b.AdapterName}\" source=dhcp");
            }
            else if (!string.IsNullOrEmpty(b.OldIp))
            {
                RunNetsh($"interface ip set address \"{b.AdapterName}\" static " +
                         $"{b.OldIp} {b.OldMask} {b.OldGateway}");
                if (!string.IsNullOrEmpty(b.OldDns))
                    RunNetsh($"interface ip set dns \"{b.AdapterName}\" static {b.OldDns}");
            }
        }
        catch { }
    }

    /// <summary>Chuyen subnet mask sang dang prefix (de tinh dai host).</summary>
    public static int MaskToPrefix(string mask)
    {
        try
        {
            var b = IPAddress.Parse(mask).GetAddressBytes();
            int bits = 0;
            foreach (byte x in b) bits += System.Numerics.BitOperations.PopCount((uint)x);
            return bits;
        }
        catch { return 24; }
    }
}
