using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Management;
using System.Text;

namespace NetSecTool;

/// <summary>Muc do ket qua cua tung buoc chan doan.</summary>
internal enum CheckLevel
{
    Ok = 0,
    Warn = 1,
    Fail = 2,
    Info = 3
}

/// <summary>Ket qua cua mot buoc chan doan.</summary>
internal sealed class CheckResult
{
    public string Step { get; init; } = "";
    public CheckLevel Level { get; init; } = CheckLevel.Info;
    public string Message { get; init; } = "";
    public string Detail { get; init; } = "";

    public string Icon => Level switch
    {
        CheckLevel.Ok => "[ OK ]",
        CheckLevel.Warn => "[WARN]",
        CheckLevel.Fail => "[FAIL]",
        _ => "[INFO]"
    };
}

/// <summary>
/// Dich vu chan doan ket noi mang theo kieu "bottom-up" (tu tang thap len cao).
///
///   Buoc 1 - Cong vat ly & trang thai Link (Layer 1)
///   Buoc 2 - Driver & trang thai card mang (Win32_NetworkAdapter)
///   Buoc 3 - Ket noi cuc bo & Gateway / modem (Layer 2-3)
///   Buoc 4 - Dinh tuyen & phan giai ten mien (Routing + DNS + tracert)
///
/// Nguyên tac: buoc sau CHI chay khi buoc truoc khong that bai, va luon
/// "best effort" - khong bao gio lam treo phan mem.
///
/// Xem "Tich hop kiem tra ket noi vao NetSecTool.md" de xem yeu cau goc.
internal static class NetDiagnostics
{
    /// <summary>Truong hop nghien dung cho ca phep doan.</summary>
    public sealed class Options
    {
        /// <summary>Ten card mang can chan doan (neu rong => tu dong chon card co Link Up).</summary>
        public string AdapterName { get; init; } = "";

        /// <summary>Dia chi IP tinh (neu rong => lay tu card).</summary>
        public string IpAddress { get; init; } = "";

        /// <summary>Default gateway (neu rong => tu phat hien).</summary>
        public string Gateway { get; init; } = "";

        /// <summary>So lan ping moi muc tieu.</summary>
        public int PingCount { get; init; } = 4;

        /// <summary>Thoi gian cho toi da (giay) cho moi lenh ping/tracert.</summary>
        public int TimeoutSeconds { get; init; } = 8;

        /// <summary>Co chay tracert toi DNS quan su hay khong.</summary>
        public bool RunTracert { get; init; } = true;

        /// <summary>Co chay ping thu toi danh sach modem WAN hay khong.</summary>
        public bool TestModemWan { get; init; } = true;

        /// <summary>Ten file bao cao.</summary>
        public string ReportFile { get; init; } = "Bao cao ket noi.txt";

        /// <summary>
        /// Don vi do nguoi dung chon trong o tim kiem o tab 'KIEM TRA KET NOI'.
        /// Neu co, chan doan se so sanh gateway/IP hien tai voi don vi da chon
        /// thay vi chi tu dong nhan dien.
        /// </summary>
        public IpPlan.Unit? Unit { get; init; }
    }

    /// <summary>Diem dieu kien cho tung buoc chan doan.</summary>
    public sealed class Progress
    {
        private readonly Action<string>? _onStep;

        public Progress(Action<string>? onStep = null) { _onStep = onStep; }

        public void Report(string message) => _onStep?.Invoke(message);
    }

    // ==================================================================
    // DIEM VAO
    // ==================================================================

    /// <summary>
    /// Chay toan bo quy trinh chan doan 4 buoc.
    /// Tra ve danh sach ket qua + bao cao dang text.
    /// </summary>
    public static (List<CheckResult> Results, string Report) Run(Options opt, Progress? progress = null)
    {
        var results = new List<CheckResult>();
        var p = progress ?? new Progress();

        string adapterName = opt.AdapterName.Trim();
        NetworkInterface? nic = null;

        // ============================================================
        // BUOC 1 - CONG VAT LY & TRANG THAI LINK (LAYER 1)
        // ============================================================
        p.Report("Buoc 1: Kiem tra cong vat ly & trang thai link...");

        var allNics = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.NetworkInterfaceType != NetworkInterfaceType.Loopback
                     && n.NetworkInterfaceType != NetworkInterfaceType.Tunnel)
            .ToList();

        if (!string.IsNullOrEmpty(adapterName))
        {
            nic = allNics.FirstOrDefault(n =>
                n.Name.Equals(adapterName, StringComparison.OrdinalIgnoreCase) ||
                n.Description.Equals(adapterName, StringComparison.OrdinalIgnoreCase));
        }

        // Tu dong chon: uu tien Ethernet dang co Link Up
        nic ??= allNics.FirstOrDefault(n =>
                    n.NetworkInterfaceType == NetworkInterfaceType.Ethernet &&
                    n.OperationalStatus == OperationalStatus.Up)
               ?? allNics.FirstOrDefault(n => n.OperationalStatus == OperationalStatus.Up)
               ?? allNics.FirstOrDefault();

        if (nic == null)
        {
            results.Add(new CheckResult
            {
                Step = "1. Cong vat ly / Link",
                Level = CheckLevel.Fail,
                Message = "Khong tim thay card mang nao tren may.",
                Detail = "Hay kiem tra lai card mang hoac cau hinh."
            });
            return (results, BuildReport(results, opt));
        }

        string desc = nic.Description;
        string mac = FormatMac(nic.GetPhysicalAddress());

        if (nic.OperationalStatus != OperationalStatus.Up)
        {
            results.Add(new CheckResult
            {
                Step = "1. Cong vat ly / Link",
                Level = CheckLevel.Fail,
                Message = $"'{nic.Name}' ({desc}) CHUA LINK UP.",
                Detail = $"Trang thai: {nic.OperationalStatus}. " +
                         "Kiem tra cap mang, cong switch hoac card co bi vo hieu hoa khong."
            });
        }
        else
        {
            long speed = nic.Speed;
            string speedText = speed > 0
                ? (speed >= 1_000_000_000
                    ? (speed / 1_000_000_000.0).ToString("0.#", CultureInfo.InvariantCulture) + " Gbps"
                    : (speed / 1_000_000.0).ToString("0.#", CultureInfo.InvariantCulture) + " Mbps")
                : "khong ro";

            string duplex = nic.Speed > 0 ? "Full Duplex" : "";

            results.Add(new CheckResult
            {
                Step = "1. Cong vat ly / Link",
                Level = CheckLevel.Ok,
                Message = $"'{nic.Name}' ({desc}) LINK UP.",
                Detail = $"Toc do: {speedText} {duplex} | MAC: {mac} | Loai: {nic.NetworkInterfaceType}"
            });
        }

        // Thong tin IP cua card
        var ipProps = nic.GetIPProperties();
        var unicastInfos = ipProps.UnicastAddresses
            .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork)
            .ToList();

        var unicast = unicastInfos.Select(a => a.Address).ToList();

        string ip = opt.IpAddress.Trim();
        if (string.IsNullOrEmpty(ip) && unicast.Count > 0)
            ip = unicast[0].ToString();

        string subnetMask = unicastInfos.Count > 0 && unicastInfos[0].IPv4Mask != null
            ? unicastInfos[0].IPv4Mask.ToString()
            : "";
        if (string.IsNullOrEmpty(subnetMask)) subnetMask = "255.255.255.0";

        if (string.IsNullOrEmpty(ip))
        {
            results.Add(new CheckResult
            {
                Step = "1. Cong vat ly / Link",
                Level = CheckLevel.Warn,
                Message = "Card mang CHUA DUOC GAN DIA CHI IP.",
                Detail = "Hay dung tab 'CAU HINH IP MOT CHAM' de cau hinh dia chi IP tinh."
            });
        }

        // ============================================================
        // BUOC 1b - NHAN DIEN DON VI (tu IP + gateway hien tai)
        // ============================================================
        p.Report("Buoc 1b: Xac dinh don vi theo dia chi IP & gateway...");

        string gateway = opt.Gateway.Trim();
        if (string.IsNullOrEmpty(gateway))
            gateway = FindGateway(nic);

        IpPlan.Unit? unit = null;

        // Don vi da chon thu cong (tu o tim kiem) - uu tien cao nhat
        if (opt.Unit != null)
        {
            unit = opt.Unit;

            string chon = opt.Unit.LanGateway == gateway
                ? $"Gateway khop dung voi don vi da chon (LAN {opt.Unit.LanCidr})."
                : $"Gateway hien tai KHONG khop don vi da chon (can {opt.Unit.LanGateway}).";

            bool ipTrongDai = !string.IsNullOrEmpty(ip) && IpPlan.IsIpInUnit(ip, opt.Unit);

            results.Add(new CheckResult
            {
                Step = "1b. Nhan dien don vi",
                Level = ipTrongDai && opt.Unit.LanGateway == gateway ? CheckLevel.Ok : CheckLevel.Warn,
                Message = $"DON VI DA CHON: {opt.Unit.Name}.",
                Detail = $"Dai LAN: {opt.Unit.LanCidr} (mask {opt.Unit.SubnetMask}) | " +
                         $"Gateway LAN: {opt.Unit.LanGateway} | " +
                         $"IP WAN modem: {opt.Unit.WanIp} | GW WAN: {opt.Unit.WanGateway} | " +
                         $"DNS: {IpPlan.MilitaryDns} | {chon} | " +
                         (ipTrongDai ? "IP may thuoc dai LAN cua don vi." : "IP may KHONG nam trong dai LAN cua don vi.")
            });
        }
        else if (!string.IsNullOrEmpty(ip))
            unit = IpPlan.FindByLanIp(ip);

        // Neu khong xac dinh duoc tu IP, thu them tu gateway
        var gwCandidates = IpPlan.FindByGatewayCandidates(gateway);
        if (unit == null && gwCandidates.Count == 1)
            unit = gwCandidates[0];

        // Gateway WAN dung chung cho nhieu don vi - KHONG dung de khop don vi
        var sharedWan = IpPlan.FindBySharedWanGateway(gateway);

        if (unit != null && opt.Unit != null)
        {
            // Da xu ly o khoi tren (don vi do nguoi dung chon)
            string sharedNote = sharedWan.Count > 1
                ? $" | Luu y: gateway WAN {gateway} duoc {sharedWan.Count} don vi cung dung."
                : "";

            results.Add(new CheckResult
            {
                Step = "1b. Nhan dien don vi",
                Level = CheckLevel.Ok,
                Message = $"May nay thuoc DON VI: {unit.Name}.",
                Detail = $"Dai LAN: {unit.LanCidr} (mask {unit.SubnetMask}) | " +
                         $"Gateway LAN: {unit.LanGateway} | " +
                         $"IP WAN modem: {unit.WanIp} | GW WAN: {unit.WanGateway} | " +
                         $"DNS: {IpPlan.MilitaryDns} | {sharedNote}"
            });
        }
        else if (gwCandidates.Count > 1)
        {
            // Gateway LAN bi dung chung giua nhieu don vi - khong phan biet duoc
            results.Add(new CheckResult
            {
                Step = "1b. Nhan dien don vi",
                Level = CheckLevel.Warn,
                Message = $"Gateway {gateway} la gateway LAN DUNG CHUNG cho {gwCandidates.Count} don vi.",
                Detail = "Khong the xac dinh duy nhat don vi chi tu gateway. " +
                         $"Cac don vi: {string.Join(", ", gwCandidates.Select(u => u.Name))}. " +
                         "Can kiem tra theo dai LAN cua IP may, hoac chon thu cong o tab " +
                         "'CAU HINH IP MOT CHAM'."
            });
        }
        else if (sharedWan.Count > 1)
        {
            results.Add(new CheckResult
            {
                Step = "1b. Nhan dien don vi",
                Level = CheckLevel.Warn,
                Message = $"Gateway {gateway} la gateway WAN DUNG CHUNG cho {sharedWan.Count} don vi.",
                Detail = "Không thể xác định duy nhất đơn vị chỉ từ gateway. " +
                         $"Các đơn vị dùng chung: {string.Join(", ", sharedWan.Take(6).Select(u => u.Name))}" +
                         (sharedWan.Count > 6 ? "..." : "") + ". " +
                         "Cần kiểm tra theo dải LAN của IP máy."
            });
        }
        else
        {
            results.Add(new CheckResult
            {
                Step = "1b. Nhan dien don vi",
                Level = CheckLevel.Warn,
                Message = "KHONG xac dinh duoc don vi tu cau hinh IP hien tai.",
                Detail = $"IP: {(string.IsNullOrEmpty(ip) ? "(chua co)" : ip)} | " +
                         $"GW: {(string.IsNullOrEmpty(gateway) ? "(khong co)" : gateway)}. " +
                         "Dia chi co the khong thuoc danh sach quy hoach, " +
                         "hoac may chua duoc gan IP dung."
            });
        }

        // ============================================================
        // BUOC 2 - DRIVER & TRANG THAI CARD MANG
        // ============================================================
        p.Report("Buoc 2: Kiem tra driver & trang thai card mang...");

        var driverInfo = QueryWmiAdapter(desc);
        if (driverInfo == null)
        {
            results.Add(new CheckResult
            {
                Step = "2. Driver / Card mang",
                Level = CheckLevel.Warn,
                Message = "Khong doc duoc thong tin driver qua WMI.",
                Detail = "Co the WMI bi chan. Van dung buoc 3 de kiem tra ket noi thuc te."
            });
        }
        else
        {
            int errorCode = driverInfo.ConfigManagerErrorCode;

            if (errorCode != 0)
            {
                results.Add(new CheckResult
                {
                    Step = "2. Driver / Card mang",
                    Level = CheckLevel.Fail,
                    Message = $"Driver '{desc}' CO LOI - ConfigManager ErrorCode = {errorCode}.",
                    Detail = $"{DescribeErrorCode(errorCode)}. " +
                             "Kiem tra Device Manager hoac cai lai driver card mang."
                });
            }
            else
            {
                string dhcp = string.Equals(driverInfo.DHCPEnabled, "True", StringComparison.OrdinalIgnoreCase)
                    ? "DHCP" : "Static";
                string macWmi = string.IsNullOrWhiteSpace(driverInfo.MACAddress) ? mac : driverInfo.MACAddress;

                results.Add(new CheckResult
                {
                    Step = "2. Driver / Card mang",
                    Level = CheckLevel.Ok,
                    Message = $"Driver card mang '{desc}' hoat dong binh thuong.",
                    Detail = $"Driver {driverInfo.DriverVersion} | Che do: {dhcp} | MAC: {macWmi} | " +
                             $"IP: {(ip.Length > 0 ? ip : "(chua co)")} | " +
                             $"Mask: {subnetMask} | " +
                             $"GW: {(driverInfo.DefaultIPGateway ?? "(khong co)")}"
                });
            }
        }

        // ============================================================
        // BUOC 3 - KET NOI CUC BO & GATEWAY / MODEM
        // ============================================================
        p.Report("Buoc 3: Kiem tra gateway & ket noi cuc bo...");

        if (string.IsNullOrEmpty(gateway))
        {
            results.Add(new CheckResult
            {
                Step = "3. Gateway / Ket noi cuc bo",
                Level = CheckLevel.Fail,
                Message = "Khong tim thay DEFAULT GATEWAY.",
                Detail = "May chua duoc dinh huong duong truyen. Hay dung tab 'CAU HINH IP MOT CHAM'."
            });
        }
        else
        {
            var gwPing = Ping(gateway, opt.PingCount, opt.TimeoutSeconds);
            if (gwPing.Reachable)
            {
                results.Add(new CheckResult
                {
                    Step = "3. Gateway / Ket noi cuc bo",
                    Level = CheckLevel.Ok,
                    Message = $"Default gateway {gateway} PING THANH CONG.",
                    Detail = $"Do tre trung binh: {gwPing.AvgMs} ms | Mat goi: {gwPing.LossPercent}% | " +
                             $"Gui {opt.PingCount} nhan duoc {gwPing.Succeeded}"
                });
            }
            else
            {
                results.Add(new CheckResult
                {
                    Step = "3. Gateway / Ket noi cuc bo",
                    Level = CheckLevel.Fail,
                    Message = $"Default gateway {gateway} KHONG PING DUOC.",
                    Detail = $"Mat goi: {gwPing.LossPercent}%. Kiem tra cap LAN, cong switch, " +
                             "dia chi IP cua may va gateway."
                });
            }
        }

        // 3b. Ping IP WAN cua don vi (dia chi modem tai don vi)
        if (unit != null)
        {
            p.Report("Buoc 3b: Kiem tra IP WAN cua don vi...");

            var wanPing = Ping(unit.WanIp, 2, 4);
            if (wanPing.Reachable)
            {
                results.Add(new CheckResult
                {
                    Step = "3b. IP WAN don vi",
                    Level = CheckLevel.Ok,
                    Message = $"IP WAN cua don vi {unit.WanIp} PING THANH CONG.",
                    Detail = $"Do tre: {wanPing.AvgMs} ms | Mat goi: {wanPing.LossPercent}% | " +
                             $"Day la dia chi modem tai '{unit.Name}'."
                });
            }
            else
            {
                results.Add(new CheckResult
                {
                    Step = "3b. IP WAN don vi",
                    Level = CheckLevel.Warn,
                    Message = $"IP WAN cua don vi {unit.WanIp} KHONG PING DUOC.",
                    Detail = $"Mat goi: {wanPing.LossPercent}%. " +
                             "Co the modem WAN chua len, hoac duong truyen WAN bi chan " +
                             "(kiem tra voi hop trong buoc 4)."
                });
            }

            // 3c. Ping gateway WAN
            p.Report("Buoc 3c: Kiem tra gateway WAN...");
            var wanGwPing = Ping(unit.WanGateway, 2, 4);
            if (wanGwPing.Reachable)
            {
                results.Add(new CheckResult
                {
                    Step = "3c. Gateway WAN",
                    Level = CheckLevel.Ok,
                    Message = $"Gateway WAN {unit.WanGateway} PING THANH CONG.",
                    Detail = $"Do tre: {wanGwPing.AvgMs} ms | Mat goi: {wanGwPing.LossPercent}%"
                });
            }
            else
            {
                results.Add(new CheckResult
                {
                    Step = "3c. Gateway WAN",
                    Level = CheckLevel.Warn,
                    Message = $"Gateway WAN {unit.WanGateway} KHONG PING DUOC.",
                    Detail = $"Mat goi: {wanGwPing.LossPercent}%. " +
                             "Kiem tra duong truyen WAN cua don vi."
                });
            }
        }

        // 3d. Quet nhanh cac modem WAN truc thuoc (gioi han thoi gian)
        if (opt.TestModemWan)
        {
            p.Report("Buoc 3d: Quet nhanh cac modem WAN truc thuoc...");

            var reachable = new List<string>();
            int checkedCount = 0;

            foreach (var u in IpPlan.All)
            {
                if (checkedCount >= 12) break;
                checkedCount++;

                var pr = Ping(u.WanIp, 1, 2);
                if (pr.Reachable)
                    reachable.Add($"{u.Name} ({u.WanIp})");
            }

            if (reachable.Count > 0)
            {
                results.Add(new CheckResult
                {
                    Step = "3d. Modem WAN truc thuoc",
                    Level = CheckLevel.Ok,
                    Message = $"Phat hien {reachable.Count}/{checkedCount} modem WAN phan hoi.",
                    Detail = string.Join(", ", reachable)
                });
            }
            else
            {
                results.Add(new CheckResult
                {
                    Step = "3d. Modem WAN truc thuoc",
                    Level = CheckLevel.Warn,
                    Message = $"Khong modem WAN nao phan hoi ({checkedCount} dia chi da thu).",
                    Detail = "Co the khong thuoc don vi nao trong danh sach, hoac duong truyen WAN bi chan."
                });
            }
        }

        // ============================================================
        // BUOC 4 - DINH TUYEN, DNS & TRACERT
        // ============================================================
        p.Report("Buoc 4: Kiem tra dinh tuyen, DNS & tracert...");

        // 4a. Tracert toi DNS quan su
        if (opt.RunTracert)
        {
            var trace = Tracert(IpPlan.MilitaryDns, opt.TimeoutSeconds);
            if (trace.Hops.Count == 0)
            {
                results.Add(new CheckResult
                {
                    Step = "4. Dinh tuyen / DNS / Tracert",
                    Level = CheckLevel.Warn,
                    Message = $"Khong tra duoc duong dan toi DNS quan su {IpPlan.MilitaryDns}.",
                    Detail = "Tracert khong tra ve hop nao - dang chan hoac khong co duong tro."
                });
            }
            else
            {
                int lastHop = trace.Hops.Keys.Max();
                int maxRt = trace.Hops.Values.Where(v => v.RtMs > 0).Select(v => v.RtMs).DefaultIfEmpty(0).Max();
                string lastIp = trace.Hops.TryGetValue(lastHop, out var lastHopInfo) ? lastHopInfo.Ip : "(khong xac dinh)";

                // Hop ngay truoc hop cuoi = bien do phai WAN cua don vi
                string wanHop = "(khong xac dinh)";
                if (unit != null && trace.Hops.Values.Any(v => v.Ip == unit.WanIp))
                    wanHop = unit.WanIp;
                else if (trace.Hops.TryGetValue(lastHop - 1, out var prev))
                    wanHop = prev.Ip;

                results.Add(new CheckResult
                {
                    Step = "4. Dinh tuyen / DNS / Tracert",
                    Level = lastHop <= 12 ? CheckLevel.Ok : CheckLevel.Warn,
                    Message = $"Duong dan toi DNS quan su {IpPlan.MilitaryDns}: {lastHop} hop.",
                    Detail = $"RTT cao nhat tren duong: {maxRt} ms | Hop cuoi: {lastIp} | " +
                             $"Bien do gan day nhat: {wanHop} | " +
                             $"So hop co phan hoi: {trace.Hops.Count}/{lastHop}"
                });
            }
        }

        // 4b. Kiem tra DNS phan giai ten mien
        string[] testDomains = { "www.lamdong.gov.vn", "google.com", "intranet" };
        var dnsOk = new List<string>();
        foreach (string domain in testDomains)
        {
            p.Report($"Buoc 4: Phan giai ten mien '{domain}'...");
            try
            {
                var entry = Dns.GetHostEntry(domain);
                dnsOk.Add($"{domain} -> {entry.AddressList[0]}");
            }
            catch
            {
                // bo qua - ghi nhan o duoi
            }
        }

        if (dnsOk.Count > 0)
        {
            results.Add(new CheckResult
            {
                Step = "4. Dinh tuyen / DNS / Tracert",
                Level = CheckLevel.Ok,
                Message = $"Phan giai ten mien thanh cong {dnsOk.Count}/{testDomains.Length}.",
                Detail = string.Join(" | ", dnsOk)
            });
        }
        else
        {
            results.Add(new CheckResult
            {
                Step = "4. Dinh tuyen / DNS / Tracert",
                Level = CheckLevel.Fail,
                Message = "KHONG PHAN GIAI DUOC TEN MIEN NAO.",
                Detail = $"Da thu: {string.Join(", ", testDomains)}. " +
                         $"Kiem tra cau hinh DNS (phai la {IpPlan.MilitaryDns})."
            });
        }

        return (results, BuildReport(results, opt, unit, ip, subnetMask, gateway));
    }

    // ==================================================================
    // TIEN ICH
    // ==================================================================

    private sealed class WmiAdapter
    {
        public string Description { get; init; } = "";
        public string DriverVersion { get; init; } = "";
        public string MACAddress { get; init; } = "";
        public string DHCPEnabled { get; init; } = "";
        public string DefaultIPGateway { get; init; } = "";
        public string NetConnectionStatus { get; init; } = "";
        public int ConfigManagerErrorCode { get; init; }
    }

    /// <summary>Doc thong tin driver card mang qua WMI (Win32_NetworkAdapter).</summary>
    private static WmiAdapter? QueryWmiAdapter(string description)
    {
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT * FROM Win32_NetworkAdapter WHERE NetEnabled = TRUE OR Name LIKE '%" +
                description.Replace("'", "''") + "%'");

            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    string desc = GetStr(obj, "Name");
                    if (!desc.Equals(description, StringComparison.OrdinalIgnoreCase)) continue;

                    return new WmiAdapter
                    {
                        Description = desc,
                        DriverVersion = GetStr(obj, "DriverVersion"),
                        MACAddress = GetStr(obj, "MACAddress"),
                        DHCPEnabled = GetStr(obj, "DHCPEnabled"),
                        DefaultIPGateway = GetStr(obj, "DefaultIPGateway"),
                        NetConnectionStatus = GetStr(obj, "NetConnectionStatus"),
                        ConfigManagerErrorCode = GetInt(obj, "ConfigManagerErrorCode")
                    };
                }
            }
        }
        catch
        {
            // WMI khong truy cap duoc - bo qua
        }
        return null;
    }

    private static string GetStr(ManagementObject obj, string prop)
    {
        try { return obj[prop]?.ToString() ?? ""; }
        catch { return ""; }
    }

    private static int GetInt(ManagementObject obj, string prop)
    {
        try
        {
            object? v = obj[prop];
            return v == null ? 0 : Convert.ToInt32(v, CultureInfo.InvariantCulture);
        }
        catch { return 0; }
    }

    /// <summary>Mo ta ma loi cua Device Manager.</summary>
    private static string DescribeErrorCode(int code) => code switch
    {
        1 => "Loi phan cung khong xac dinh",
        2 => "Card mang khong tim thay",
        3 => "Card mang bi loai khoi he thong",
        10 => "Thiet bi khong the mo",
        22 => "Thiet bi bi vo hieu hoa",
        31 => "Lai cau hinh driver cho card mang",
        45 => "Thiet bi khong duoc ket noi dung cach",
        48 => "Phep truy cap bi tu choi",
        _ => "Ma loi thiet bi khong xac dinh"
    };

    private static string FormatMac(PhysicalAddress addr)
    {
        byte[] b = addr.GetAddressBytes();
        if (b.Length == 0) return "(khong co)";
        return string.Join(":", b.Select(x => x.ToString("X2")));
    }

    /// <summary>Tu phat hien default gateway cua card.</summary>
    private static string FindGateway(NetworkInterface nic)
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

        // Fallback: doc tu WMI
        try
        {
            using var searcher = new ManagementObjectSearcher(
                "SELECT DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled = TRUE");
            foreach (ManagementObject obj in searcher.Get())
            {
                using (obj)
                {
                    var arr = obj["DefaultIPGateway"] as string[];
                    if (arr != null && arr.Length > 0 && !string.IsNullOrWhiteSpace(arr[0]))
                        return arr[0];
                }
            }
        }
        catch { }
        return "";
    }

    /// <summary>Ket qua mot lenh ping.</summary>
    public sealed class PingResult
    {
        public bool Reachable { get; init; }
        public int Succeeded { get; init; }
        public int Total { get; init; }
        public int AvgMs { get; init; }
        public int LossPercent { get; init; }
    }

    /// <summary>Ping mot dia chi IPv4, phan tich output cua lenh ping.exe.</summary>
    public static PingResult Ping(string address, int count, int timeoutSeconds)
    {
        int ok = 0;
        var times = new List<int>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ping.exe",
                Arguments = $"-n {count} -w {timeoutSeconds * 1000} {address}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(timeoutSeconds * 1000 + 4000))
            {
                try { p.Kill(); } catch { }
                return new PingResult { Reachable = false, Total = count };
            }

            // Dong dang "time=12ms" hoac "time<1ms"
            foreach (var line in output.Split('\n'))
            {
                int idx = line.IndexOf("time=", StringComparison.OrdinalIgnoreCase);
                if (idx < 0) continue;

                string rest = line[(idx + 5)..].Trim();
                int end = 0;
                while (end < rest.Length && (char.IsDigit(rest[end]) || rest[end] == '<')) end++;
                string num = rest[..end].TrimStart('<');
                if (int.TryParse(num, out int ms))
                {
                    ok++;
                    times.Add(ms);
                }
            }
        }
        catch
        {
            return new PingResult { Reachable = false, Total = count };
        }

        int total = Math.Max(count, ok);
        int loss = total > 0 ? (total - ok) * 100 / total : 100;
        int avg = times.Count > 0 ? (int)times.Average() : 0;

        return new PingResult
        {
            Reachable = ok > 0,
            Succeeded = ok,
            Total = count,
            AvgMs = avg,
            LossPercent = loss
        };
    }

    /// <summary>Thong tin mot hop trong duong dan tracert.</summary>
    public sealed record HopInfo(string Ip, int RtMs);

    /// <summary>Ket qua tracert.</summary>
    public sealed class TraceResult
    {
        public Dictionary<int, HopInfo> Hops { get; init; } = new();
        public bool Completed { get; init; }
    }

    /// <summary>Chay tracert toi mot dia chi, tra ve cac hop.</summary>
    public static TraceResult Tracert(string address, int timeoutSeconds)
    {
        var hops = new Dictionary<int, HopInfo>();

        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "tracert.exe",
                Arguments = $"-d -h 20 -w 1000 {address}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var p = Process.Start(psi)!;
            string output = p.StandardOutput.ReadToEnd();
            p.StandardError.ReadToEnd();
            if (!p.WaitForExit(timeoutSeconds * 1000 + 8000))
            {
                try { p.Kill(); } catch { }
                return new TraceResult { Hops = hops, Completed = false };
            }

            foreach (var raw in output.Split('\n'))
            {
                string line = raw.Trim();
                if (line.Length == 0) continue;

                // So hop: "13" hoac " 13"
                int sp = line.IndexOf(' ');
                if (sp <= 0) continue;

                string numPart = line[..sp].Trim();
                if (!int.TryParse(numPart, out int hopNum)) continue;

                string rest = line[(sp + 1)..].Trim();

                // Dia chi IP: dung regex de khong phu thuoc vi tri (co the o dau hoac cuoi dong)
                var ipMatch = System.Text.RegularExpressions.Regex.Match(rest,
                    @"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b");
                if (!ipMatch.Success) continue;   // hop khong phan hoi -> bo qua

                string ip = ipMatch.Value;

                // RTT: lay gia tri "N ms" dau tien trong dong
                int rt = 0;
                var msMatch = System.Text.RegularExpressions.Regex.Match(rest, @"(\d+)\s*ms");
                if (msMatch.Success && int.TryParse(msMatch.Groups[1].Value, out int v)) rt = v;

                hops[hopNum] = new HopInfo(ip, rt);
            }
        }
        catch
        {
            // ignore
        }

        return new TraceResult { Hops = hops, Completed = hops.Count > 0 };
    }

    /// <summary>Tao bao cao dang text de luu file.</summary>
    private static string BuildReport(
        List<CheckResult> results,
        Options opt,
        IpPlan.Unit? unit = null,
        string currentIp = "",
        string subnetMask = "",
        string currentGateway = "")
    {
        var sb = new StringBuilder();
        sb.AppendLine("================================================================");
        sb.AppendLine("   BAO CAO KIEM TRA KET NOI - DANNY (Tro ly CNTT)");
        sb.AppendLine("   Bo Chi Huy Quan su tinh Lam Dong");
        sb.AppendLine("================================================================");
        sb.AppendLine();
        sb.AppendLine("Thoi gian   : " + DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"));
        sb.AppendLine("May         : " + Environment.MachineName);
        sb.AppendLine("Nguoi dung  : " + Environment.UserName);
        sb.AppendLine("He dieu hanh: " + Environment.OSVersion.ToString());
        sb.AppendLine("Card mang   : " + (opt.AdapterName.Length > 0 ? opt.AdapterName : "(tu dong chon)"));
        sb.AppendLine("IP hien tai : " + (currentIp.Length > 0 ? currentIp : "(tu dong phat hien)"));
        sb.AppendLine("Subnet mask : " + (subnetMask.Length > 0 ? subnetMask : "(khong ro)"));
        sb.AppendLine("Gateway     : " + (currentGateway.Length > 0 ? currentGateway : "(tu dong phat hien)"));
        sb.AppendLine("DNS quan su : " + IpPlan.MilitaryDns);
        sb.AppendLine();
        sb.AppendLine("----------------------------------------------------------------");
        sb.AppendLine("DON VI CANH QUY HOACH");
        sb.AppendLine("----------------------------------------------------------------");
        if (unit != null)
        {
            sb.AppendLine("   Don vi     : " + unit.Name);
            sb.AppendLine("   Dai LAN    : " + unit.LanCidr + "  (mask " + unit.SubnetMask + ")");
            sb.AppendLine("   Gateway LAN: " + unit.LanGateway);
            sb.AppendLine("   IP WAN     : " + unit.WanIp);
            sb.AppendLine("   GW WAN     : " + unit.WanGateway);
        }
        else
        {
            sb.AppendLine("   (khong xac dinh duoc don vi tu cau hinh hien tai)");
        }
        sb.AppendLine();
        sb.AppendLine("----------------------------------------------------------------");
        sb.AppendLine("KET QUA CHAN DOAN");
        sb.AppendLine("----------------------------------------------------------------");

        foreach (var r in results)
        {
            sb.AppendLine();
            sb.AppendLine($"[{r.Level.ToString().ToUpper()}] {r.Step}");
            sb.AppendLine("   " + r.Message);
            if (!string.IsNullOrWhiteSpace(r.Detail))
                sb.AppendLine("   " + r.Detail);
        }

        sb.AppendLine();
        sb.AppendLine("----------------------------------------------------------------");
        sb.AppendLine("TONG KET");
        sb.AppendLine("----------------------------------------------------------------");

        int ok = results.Count(r => r.Level == CheckLevel.Ok);
        int warn = results.Count(r => r.Level == CheckLevel.Warn);
        int fail = results.Count(r => r.Level == CheckLevel.Fail);

        sb.AppendLine($"   Thanh cong : {ok}");
        sb.AppendLine($"   Canh bao   : {warn}");
        sb.AppendLine($"   Loi        : {fail}");

        string verdict = fail > 0
            ? "KET LUAN: CO LOI - can can thi cua don vi quan tri mang."
            : warn > 0
                ? "KET LUAN: KET NOI DUOC NHUNG CO CANH BAO - xem chi tiet ben tren."
                : "KET LUAN: KET NOI BINH THUONG - tat ca cac buoc deu dat yeu cau.";

        sb.AppendLine();
        sb.AppendLine("   " + verdict);
        sb.AppendLine("================================================================");

        return sb.ToString();
    }
}
