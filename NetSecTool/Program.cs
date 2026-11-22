using System;
using System.Threading;
using System.Windows.Forms;

namespace NetSecTool;

static class Program
{
    /// <summary>
    ///  Diem vao chinh cua ung dung.
    ///
    ///  Che do GUI (mac dinh).
    ///
    ///  Che do CLI (headless) - dung cho automation / tinh hieu:
    ///      Danny.exe --make-safe "J:\" [--version 2.6] [--vendor BTL86] [--seed XZ3O4HN5GDKRS3G95]
    ///      Danny.exe --check "J:\"
    ///      Danny.exe --diag [--adapter Ethernet] [--ip 192.168.1.100] [--gateway 192.168.1.1] [--full]
    ///      Danny.exe --clean
    ///      Danny.exe --remote-listen [--port 21118] [--whitelist "86.134.32.150/24"]
    ///      Danny.exe --remote-connect --ip 192.168.1.55 [--port 21118] [--whitelist "..."]
    ///      Danny.exe --kvrt-update
    ///      Danny.exe --uncover "D:\" [--no-recursive] [--dry-run]
    ///      Danny.exe --backup --target E: [--no-system-image] [--no-user-data] [--dry-run]
    ///      Danny.exe --forensic [--out "C:\Bao-cao"]
    ///
    ///  Ket qua duoc ghi ra STDOUT. Che do CLI KHONG hien bat ky hop thoai
    ///  nao (khong MessageBox) - phu hop voi viec chay tu dong.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length > 0 && args[0].StartsWith("--"))
        {
            // Bat UTF-8 cho console de chu tieng Viet hien thi dung
            try { Console.OutputEncoding = System.Text.Encoding.UTF8; } catch { }
            RunCli(args);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new Form1());
    }

    /// <summary>
    ///  Ghi ra console theo dang ASCII thuan.
    ///
    ///  <para>Windows Console mac dinh dung codepage 437/850, khong hien thi
    ///  duoc chu tieng Viet co dau -> hien se ra "mojibake". Ham nay bo dau
    ///  tieng Viet truoc khi ghi ra, giu cho phan CLI doc duoc tren moi
    ///  dau cua so lenh.</para>
    /// </summary>
    private static void Say(string message = "")
    {
        Console.WriteLine(ToAscii(message));
    }

    /// <summary>
    ///  Chuyen chuoi tieng Viet co dau sang ASCII tuong duong.
    ///
    ///  <para>Dung Unicode normalization dang FormD de tach dau ra thanh
    ///  ky tu combining, roi loai bo ky tu khong thuoc ASCII.</para>
    /// </summary>
    private static string ToAscii(string s)
    {
        if (string.IsNullOrEmpty(s)) return s;

        // Cac ky tu dac biet can giu lai vi chung khong phai dau tieng Viet
        var keep = new Dictionary<char, char>
        {
            { '\u0111', 'd' },  // đ
            { '\u0110', 'D' },  // Đ
        };

        try
        {
            string decomposed = s.Normalize(System.Text.NormalizationForm.FormD);
            var sb = new System.Text.StringBuilder(decomposed.Length);
            foreach (char c in decomposed)
            {
                if (c < 128) { sb.Append(c); continue; }
                if (keep.TryGetValue(c, out char rep)) { sb.Append(rep); continue; }
                // Ky tu combining (dau) -> bo qua
                if (char.GetUnicodeCategory(c) == System.Globalization.UnicodeCategory.NonSpacingMark) continue;
                sb.Append(c);
            }
            return sb.ToString().Normalize(System.Text.NormalizationForm.FormC);
        }
        catch
        {
            return s;
        }
    }

    private static void RunCli(string[] args)
    {
        string cmd = args[0].ToLowerInvariant();
        string root = "";
        string version = UsbSafeMaker.DefaultVersion;
        string vendor = UsbSafeMaker.DefaultVendor;
        string seed = UsbSafeMaker.DefaultSeed;
        string adapter = "";
        string ip = "";
        string gateway = "";
        string whitelist = RemoteSupport.DefaultWhitelist;
        bool doFormat = false;
        bool full = false;
        int port = 0;
        bool noService = false;
        bool noBrowser = false, noSrum = false, noDns = false, noPrefetch = false,
             noAmcache = false, noRunMru = false, noJumpList = false, noEventLog = false,
             noMiAV = false, noKvrt = false, reboot = false, noInstallMiAV = false;
        // Ver5.7
        string backupTarget = "";
        string forensicOut = "";
        bool noSystemImage = false, noUserData = false, dryRun = false;
        bool noRecursive = false, dryRunUncover = false;
        string acronisEngine = "";

        for (int i = 1; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--version": if (i + 1 < args.Length) version = args[++i]; break;
                case "--vendor": if (i + 1 < args.Length) vendor = args[++i]; break;
                case "--seed": if (i + 1 < args.Length) seed = args[++i]; break;
                case "--adapter": if (i + 1 < args.Length) adapter = args[++i]; break;
                case "--ip": if (i + 1 < args.Length) ip = args[++i]; break;
                case "--gateway": if (i + 1 < args.Length) gateway = args[++i]; break;
                case "--whitelist": if (i + 1 < args.Length) whitelist = args[++i]; break;
                case "--format": doFormat = true; break;
                case "--full": full = true; break;
                case "--no-browser": noBrowser = true; break;
                case "--no-srum": noSrum = true; break;
                case "--no-dns": noDns = true; break;
                case "--no-prefetch": noPrefetch = true; break;
                case "--no-amcache": noAmcache = true; break;
                case "--no-runmru": noRunMru = true; break;
                case "--no-jumplist": noJumpList = true; break;
                case "--no-eventlog": noEventLog = true; break;
                case "--no-miav": noMiAV = true; break;
                case "--no-kvrt": noKvrt = true; break;
                case "--no-install-miav": noInstallMiAV = true; break;
                case "--reboot": reboot = true; break;
                case "--port": if (i + 1 < args.Length && int.TryParse(args[++i], out int pv)) port = pv; break;
                case "--no-service": noService = true; break;
                // --- Ver5.7 ---
                case "--target": if (i + 1 < args.Length) backupTarget = args[++i]; break;
                case "--out": if (i + 1 < args.Length) forensicOut = args[++i]; break;
                case "--acronis": if (i + 1 < args.Length) acronisEngine = args[++i]; break;
                case "--no-system-image": noSystemImage = true; break;
                case "--no-user-data": noUserData = true; break;
                case "--dry-run": dryRun = true; break;
                case "--no-recursive": noRecursive = true; break;
                default:
                    if (args[i].StartsWith("--")) break;
                    root = args[i];
                    break;
            }
        }

        switch (cmd)
        {
            case "--make-safe":
                {
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        Console.WriteLine("LOI: thieu duong dan o dia. Vi du: --make-safe \"J:\\\"");
                        return;
                    }
                    if (!root.EndsWith("\\")) root += "\\";

                    string fs = UsbFormatter.GetFileSystem(root);
                    bool needFormat = doFormat || !fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase);
                    Console.WriteLine(UsbSafeService.MakeSafeUsb(root, version, vendor, seed, needFormat));
                    break;
                }

            case "--check":
                {
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        Console.WriteLine("LOI: thieu duong dan o dia. Vi du: --check \"J:\\\"");
                        return;
                    }
                    if (!root.EndsWith("\\")) root += "\\";
                    Console.WriteLine(UsbSafeService.InspectUsbSafe(root));
                    break;
                }

            case "--diag":
                {
                    var opt = new NetDiagnostics.Options
                    {
                        AdapterName = adapter,
                        IpAddress = ip,
                        Gateway = gateway,
                        PingCount = 4,
                        TimeoutSeconds = 8,
                        RunTracert = full,
                        TestModemWan = full
                    };

                    var progress = new NetDiagnostics.Progress(msg => Console.WriteLine("  ... " + msg));
                    var (results, report) = NetDiagnostics.Run(opt, progress);

                    foreach (var r in results)
                    {
                        Console.WriteLine(r.Icon + " " + r.Step);
                        Console.WriteLine("     " + r.Message);
                        if (!string.IsNullOrWhiteSpace(r.Detail))
                            Console.WriteLine("     " + r.Detail);
                        Console.WriteLine();
                    }

                    Console.WriteLine(report);
                    break;
                }

            case "--clean":
                {
                    // Lam sach PC mot cham (headless) - dung cho automation.
                    var opt = new CleanOptions
                    {
                        CleanBrowserHistory = !noBrowser,
                        CleanSrum = !noSrum,
                        CleanDnsCache = !noDns,
                        CleanPrefetch = !noPrefetch,
                        CleanAmcache = !noAmcache,
                        CleanRunMru = !noRunMru,
                        CleanJumpList = !noJumpList,
                        CleanEventLog = !noEventLog,
                        CleanMiAV = !noMiAV,
                        RunKvrt = !noKvrt,
                        InstallMiAV = !noInstallMiAV,
                        RebootAfterKvrt = reboot
                    };

                    Console.WriteLine("=== DANNY ver4.0 - LAM SACH PC MOT CHAM ===");
                    var res = PcCleaner.Run(opt, (m, k) =>
                    {
                        string pfx = k switch
                        {
                            CleanLogKind.Success => "[ OK ] ",
                            CleanLogKind.Warn => "[CANH BAO] ",
                            CleanLogKind.Error => "[LOI]  ",
                            CleanLogKind.Heading => "== ",
                            CleanLogKind.Step => "[...]  ",
                            _ => "       "
                        };
                        Console.WriteLine(pfx + m);
                    }, (c, t) =>
                    {
                        Console.Write($"\r  [{c}/{t}]");
                        Console.Out.Flush();
                    });

                    Console.WriteLine();
                    Console.WriteLine($"Xong: {res.Succeeded} thanh cong / {res.Failed} loi / {res.Skipped} bo qua");
                    Console.WriteLine($"Bao cao: {opt.BackupRoot}");
                    break;
                }

            case "--remote-listen":
                {
                    // May nhan ket noi: mo cong, cau hinh Direct IP, tao shortcut, chay RustDesk.
                    int p = port > 0 ? port : RemoteSupport.DefaultDirectPort;
                    Say("=== DANNY ver5.6 - HO TRO KY THUAT TU XA (MAY NHAN KET NOI) ===");

                    string? client = RemoteSupport.LocateClient();
                    if (client == null)
                    {
                        Say("LOI: khong tim thay rustdesk.exe trong tools\\RustDesk.");
                        break;
                    }
                    Say($"Cong Direct IP : {p}");
                    Say($"Whitelist     : {whitelist}");
                    Say($"IP LAN may nay: {RemoteSupport.GetLocalNetworkInfo().ip}");
                    Say();

                    var fw = RemoteSupport.OpenFirewallPort(p, whitelist);
                    Say((fw.Success ? "[ OK ] " : "[LOI]  ") + fw.Summary);

                    var cfg = RemoteSupport.ApplyDirectIpConfig(p, whitelist,
                        approveMode: "click", verificationMethod: "use-temporary-password");
                    Say((cfg.Success ? "[ OK ] " : "[LOI]  ") + cfg.Summary);
                    foreach (string d in cfg.Details) Say("       " + d);

                    var lnk = RemoteSupport.CreateHostShortcut(client, p);
                    Say((lnk.Success ? "[ OK ] " : "[LOI]  ") + lnk.Summary);

                    if (!noService && RemoteSupport.IsAdministrator())
                    {
                        var svc = RemoteSupport.InstallService(client);
                        Say((svc.Success ? "[ OK ] " : "[LOI]  ") + svc.Summary);
                        var st = RemoteSupport.SetServiceState(true);
                        Say((st.Success ? "[ OK ] " : "[LOI]  ") + st.Summary);
                    }
                    else
                    {
                        var host = RemoteSupport.StartHost(client);
                        Say((host.Success ? "[ OK ] " : "[LOI]  ") + host.Summary);
                    }

                    System.Threading.Thread.Sleep(2000);
                    bool ready = RemoteSupport.WaitForPort(p, 10000);
                    var probe = RemoteSupport.RunProbe(p);
                    Say();
                    if (ready && probe.PortListening)
                    {
                        Say($"DA SAN SANG NHAN KET NOI tren cong {p}.");
                        Say($"Bao nguoi dung IP: {probe.LocalIPv4}:{p}");
                    }
                    else
                    {
                        Say($"Cong {p} chua san sang. Kiem tra Windows Defender Firewall.");
                    }
                    Say("Luu y: trang thai \"Not ready\" trong RustDesk la binh thuong khi offline.");
                    break;
                }

            case "--remote-connect":
                {
                    // May can ho tro: mo cong, cau hinh Direct IP, ket noi truc tiep.
                    int p = port > 0 ? port : RemoteSupport.DefaultDirectPort;
                    if (string.IsNullOrWhiteSpace(ip))
                    {
                        Say("LOI: thieu IP may can ho tro. Vi du: --remote-connect --ip 86.134.32.55");
                        break;
                    }
                    if (!RemoteSupport.IsValidTarget(ip))
                    {
                        Say("LOI: IP khong hop le: " + ip);
                        break;
                    }

                    Say("=== DANNY ver5.6 - HO TRO KY THUAT TU XA (MAY CAN HO TRO) ===");

                    string? client = RemoteSupport.LocateClient();
                    if (client == null)
                    {
                        Say("LOI: khong tim thay rustdesk.exe trong tools\\RustDesk.");
                        break;
                    }
                    Say($"Dich ket noi   : {RemoteSupport.BuildConnectTarget(ip, p)}");
                    Say($"Cong Direct IP : {p}");
                    Say($"Whitelist     : {whitelist}");
                    Say();

                    var fw = RemoteSupport.OpenFirewallPort(p, whitelist);
                    Say((fw.Success ? "[ OK ] " : "[LOI]  ") + fw.Summary);

                    var cfg = RemoteSupport.ApplyDirectIpConfig(p, whitelist,
                        approveMode: "click", verificationMethod: "use-temporary-password");
                    Say((cfg.Success ? "[ OK ] " : "[LOI]  ") + cfg.Summary);

                    if (!noService && RemoteSupport.IsAdministrator())
                    {
                        var svc = RemoteSupport.InstallService(client);
                        Say((svc.Success ? "[ OK ] " : "[LOI]  ") + svc.Summary);
                        var st = RemoteSupport.SetServiceState(true);
                        Say((st.Success ? "[ OK ] " : "[LOI]  ") + st.Summary);
                    }
                    else
                    {
                        var host = RemoteSupport.StartHost(client);
                        Say((host.Success ? "[ OK ] " : "[LOI]  ") + host.Summary);
                    }

                    var conn = RemoteSupport.ConnectDirect(client, ip, p);
                    Say((conn.Success ? "[ OK ] " : "[LOI]  ") + conn.Summary);
                    foreach (string d in conn.Details) Say("       " + d);
                    break;
                }

            case "--kvrt-update":
                {
                    Say("=== DANNY ver5.7 - CAP NHAT KVRT ===");
                    var res = KvrtUpdater.UpdateAsync(m => Say("  " + m), null, CancellationToken.None)
                                          .GetAwaiter().GetResult();
                    foreach (string s in res.Steps) Say("  " + s);
                    Say();
                    Say(res.Message);
                    break;
                }

            case "--uncover":
                {
                    if (string.IsNullOrWhiteSpace(root))
                    {
                        Say("LOI: thieu duong dan. Vi du: --uncover \"D:\\\"");
                        break;
                    }
                    if (!root.EndsWith("\\")) root += "\\";

                    Say("=== DANNY ver5.7 - HIEN FILE/FOLDER AN ===");
                    Say($"Dung dich  : {root}");
                    Say($"De quy    : {(noRecursive ? "KHONG" : "CO")}");
                    Say($"Che do    : {(dryRunUncover ? "DRY-RUN (xem truoc)" : "KHOI PHUC THAT")}");
                    Say();

                    var r = UncoverFiles.Scan(root, !noRecursive, dryRunUncover, null, CancellationToken.None);
                    foreach (UncoverItem it in r.Items)
                    {
                        Say($"  {(it.Restored ? "[ OK ]" : "[ -- ]")} {it.FullPath}" +
                            (it.Note != null ? " — " + it.Note : ""));
                    }
                    Say();
                    Say(r.Restored > 0
                        ? $"Da khoi phuc {r.Restored} muc, loi {r.Failed}, xem truoc {r.Skipped}"
                        : $"Khong co muc an nao de khoi phuc (loi {r.Failed})");
                    break;
                }

            case "--backup":
                {
                    if (string.IsNullOrWhiteSpace(backupTarget))
                    {
                        Say("LOI: thieu o dia dich. Vi du: --backup --target E:");
                        break;
                    }

                    Say("=== DANNY ver5.7 - SAO LUU MAY TINH ===");
                    Say("Quet o dia vat ly...");
                    var scan = BackupService.ScanDisks();
                    foreach (PhysicalDisk d in scan.Disks)
                    {
                        Say($"  {d.DeviceId,-12} {d.Model,-32} {d.SizeText,-10} " +
                            $"[{d.InterfaceType}] o: {string.Join(",", d.DriveLetters)} " +
                            $"{(d.IsExternal ? "DI DONG" : "GAN TRONG")}");
                    }
                    Say();
                    foreach (string e in scan.Errors) Say("  [WMI] " + e);
                    foreach (string e in scan.Rejected) Say("  [TU CHOI] " + e);
                    Say();

                    string? reject = BackupService.ValidateTarget(backupTarget, out PhysicalDisk? target);
                    if (reject != null)
                    {
                        Say("LOI: " + reject);
                        break;
                    }
                    Say($"O dich hop le: {target!.Model} ({target.SizeText})");
                    Say();

                    var opt = new BackupOptions
                    {
                        TargetDrive = backupTarget,
                        BackupSystemImage = !noSystemImage,
                        BackupUserData = !noUserData,
                        AcronisEnginePath = acronisEngine,
                        MachineName = Environment.MachineName,
                        DryRun = dryRun
                    };

                    var res = BackupService.RunAsync(opt,
                        m => Say("  " + m), null, CancellationToken.None)
                        .GetAwaiter().GetResult();

                    foreach (string e in res.Errors) Say("[LOI]  " + e);
                    foreach (string w in res.Warnings) Say("[CANH BAO] " + w);
                    Say();
                    Say(res.Message);
                    break;
                }

            case "--forensic":
                {
                    Say("=== DANNY ver5.7 - KIEM TRA AN TOAN THONG TIN (FORENSIC) ===");
                    Say("Che do: CHI DOC — khong sua/xoa du lieu tren may.");
                    Say();

                    var opt = new Forensic.ForensicOptions
                    {
                        OutputDirectory = forensicOut,
                        SkipLargeFileHashing = false
                    };

                    var bundle = Forensic.ForensicEngine.RunAsync(opt,
                        m => Say("  " + m), null, CancellationToken.None)
                        .GetAwaiter().GetResult();

                    Say();
                    Say($"Diem ngo ngo: {bundle.TotalScore}/100");
                    Say(bundle.Verdict);
                    Say($"Phat hien: {bundle.Findings.Count} " +
                        $"(CRITICAL {bundle.Findings.Count(f => f.Severity == Forensic.Severity.Critical)}, " +
                        $"HIGH {bundle.Findings.Count(f => f.Severity == Forensic.Severity.High)})");
                    Say($"Artifact: {bundle.Artifacts.Count}, su kien timeline: {bundle.Timeline.Count}");
                    Say($"Goi chung cu: {bundle.OutputDirectory}");
                    break;
                }

            default:
                Say("LOI: lenh khong hop le: " + cmd);
                Say("Cac lenh ho tro:");
                Say("  --make-safe \"X:\\\"   Tao USB An Toan 2.6");
                Say("  --check \"X:\\\"       Kiem tra trang thai USB an toan");
                Say("  --diag [--full]      Kiem tra ket noi mang (4 buoc chan doan)");
                Say("  --clean [--no-kvrt]  Lam sach PC mot cham (xoa log, quet KVRT, cai lai MiAV)");
                Say("  --remote-listen [--port 21118] [--whitelist \"IP/CIDR\"]   May nhan ket noi (RustDesk Direct IP)");
                Say("  --remote-connect --ip X.X.X.X [--port 21118] [--whitelist \"IP/CIDR\"]  May can ho tro (ket noi truc tiep)");
                Say("  --kvrt-update              Cap nhat Kaspersky KVRT (tu dong, co xac thuc chu ky so)");
                Say("  --uncover \"X:\\\" [--no-recursive] [--dry-run]   Hien file/thu muc an");
                Say("  --backup --target E: [--no-system-image] [--no-user-data] [--dry-run]  Sao luu may tinh (Acronis + Robocopy)");
                Say("  --forensic [--out \"C:\\Bao-cao\"]          Kiem tra an toan thong tin (phap y so DFIR)");
                break;
        }
    }
}
