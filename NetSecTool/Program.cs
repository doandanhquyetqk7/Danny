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
    ///      Danny.exe --remote-listen [--port 5500]
    ///      Danny.exe --remote-connect --ip 192.168.1.55 [--port 5500]
    ///
    ///  Ket qua duoc ghi ra STDOUT. Che do CLI KHONG hien bat ky hop thoai
    ///  nao (khong MessageBox) - phu hop voi viec chay tu dong.
    /// </summary>
    [STAThread]
    static void Main(string[] args)
    {
        if (args.Length > 0 && args[0].StartsWith("--"))
        {
            RunCli(args);
            return;
        }

        ApplicationConfiguration.Initialize();
        Application.Run(new Form1());
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
        bool doFormat = false;
        bool full = false;
        int port = 0;
        bool noService = false;
        bool noBrowser = false, noSrum = false, noDns = false, noPrefetch = false,
             noAmcache = false, noRunMru = false, noJumpList = false, noEventLog = false,
             noMiAV = false, noKvrt = false, reboot = false, noInstallMiAV = false;

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
                    // May nhan ket noi: mo cong, cau hinh, tao shortcut, chay viewer listen.
                    int p = port > 0 ? port : RemoteSupport.DefaultListenPort;
                    Console.WriteLine("=== DANNY ver5.5 - HO TRO KY THUAT TU XA (MAY NHAN KET NOI) ===");

                    var (viewer, server) = RemoteSupport.LocateExecutables();
                    if (viewer == null || server == null)
                    {
                        Console.WriteLine("LOI: khong tim thay bo cong cu UltraVNC trong tools\\UltraVNC.");
                        break;
                    }
                    string uvncDir = Path.GetDirectoryName(viewer)!;
                    string? dsm = RemoteSupport.LocateDsmPlugin(uvncDir);

                    var probe0 = RemoteSupport.RunProbe(p);
                    Console.WriteLine($"IP LAN may nay: {probe0.LocalIPv4}");
                    Console.WriteLine($"Cong listen   : {p}");
                    Console.WriteLine($"Ma hoa DSM    : {(dsm != null ? Path.GetFileName(dsm) : "KHONG (khong ma hoa!)")}");
                    Console.WriteLine();

                    var fw = RemoteSupport.OpenFirewallPort(p);
                    Console.WriteLine((fw.Success ? "[ OK ] " : "[LOI]  ") + fw.Summary);

                    var ini = RemoteSupport.WriteIni(uvncDir, dsm, p);
                    Console.WriteLine((ini.Success ? "[ OK ] " : "[LOI]  ") + ini.Summary);

                    var lnk = RemoteSupport.CreateListenShortcut(viewer, p, dsm);
                    Console.WriteLine((lnk.Success ? "[ OK ] " : "[LOI]  ") + lnk.Summary);

                    var lst = RemoteSupport.StartListener(viewer, p, dsm);
                    Console.WriteLine((lst.Success ? "[ OK ] " : "[LOI]  ") + lst.Summary);

                    System.Threading.Thread.Sleep(2000);
                    bool ready = RemoteSupport.WaitForPort(p, 10000);
                    var probe = RemoteSupport.RunProbe(p);
                    Console.WriteLine();
                    if (ready && probe.PortListening)
                    {
                        Console.WriteLine($"DA SAN SANG NHAN KET NOI tren cong {p}.");
                        Console.WriteLine($"Bao cho nguoi dung: IP = {probe.LocalIPv4}, cong = {p}");
                    }
                    else
                    {
                        Console.WriteLine($"CANH BAO: cong {p} chua san sang.");
                    }
                    break;
                }

            case "--remote-connect":
                {
                    // May can ho tro: mo ket noi nguoc toi may ky thuat vien.
                    int p = port > 0 ? port : RemoteSupport.DefaultListenPort;
                    if (string.IsNullOrWhiteSpace(ip))
                    {
                        Console.WriteLine("LOI: thieu IP may ky thuat vien. Vi du: --remote-connect --ip 192.168.1.55");
                        break;
                    }
                    if (!RemoteSupport.IsValidIPv4(ip) && !RemoteSupport.IsSafeHost(ip))
                    {
                        Console.WriteLine("LOI: IP khong hop le: " + ip);
                        break;
                    }

                    Console.WriteLine("=== DANNY ver5.5 - HO TRO KY THUAT TU XA (MAY CAN HO TRO) ===");
                    var (viewer, server) = RemoteSupport.LocateExecutables();
                    if (viewer == null || server == null)
                    {
                        Console.WriteLine("LOI: khong tim thay bo cong cu UltraVNC trong tools\\UltraVNC.");
                        break;
                    }
                    string uvncDir = Path.GetDirectoryName(server)!;
                    string? dsm = RemoteSupport.LocateDsmPlugin(uvncDir);

                    var fw = RemoteSupport.OpenFirewallPort(p);
                    Console.WriteLine((fw.Success ? "[ OK ] " : "[LOI]  ") + fw.Summary);

                    var ini = RemoteSupport.WriteIni(uvncDir, dsm, p,
                        $"-autoreconnect -connect {ip}::{p}");
                    Console.WriteLine((ini.Success ? "[ OK ] " : "[LOI]  ") + ini.Summary);

                    if (!noService)
                    {
                        var svc = RemoteSupport.InstallService(server);
                        Console.WriteLine((svc.Success ? "[ OK ] " : "[LOI]  ") + svc.Summary);
                        var st = RemoteSupport.SetServiceState(true);
                        Console.WriteLine((st.Success ? "[ OK ] " : "[LOI]  ") + st.Summary);
                    }

                    var conn = RemoteSupport.ConnectReverse(server, ip, p);
                    Console.WriteLine((conn.Success ? "[ OK ] " : "[LOI]  ") + conn.Summary);
                    foreach (string d in conn.Details) Console.WriteLine("       " + d);
                    break;
                }

            default:
                Console.WriteLine("LOI: lenh khong hop le: " + cmd);
                Console.WriteLine("Cac lenh ho tro:");
                Console.WriteLine("  --make-safe \"X:\\\"   Tao USB An Toan 2.6");
                Console.WriteLine("  --check \"X:\\\"       Kiem tra trang thai USB an toan");
                Console.WriteLine("  --diag [--full]      Kiem tra ket noi mang (4 buoc chan doan)");
                Console.WriteLine("  --clean [--no-kvrt]  Lam sach PC mot cham (xoa log, quet KVRT, cai lai MiAV)");
                Console.WriteLine("  --remote-listen [--port 5500]      May nhan ket noi (UltraVNC listen)");
                Console.WriteLine("  --remote-connect --ip X.X.X.X [--port 5500]  May can ho tro (ket noi nguoc)");
                break;
        }
    }
}
