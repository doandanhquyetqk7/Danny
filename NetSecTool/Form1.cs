using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetSecTool
{
    public partial class Form1 : Form
    {
        // --- Bang mau quan doi ---
        private static readonly Color ClrDarkGreen = Color.FromArgb(23, 74, 44);
        private static readonly Color ClrMidGreen = Color.FromArgb(34, 104, 62);
        private static readonly Color ClrRed = Color.FromArgb(158, 22, 22);
        private static readonly Color ClrGold = Color.FromArgb(214, 176, 58);
        private static readonly Color ClrDarkGold = Color.FromArgb(160, 126, 26);
        private static readonly Color ClrBg = Color.FromArgb(235, 239, 233);
        private static readonly Color ClrPanel = Color.FromArgb(250, 251, 248);
        private static readonly Color ClrText = Color.FromArgb(28, 34, 29);
        private static readonly Color ClrMuted = Color.FromArgb(96, 104, 97);
        private static readonly Color ClrLogBg = Color.FromArgb(14, 30, 20);
        private static readonly Color ClrLogText = Color.FromArgb(142, 232, 150);
        private static readonly Color ClrLogGold = Color.FromArgb(214, 176, 58);
        private static readonly Color ClrLogRed = Color.FromArgb(240, 120, 110);
        private static readonly Color ClrLogBlue = Color.FromArgb(120, 200, 235);

        // --- Controls ---
        TextBox txtAdapter, txtIP, txtSubnet, txtGateway, txtDNS;
        ComboBox cmbDrives;
        ComboBox cmbUsbDrives;
        TextBox txtVersion, txtVendor, txtSeed;
        RichTextBox txtLog;
        Button btnChangeIP, btnRunKVRT, btnRefreshDrives, btnUncoverFiles, btnClearLogs;
        Button btnMakeUsbSafe, btnCheckUsbSafe, btnUnlockUsb;
        Label lblUsbInfo;

        // --- Cau hinh IP mot cham ---
        UnitSearchBox searchOneClickUnit;
        Button btnOneClick, btnOneClickDetect, btnOneClickRestore, btnOneClickRefresh;
        RichTextBox txtOneClickLog;
        ProgressBar barOneClick;
        Label lblOneIpLan, lblOneGwLan, lblOneIpWan, lblOneGwWan, lblOneCurrent;

        // --- Kiem tra ket noi ---
        ComboBox cmbDiagAdapter;
        UnitSearchBox searchDiagUnit;
        Label lblDiagUnitInfo;
        Button btnRunDiag, btnSaveReport, btnDiagQuick, btnDiagFull, btnRefreshAdapters;
        RichTextBox txtDiagLog;
        Label lblDiagSummary;
        ProgressBar barDiag;

        // --- Lam sach PC mot cham ---
        Button btnCleanNow, btnCleanStop;
        RichTextBox txtCleanLog;
        ProgressBar barClean;
        Label lblCleanSummary;
        CheckBox chkCleanBrowser = null!, chkCleanSrum = null!, chkCleanDns = null!, chkCleanPrefetch = null!,
                      chkCleanAmcache = null!, chkCleanRunMru = null!, chkCleanJumpList = null!, chkCleanEventLog = null!,
                      chkCleanMiAV = null!, chkCleanKvrt = null!, chkCleanReboot = null!, chkInstallMiAV = null!;
        CancellationTokenSource? ctsClean;
        bool cleanRunning;

        public Form1()
        {
            InitializeComponent();
            SetupUI();
        }

        // ==================================================================
        // GIAO DIEN - PHONG CACH QUAN DOI, BO CUC TAB
        // ==================================================================

        private void SetupUI()
        {
            this.Text = "DANNY ver5.0 - Trợ lý Công nghệ Thông tin";
            this.Size = new Size(1000, 800);
            this.MinimumSize = new Size(880, 640);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.BackColor = ClrBg;
            this.Font = new Font("Segoe UI", 9f);
            this.AutoScaleMode = AutoScaleMode.Font;

            // ================= ROOT LAYOUT =================
            // Bang dieu khien goc 3 hang: HEADER / TABS / FOOTER.
            //
            // Ban 1.0 dung Dock + SetChildIndex -> thu tu z-order sai lam
            // TabControl chong len Panel header (ca hai cung Y=0), nen tab
            // strip bi header cat mat va khong click duoc.
            // TableLayoutPanel loai bo hoan toan kha nang nay: moi control
            // nam trong mot o rieng, khong the chong nhau.
            var root = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Margin = Padding.Empty,
                Padding = Padding.Empty,
                BackColor = ClrBg
            };
            root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 76));   // 0 - header
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 1 - tab
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));   // 2 - footer
            this.Controls.Add(root);

            root.Controls.Add(BuildHeader(), 0, 0);
            root.Controls.Add(BuildTabs(), 0, 1);
            root.Controls.Add(BuildFooter(), 0, 2);

            LoadDrives();
            LoadUsbDrives();
            LoadDiagAdapters();
        }

        /// <summary>Header: logo + tieu de + nhan phien ban + thong tin tac gia.</summary>
        private Control BuildHeader()
        {
            // Bang 2 cot: cot 0 = logo + chu, cot 1 = nhan ver3.0 neo ben phai.
            // Dung TableLayoutPanel de nhan luon nam dung cho du cua so thu nho
            // (dinh vi "Location = 600" se bi day ra ngoai man hinh khi co giang).
            var tblHeader = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                BackColor = ClrDarkGreen,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            tblHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tblHeader.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 70));
            tblHeader.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            // --- Cot 0: logo + tieu de + thong tin tac gia ---
            var pnlText = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = ClrDarkGreen,
                Margin = Padding.Empty
            };

            // --- Logo ---
            PictureBox picLogo = new PictureBox
            {
                Location = new Point(14, 8),
                Size = new Size(60, 60),
                SizeMode = PictureBoxSizeMode.Zoom,
                BackColor = ClrDarkGreen
            };
            try
            {
                using Stream? s = Assembly.GetExecutingAssembly()
                    .GetManifestResourceStream("NetSecTool.Resources.logo.png");
                if (s != null)
                {
                    using var ms = new MemoryStream();
                    s.CopyTo(ms);
                    ms.Position = 0;
                    picLogo.Image = Image.FromStream(ms);
                }
            }
            catch { /* khong co logo - bo qua */ }
            pnlText.Controls.Add(picLogo);

            // --- Tieu de ---
            Label lblTitle = new Label
            {
                Text = "DANNY  —  TRỢ LÝ CÔNG NGHỆ THÔNG TIN",
                ForeColor = Color.White,
                Font = new Font("Segoe UI", 15f, FontStyle.Bold),
                Location = new Point(88, 8),
                AutoSize = true,
                BackColor = Color.Transparent
            };
            pnlText.Controls.Add(lblTitle);

            // --- Thong tin tac gia ---
            Label lblSub = new Label
            {
                Text = "Phần mềm được viết bởi Trung tá Đoàn Danh Quyết - Trợ lý Công nghệ Thông tin - Cellphone: 0366.714.139",
                ForeColor = ClrGold,
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                Location = new Point(90, 38),
                AutoSize = true,
                BackColor = Color.Transparent
            };
            pnlText.Controls.Add(lblSub);

            tblHeader.Controls.Add(pnlText, 0, 0);

            // --- Cot 1: nhan phien ban ---
            var pnlVer = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = ClrDarkGreen,
                Margin = Padding.Empty,
                Padding = new Padding(0, 12, 14, 0)
            };
            Label lblVer = new Label
            {
                Text = "ver5.0",
                ForeColor = ClrDarkGreen,
                BackColor = ClrGold,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                Margin = Padding.Empty
            };
            pnlVer.Controls.Add(lblVer);
            tblHeader.Controls.Add(pnlVer, 1, 0);

            // --- Soc mau do ---
            Panel pnlStripe = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 5,
                BackColor = ClrRed
            };
            tblHeader.Controls.Add(pnlStripe);

            return tblHeader;
        }

        /// <summary>Footer: dong thong tin tac gia.</summary>
        private Control BuildFooter()
        {
            return new Label
            {
                Text = "Phần mềm được viết bởi Trung tá Đoàn Danh Quyết - Trợ lý Công nghệ Thông tin - Cellphone: 0366.714.139",
                ForeColor = ClrRed,
                Font = new Font("Segoe UI", 9f, FontStyle.Italic | FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = ClrBg,
                Margin = Padding.Empty
            };
        }

        /// <summary>Tao TabControl voi 4 trang chuc nang.</summary>
        private TabControl BuildTabs()
        {
            var tabs = new TabControl
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 10f, FontStyle.Bold),
                Padding = new Point(18, 6),
                Margin = Padding.Empty
            };

            var tabDiag = new TabPage("  KIỂM TRA KẾT NỐI  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };
            var tabUsb = new TabPage("  USB AN TOÀN 2.6  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };
            var tabOneClick = new TabPage("  CẤU HÌNH IP MỘT CHẠM  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };
            var tabNet = new TabPage("  CẤU HÌNH MẠNG  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };
            var tabTools = new TabPage("  BẢO MẬT & TIỆN ÍCH  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };
            var tabClean = new TabPage("  LÀM SẠCH PC MỘT CHẠM  ")
            {
                BackColor = ClrBg,
                Font = new Font("Segoe UI", 9f),
                Padding = new Padding(10)
            };

            // An bang goi y cua o tim kiem khi nguoi dung doi tab
            tabs.SelectedIndexChanged += (s, e) =>
            {
                searchDiagUnit?.HideSuggestions();
                searchOneClickUnit?.HideSuggestions();
            };

            tabs.TabPages.Add(tabDiag);
            tabs.TabPages.Add(tabUsb);
            tabs.TabPages.Add(tabOneClick);
            tabs.TabPages.Add(tabNet);
            tabs.TabPages.Add(tabClean);
            tabs.TabPages.Add(tabTools);

            BuildDiagTab(tabDiag);
            BuildUsbTab(tabUsb);
            BuildOneClickTab(tabOneClick);
            BuildNetTab(tabNet);
            BuildCleanTab(tabClean);
            BuildToolsTab(tabTools);

            return tabs;
        }

        // ==================================================================
        // TAB 1: KIEM TRA KET NOI
        // ==================================================================

        private void BuildDiagTab(TabPage tab)
        {
            // 5 hang: dieu khien / ket qua / progress / log / nut
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 122));  // 0 - dieu khien (card mang + tim don vi)
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));   // 1 - ket qua
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - log
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));   // 4 - nut
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildDiagTopPanel(), 0, 0);

            // --- Thanh ket qua ---
            lblDiagSummary = new Label
            {
                Text = "Chưa chạy kiểm tra.",
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(240, 243, 238),
                ForeColor = ClrMuted,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(12, 0, 0, 0),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 2, 0, 2)
            };
            layout.Controls.Add(lblDiagSummary, 0, 1);

            // --- Thanh tien do ---
            barDiag = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barDiag, 0, 2);

            // --- Nhat ky chan doan ---
            txtDiagLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = ClrLogBg,
                ForeColor = ClrLogText,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                Margin = new Padding(0, 4, 0, 4),
                TabStop = true
            };
            layout.Controls.Add(txtDiagLog, 0, 3);

            // --- Hang nut duoi ---
            layout.Controls.Add(BuildDiagBottomPanel(), 0, 4);
        }

        /// <summary>Hang dieu khien tren: chon card mang, tim don vi + 3 nut chay chan doan.</summary>
        private Control BuildDiagTopPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 4,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 4),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));    // 0 - combo
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 98));    // 1 - lam moi
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 152));   // 2 - nhanh
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 196));   // 3 - day du
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));   // 0 - card mang
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 1 - tim don vi
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 22));   // 2 - thong tin don vi
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - ghi chu

            // --- Chon card mang ---
            var pnlAdapter = new Panel { Dock = DockStyle.Fill, Margin = Padding.Empty };
            pnlAdapter.Controls.Add(MakeLabel("Card mạng:", 0, 7));

            cmbDiagAdapter = new ComboBox
            {
                Location = new Point(80, 4),
                Width = 280,
                Height = 24,
                Anchor = AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Top,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 9f)
            };
            pnlAdapter.Controls.Add(cmbDiagAdapter);
            tbl.Controls.Add(pnlAdapter, 0, 0);

            // --- Nut lam moi ---
            btnRefreshAdapters = MakeButton("Làm mới", 0, 0, 88, 26, ClrDarkGold);
            btnRefreshAdapters.Click += (s, e) => LoadDiagAdapters();
            btnRefreshAdapters.Dock = DockStyle.Fill;
            btnRefreshAdapters.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnRefreshAdapters, 1, 0);

            // --- Nut kiem tra nhanh ---
            btnDiagQuick = MakeButton("KIỂM TRA NHANH", 0, 0, 142, 26, ClrMidGreen);
            btnDiagQuick.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            btnDiagQuick.Click += (s, e) => RunDiagnostics(false);
            btnDiagQuick.Dock = DockStyle.Fill;
            btnDiagQuick.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnDiagQuick, 2, 0);

            // --- Nut kiem tra day du ---
            btnDiagFull = MakeButton("KIỂM TRA ĐẦY ĐỦ", 0, 0, 186, 26, ClrRed);
            btnDiagFull.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            btnDiagFull.Click += (s, e) => RunDiagnostics(true);
            btnDiagFull.Dock = DockStyle.Fill;
            btnDiagFull.Margin = Padding.Empty;
            tbl.Controls.Add(btnDiagFull, 3, 0);

            // --- Hang 1: TIM KIEM DON VI (co goi y tu dong) ---
            tbl.Controls.Add(MakeLabel("Đơn vị:", 0, 7), 0, 1);

            searchDiagUnit = new UnitSearchBox
            {
                Placeholder = "Nhập tên đơn vị để tìm — có dấu hoặc không dấu (VD: \"xuan huong\", \"994A\", \"lac duong\")",
                Margin = new Padding(0, 3, 0, 3)
            };
            searchDiagUnit.UnitSelected += (s, e) => OnDiagUnitSelected();
            tbl.Controls.Add(searchDiagUnit, 1, 1);
            tbl.SetColumnSpan(searchDiagUnit, 3);

            // --- Hang 2: thong tin don vi da chon ---
            lblDiagUnitInfo = new Label
            {
                Text = "Chưa chọn đơn vị — kết quả sẽ tự nhận diện đơn vị từ IP/gateway của máy.",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblDiagUnitInfo, 0, 2);
            tbl.SetColumnSpan(lblDiagUnitInfo, 4);

            // --- Hang 3: ghi chu ---
            var lblHint = new Label
            {
                Text = "Chế độ nhanh: 4 bước cơ bản (link, driver, gateway, DNS).   Đầy đủ: thêm tracert & quét modem WAN.",
                ForeColor = Color.FromArgb(90, 98, 91),
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblHint, 0, 3);
            tbl.SetColumnSpan(lblHint, 4);

            return tbl;
        }

        /// <summary>Hang nut duoi tab chan doan.</summary>
        private Control BuildDiagBottomPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                BackColor = ClrPanel,
                Padding = new Padding(12, 10, 12, 10),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 140));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 165));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnRunDiag = MakeButton("CHẠY LẠI", 0, 0, 130, 28, ClrMidGreen);
            btnRunDiag.Click += (s, e) => RunDiagnostics(true);
            btnRunDiag.Dock = DockStyle.Fill;
            btnRunDiag.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnRunDiag, 0, 0);

            btnSaveReport = MakeButton("XUẤT BÁO CÁO", 0, 0, 160, 28, ClrDarkGold);
            btnSaveReport.Click += (s, e) => SaveReport();
            btnSaveReport.Dock = DockStyle.Fill;
            btnSaveReport.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnSaveReport, 1, 0);

            var lblHint = new Label
            {
                Text = "Báo cáo được lưu trên Desktop dưới dạng \"Báo cáo kết nối.txt\".",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblHint, 2, 0);

            return tbl;
        }

        private void LoadDiagAdapters()
        {
            if (cmbDiagAdapter == null) return;

            cmbDiagAdapter.Items.Clear();
            try
            {
                foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (nic.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                        continue;

                    string status = nic.OperationalStatus.ToString();
                    string label = $"{nic.Name}  [{status}]  — {nic.Description}";
                    cmbDiagAdapter.Items.Add(label);
                }
            }
            catch { }

            if (cmbDiagAdapter.Items.Count > 0)
            {
                // Uu tien card Ethernet dang Link Up
                int idx = 0;
                for (int i = 0; i < cmbDiagAdapter.Items.Count; i++)
                {
                    string s = cmbDiagAdapter.Items[i].ToString();
                    if (s.Contains("Up") && s.Contains("Ethernet")) { idx = i; break; }
                }
                cmbDiagAdapter.SelectedIndex = idx;
            }
        }

        private string GetSelectedDiagAdapterName()
        {
            if (cmbDiagAdapter?.SelectedItem == null) return "";
            string s = cmbDiagAdapter.SelectedItem.ToString();

            // "Ethernet [Up] — Intel(R) ..." -> lay phan truoc " ["
            int br = s.IndexOf(" [");
            return br > 0 ? s[..br].Trim() : s;
        }

        /// <summary>Xu ly khi nguoi dung chon don vi trong o tim kiem o tab chan doan.</summary>
        private void OnDiagUnitSelected()
        {
            if (lblDiagUnitInfo == null) return;

            var hit = searchDiagUnit?.Selected;
            if (hit == null)
            {
                lblDiagUnitInfo.Text = "Chưa chọn đơn vị — kết quả sẽ tự nhận diện đơn vị từ IP/gateway của máy.";
                lblDiagUnitInfo.ForeColor = ClrMuted;
                return;
            }

            if (hit.Unit is IpPlan.Unit u)
            {
                lblDiagUnitInfo.Text =
                    $"{u.Name}   |   Dải LAN: {u.LanCidr} (mask {u.SubnetMask})   |   " +
                    $"GW LAN: {u.LanGateway}   |   IP WAN modem: {u.WanIp}   |   " +
                    $"GW WAN: {u.WanGateway}   |   DNS: {IpPlan.MilitaryDns}";
                lblDiagUnitInfo.ForeColor = ClrDarkGreen;
            }

        }

        private async void RunDiagnostics(bool full)
        {
            btnRunDiag.Enabled = false;
            btnDiagQuick.Enabled = false;
            btnDiagFull.Enabled = false;
            barDiag.Style = ProgressBarStyle.Marquee;
            barDiag.MarqueeAnimationSpeed = 30;
            lblDiagSummary.Text = "Đang chẩn đoán...";
            lblDiagSummary.ForeColor = ClrDarkGold;
            txtDiagLog.Clear();

            try
            {
                var opt = new NetDiagnostics.Options
                {
                    AdapterName = GetSelectedDiagAdapterName(),
                    IpAddress = txtIP?.Text.Trim() ?? "",
                    Gateway = txtGateway?.Text.Trim() ?? "",
                    PingCount = 4,
                    TimeoutSeconds = 8,
                    RunTracert = full,
                    TestModemWan = full,
                    ReportFile = "Báo cáo kết nối.txt",
                    Unit = searchDiagUnit?.Selected?.Unit
                };

                var progress = new NetDiagnostics.Progress(msg =>
                {
                    // Chay tren UI thread (Task.Run + Progress se marshal ve UI thread)
                });

                var (results, report) = await Task.Run(() => NetDiagnostics.Run(opt, progress));

                foreach (var r in results)
                {
                    Color c = r.Level switch
                    {
                        CheckLevel.Ok => Color.FromArgb(120, 235, 130),
                        CheckLevel.Warn => ClrLogGold,
                        CheckLevel.Fail => ClrLogRed,
                        _ => ClrLogText
                    };
                    DiagLog(r.Icon + " " + r.Step, c, bold: true);
                    DiagLog("     " + r.Message, c);
                    if (!string.IsNullOrWhiteSpace(r.Detail))
                        DiagLog("     " + r.Detail, Color.FromArgb(120, 150, 125));
                    DiagLog("", ClrLogText);
                }

                int ok = results.Count(r => r.Level == CheckLevel.Ok);
                int warn = results.Count(r => r.Level == CheckLevel.Warn);
                int fail = results.Count(r => r.Level == CheckLevel.Fail);

                string verdict = fail > 0
                    ? "CÓ LỖI — cần can thi của đơn vị quản trị mạng"
                    : warn > 0
                        ? "KẾT NỐI ĐƯỢC nhưng có cảnh báo — xem chi tiết"
                        : "KẾT NỐI BÌNH THƯỜNG — tất cả các bước đạt yêu cầu";

                lblDiagSummary.Text = $"   KẾT QUẢ:  ✔ {ok} thành công   |   ⚠ {warn} cảnh báo   |   ✖ {fail} lỗi    —    {verdict}";
                lblDiagSummary.ForeColor = fail > 0 ? ClrRed : (warn > 0 ? ClrDarkGold : ClrDarkGreen);
                lblDiagSummary.BackColor = fail > 0 ? Color.FromArgb(253, 235, 235)
                                            : (warn > 0 ? Color.FromArgb(253, 248, 232)
                                                        : Color.FromArgb(234, 245, 236));

                _lastReport = report;
                DiagLog("Đã hoàn tất. Bấm \"XUẤT BÁO CÁO\" để lưu kết quả.", ClrLogGold);
            }
            catch (Exception ex)
            {
                DiagLog("[FAIL] LỖI: " + ex.Message, ClrLogRed);
                lblDiagSummary.Text = "   LỖI KHI CHẨN ĐOÁN: " + ex.Message;
                lblDiagSummary.ForeColor = ClrRed;
            }
            finally
            {
                barDiag.Style = ProgressBarStyle.Continuous;
                barDiag.Value = 0;
                btnRunDiag.Enabled = true;
                btnDiagQuick.Enabled = true;
                btnDiagFull.Enabled = true;
            }
        }

        private string _lastReport = "";

        private void DiagLog(string text, Color color, bool bold = false)
        {
            if (txtDiagLog == null) return;
            txtDiagLog.SelectionStart = txtDiagLog.TextLength;
            txtDiagLog.SelectionLength = 0;
            txtDiagLog.SelectionColor = color;
            if (bold) txtDiagLog.SelectionFont = new Font("Consolas", 9f, FontStyle.Bold);
            txtDiagLog.AppendText(text + "\n");
            txtDiagLog.SelectionStart = txtDiagLog.TextLength;
            txtDiagLog.ScrollToCaret();
        }

        private void SaveReport()
        {
            if (string.IsNullOrWhiteSpace(_lastReport))
            {
                DiagLog("[WARN] Chưa có kết quả để xuất. Hãy chạy kiểm tra trước.", ClrLogGold);
                return;
            }

            try
            {
                string desktop = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
                string path = Path.Combine(desktop, "Báo cáo kết nối.txt");
                File.WriteAllText(path, _lastReport, new System.Text.UTF8Encoding(true));
                DiagLog("[ OK ] Đã lưu báo cáo: " + path, Color.FromArgb(120, 235, 130));
            }
            catch (Exception ex)
            {
                try
                {
                    string path = Path.Combine(AppContext.BaseDirectory, "Báo cáo kết nối.txt");
                    File.WriteAllText(path, _lastReport, new System.Text.UTF8Encoding(true));
                    DiagLog("[ OK ] Đã lưu báo cáo: " + path, Color.FromArgb(120, 235, 130));
                }
                catch (Exception ex2)
                {
                    DiagLog("[FAIL] Không lưu được báo cáo: " + ex2.Message, ClrLogRed);
                }
            }
        }

        // ==================================================================
        // TAB 2: USB AN TOAN 2.6
        // ==================================================================

        private void BuildUsbTab(TabPage tab)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 244));  // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 1 - log
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 2 - ghi chu
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildUsbControlPanel(), 0, 0);

            // --- Nhat ky ---
            txtLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = ClrLogBg,
                ForeColor = ClrLogText,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                Margin = new Padding(0, 4, 0, 4),
                TabStop = true
            };
            layout.Controls.Add(txtLog, 0, 1);

            // --- Ghi chu duoi ---
            var lblUsbHint = new Label
            {
                Text = "Sau khi tạo: người dùng ghi dữ liệu trong thư mục DATA\\ (đọc/ghi được, không chạy được file .exe/.bat/.cmd/.ps1).",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Italic),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(2, 0, 0, 0),
                AutoSize = false,
                Margin = Padding.Empty
            };
            layout.Controls.Add(lblUsbHint, 0, 2);
        }

        /// <summary>Bang dieu khien tao USB an toan.</summary>
        private Control BuildUsbControlPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 7,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 8),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 96));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));  // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));  // 1 - o USB
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));  // 2 - phien ban
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));  // 3 - seed
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // 4 - nut tao
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));  // 5 - nut phu
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // 6 - thong tin

            // --- 0. Tieu de ---
            var lblUsbTitle = new Label
            {
                Text = "TẠO USB AN TOÀN 2.6  (tương thích phần mềm giám sát MiAV)",
                ForeColor = ClrDarkGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblUsbTitle, 0, 0);
            tbl.SetColumnSpan(lblUsbTitle, 4);

            // --- 1. Chon o USB ---
            tbl.Controls.Add(MakeLabel("Ổ USB:", 0, 0), 0, 1);

            cmbUsbDrives = new ComboBox
            {
                Dock = DockStyle.Fill,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Margin = new Padding(0, 2, 8, 2)
            };
            tbl.Controls.Add(cmbUsbDrives, 1, 1);

            Button btnRefreshUsb = MakeButton("Làm mới", 0, 0, 88, 26, ClrDarkGold);
            btnRefreshUsb.Click += (s, e) => LoadUsbDrives();
            btnRefreshUsb.Dock = DockStyle.Fill;
            btnRefreshUsb.Margin = new Padding(0, 2, 0, 2);
            tbl.Controls.Add(btnRefreshUsb, 2, 1);
            tbl.SetColumnSpan(btnRefreshUsb, 2);

            // --- 2. Phien ban + hang san xuat ---
            tbl.Controls.Add(MakeLabel("Phiên bản:", 0, 0), 0, 2);

            txtVersion = MakeTextBox(UsbSafeMaker.DefaultVersion, 0, 0, 120);
            txtVersion.Dock = DockStyle.Fill;
            txtVersion.Margin = new Padding(0, 3, 8, 3);
            tbl.Controls.Add(txtVersion, 1, 2);

            tbl.Controls.Add(MakeLabel("Hãng SX:", 0, 0), 2, 2);

            txtVendor = MakeTextBox(UsbSafeMaker.DefaultVendor, 0, 0, 120);
            txtVendor.Dock = DockStyle.Fill;
            txtVendor.Margin = new Padding(0, 3, 0, 3);
            tbl.Controls.Add(txtVendor, 3, 2);

            // --- 3. Seed ---
            tbl.Controls.Add(MakeLabel("Seed (khóa):", 0, 0), 0, 3);

            txtSeed = MakeTextBox(UsbSafeMaker.DefaultSeed, 0, 0, 300);
            txtSeed.Dock = DockStyle.Fill;
            txtSeed.Margin = new Padding(0, 3, 0, 3);
            tbl.Controls.Add(txtSeed, 1, 3);
            tbl.SetColumnSpan(txtSeed, 3);

            // --- 4. Nut tao USB an toan ---
            btnMakeUsbSafe = MakeButton("TẠO USB AN TOÀN 2.6", 0, 0, 400, 34, ClrMidGreen);
            btnMakeUsbSafe.Click += BtnMakeUsbSafe_Click;
            btnMakeUsbSafe.Dock = DockStyle.Fill;
            btnMakeUsbSafe.Margin = new Padding(0, 4, 0, 4);
            tbl.Controls.Add(btnMakeUsbSafe, 0, 4);
            tbl.SetColumnSpan(btnMakeUsbSafe, 4);

            // --- 5. Hai nut phu ---
            btnCheckUsbSafe = MakeButton("Kiểm tra trạng thái", 0, 0, 200, 28, ClrDarkGold);
            btnCheckUsbSafe.Click += BtnCheckUsbSafe_Click;
            btnCheckUsbSafe.Dock = DockStyle.Fill;
            btnCheckUsbSafe.Margin = new Padding(0, 0, 4, 0);
            tbl.Controls.Add(btnCheckUsbSafe, 0, 5);
            tbl.SetColumnSpan(btnCheckUsbSafe, 2);

            btnUnlockUsb = MakeButton("Mở khóa quyền ghi", 0, 0, 200, 28, ClrRed);
            btnUnlockUsb.Click += BtnUnlockUsb_Click;
            btnUnlockUsb.Dock = DockStyle.Fill;
            btnUnlockUsb.Margin = new Padding(4, 0, 0, 0);
            tbl.Controls.Add(btnUnlockUsb, 2, 5);
            tbl.SetColumnSpan(btnUnlockUsb, 2);

            // --- 6. Thong tin o USB ---
            lblUsbInfo = new Label
            {
                Text = "Chưa chọn ổ USB.",
                ForeColor = ClrMuted,
                BackColor = Color.FromArgb(240, 243, 238),
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(6, 0, 6, 0),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = new Padding(0, 4, 0, 0)
            };
            tbl.Controls.Add(lblUsbInfo, 0, 6);
            tbl.SetColumnSpan(lblUsbInfo, 4);

            return tbl;
        }

        // ==================================================================
        // TAB 3: CAU HINH IP MOT CHAM
        // ==================================================================

        private void BuildOneClickTab(TabPage tab)
        {
            // 5 hang: dieu khien / thong tin don vi / progress / log / nut
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 92));   // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));   // 1 - thong tin don vi
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 18));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - log
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));   // 4 - nut
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildOneClickTopPanel(), 0, 0);
            layout.Controls.Add(BuildOneClickInfoPanel(), 0, 1);

            // --- Thanh tien do ---
            barOneClick = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barOneClick, 0, 2);

            // --- Nhat ky ---
            txtOneClickLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = ClrLogBg,
                ForeColor = ClrLogText,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                WordWrap = false,
                ScrollBars = RichTextBoxScrollBars.Both,
                Margin = new Padding(0, 4, 0, 4),
                TabStop = true
            };
            layout.Controls.Add(txtOneClickLog, 0, 3);

            layout.Controls.Add(BuildOneClickBottomPanel(), 0, 4);

            // Tu dong dien don vi theo cau hinh hien tai
            LoadOneClickUnits();
        }

        /// <summary>Hang dieu khien: chon don vi + nut cau hinh.</summary>
        private Control BuildOneClickTopPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 2,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 4),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));   // 0 - nhan
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));   // 1 - combo
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));   // 2 - nut
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            tbl.Controls.Add(MakeLabel("Đơn vị:", 0, 7), 0, 0);

            // O tim kiem co goi y tu dong (ho tro co dau / khong dau)
            searchOneClickUnit = new UnitSearchBox
            {
                Placeholder = "Nhập tên đơn vị — có dấu hoặc không dấu (VD: \"xuan huong\", \"994A\", \"dam rong\")",
                Margin = new Padding(0, 4, 8, 4)
            };
            searchOneClickUnit.UnitSelected += (s, e) => OnOneClickUnitSelected();
            tbl.Controls.Add(searchOneClickUnit, 1, 0);

            btnOneClick = MakeButton("CẤU HÌNH IP MỘT CHẠM", 0, 0, 180, 26, ClrRed);
            btnOneClick.Font = new Font("Segoe UI", 8.5f, FontStyle.Bold);
            btnOneClick.Click += BtnOneClick_Click;
            btnOneClick.Dock = DockStyle.Fill;
            btnOneClick.Margin = Padding.Empty;
            tbl.Controls.Add(btnOneClick, 2, 0);

            // Ghi chu
            var lblHint = new Label
            {
                Text = "Tự động tìm IP trống trong dải LAN của đơn vị, gán IP tĩnh + DNS 86.0.188.1. " +
                       "Tự động hoàn tác nếu không ping được gateway.",
                ForeColor = Color.FromArgb(90, 98, 91),
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblHint, 0, 1);
            tbl.SetColumnSpan(lblHint, 3);

            return tbl;
        }

        /// <summary>Bang thong tin quy hoach cua don vi dang chon.</summary>
        private Control BuildOneClickInfoPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 3,
                BackColor = Color.FromArgb(240, 243, 238),
                Padding = new Padding(12, 6, 12, 6),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 92));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            for (int i = 0; i < 3; i++)
                tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 33.34f));

            lblOneIpLan = MakeInfoValue();
            lblOneGwLan = MakeInfoValue();
            lblOneIpWan = MakeInfoValue();
            lblOneGwWan = MakeInfoValue();

            tbl.Controls.Add(MakeInfoLabel("Dải LAN:"), 0, 0);
            tbl.Controls.Add(lblOneIpLan, 1, 0);
            tbl.Controls.Add(MakeInfoLabel("Gateway LAN:"), 2, 0);
            tbl.Controls.Add(lblOneGwLan, 3, 0);

            tbl.Controls.Add(MakeInfoLabel("IP WAN:"), 0, 1);
            tbl.Controls.Add(lblOneIpWan, 1, 1);
            tbl.Controls.Add(MakeInfoLabel("Gateway WAN:"), 2, 1);
            tbl.Controls.Add(lblOneGwWan, 3, 1);

            tbl.Controls.Add(MakeInfoLabel("DNS quân sự:"), 0, 2);
            var lblDns = MakeInfoValue();
            lblDns.Text = IpPlan.MilitaryDns;
            lblDns.ForeColor = ClrDarkGreen;
            tbl.Controls.Add(lblDns, 1, 2);

            var lblNow = MakeInfoLabel("Máy hiện tại:");
            tbl.Controls.Add(lblNow, 2, 2);
            lblOneCurrent = MakeInfoValue();
            lblOneCurrent.ForeColor = ClrDarkGold;
            tbl.Controls.Add(lblOneCurrent, 3, 2);

            return tbl;
        }

        private static Label MakeInfoLabel(string text) => new Label
        {
            Text = text,
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = ClrMuted,
            Font = new Font("Segoe UI", 9f),
            AutoSize = false,
            Margin = Padding.Empty
        };

        private static Label MakeInfoValue() => new Label
        {
            Text = "—",
            Dock = DockStyle.Fill,
            TextAlign = ContentAlignment.MiddleLeft,
            ForeColor = ClrText,
            Font = new Font("Consolas", 9.5f, FontStyle.Bold),
            AutoSize = false,
            Margin = Padding.Empty
        };

        /// <summary>Hang nut duoi.</summary>
        private Control BuildOneClickBottomPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 1,
                BackColor = ClrPanel,
                Padding = new Padding(12, 10, 12, 10),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnOneClickDetect = MakeButton("Nhận diện đơn vị", 0, 0, 140, 26, ClrDarkGold);
            btnOneClickDetect.Click += (s, e) => DetectCurrentUnit();
            btnOneClickDetect.Dock = DockStyle.Fill;
            btnOneClickDetect.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnOneClickDetect, 0, 0);

            btnOneClickRestore = MakeButton("Khôi phục IP cũ", 0, 0, 140, 26, ClrRed);
            btnOneClickRestore.Click += BtnOneClickRestore_Click;
            btnOneClickRestore.Dock = DockStyle.Fill;
            btnOneClickRestore.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnOneClickRestore, 1, 0);

            btnOneClickRefresh = MakeButton("Tải lại danh sách", 0, 0, 140, 26, ClrDarkGold);
            btnOneClickRefresh.Click += (s, e) => LoadOneClickUnits();
            btnOneClickRefresh.Dock = DockStyle.Fill;
            btnOneClickRefresh.Margin = new Padding(0, 0, 8, 0);
            tbl.Controls.Add(btnOneClickRefresh, 2, 0);

            var lblHint = new Label
            {
                Text = "Cấu hình IP tĩnh cần quyền Administrator. Phần mềm đã yêu cầu sẵn khi khởi động.",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 8.5f),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblHint, 3, 0);

            return tbl;
        }

        /// <summary>
        /// Nap danh sach don vi mac dinh vao o tim kiem.
        /// </summary>
        private void LoadOneClickUnits()
        {
            if (searchOneClickUnit == null) return;

            // Neu chua chon don vi nao -> chon don vi dau tien theo ten
            if (searchOneClickUnit.Selected == null)
            {
                var first = IpPlan.SortedByName().FirstOrDefault();
                if (first != null) searchOneClickUnit.SelectUnit(first);
            }

            UpdateOneClickInfo();
        }

        /// <summary>Don vi dang duoc chon o tab Cau hinh IP mot cham.</summary>
        private IpPlan.Unit? CurrentOneClickUnit =>
            searchOneClickUnit?.Selected?.Unit;

        /// <summary>Xu ly khi nguoi dung chon don vi trong o tim kiem.</summary>
        private void OnOneClickUnitSelected()
        {
            if (searchOneClickUnit?.Selected == null) return;

            var hit = searchOneClickUnit.Selected;

            UpdateOneClickInfo();
        }

        /// <summary>Cap nhat bang thong tin theo don vi dang chon.</summary>
        private void UpdateOneClickInfo()
        {
            if (searchOneClickUnit == null || lblOneIpLan == null) return;

            if (CurrentOneClickUnit is IpPlan.Unit u)
            {
                lblOneIpLan.Text = u.LanCidr;
                lblOneGwLan.Text = u.LanGateway;
                lblOneIpWan.Text = u.WanIp;
                lblOneGwWan.Text = u.WanGateway;
            }
            else
            {
                lblOneIpLan.Text = "—";
                lblOneGwLan.Text = "—";
                lblOneIpWan.Text = "—";
                lblOneGwWan.Text = "—";
            }

            UpdateOneClickCurrent();
        }

        /// <summary>Hien thi IP + gateway hien tai cua may.</summary>
        private void UpdateOneClickCurrent()
        {
            if (lblOneCurrent == null) return;

            try
            {
                var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                var nic = nics.FirstOrDefault(n =>
                    n.Name.Equals("Ethernet", StringComparison.OrdinalIgnoreCase)) ?? nics.FirstOrDefault();

                if (nic == null)
                {
                    lblOneCurrent.Text = "(không có card mạng)";
                    return;
                }

                var ip = nic.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .FirstOrDefault() ?? "(chưa có IP)";

                var gw = nic.GetIPProperties().GatewayAddresses
                    .Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(g => g.Address.ToString())
                    .FirstOrDefault() ?? "(không có GW)";

                lblOneCurrent.Text = $"{ip} / {gw}";
            }
            catch { lblOneCurrent.Text = "(không đọc được)"; }
        }

        /// <summary>Nhan dien don vi tu cau hinh hien tai va chon trong combobox.</summary>
        private void DetectCurrentUnit()
        {
            try
            {
                var nics = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                    .Where(n => n.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up
                             && n.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                    .ToList();

                var nic = nics.FirstOrDefault(n =>
                    n.Name.Equals("Ethernet", StringComparison.OrdinalIgnoreCase)) ?? nics.FirstOrDefault();

                if (nic == null)
                {
                    OneClickLog("Không tìm thấy card mạng nào đang kết nối.", LogKind.Error);
                    return;
                }

                var ip = nic.GetIPProperties().UnicastAddresses
                    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(a => a.Address.ToString())
                    .FirstOrDefault() ?? "";

                var gw = nic.GetIPProperties().GatewayAddresses
                    .Where(g => g.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    .Select(g => g.Address.ToString())
                    .FirstOrDefault() ?? "";

                OneClickLog($"Card mạng : {nic.Name}", LogKind.Step);
                OneClickLog($"IP hiện tại: {(string.IsNullOrEmpty(ip) ? "(chưa có)" : ip)}", LogKind.Info);
                OneClickLog($"Gateway    : {(string.IsNullOrEmpty(gw) ? "(không có)" : gw)}", LogKind.Info);

                var unit = IpPlan.FindByLanIp(ip) ?? IpPlan.FindByGateway(gw);

                if (unit == null)
                {
                    OneClickLog("Không xác định được đơn vị từ cấu hình hiện tại.", LogKind.Warn);
                    return;
                }

                OneClickLog($"→ Thuộc đơn vị: {unit.Name}", LogKind.Success);
                OneClickLog($"   Dải LAN   : {unit.LanCidr} (mask {unit.SubnetMask})", LogKind.Info);
                OneClickLog($"   Gateway LAN: {unit.LanGateway}", LogKind.Info);
                OneClickLog($"   IP WAN    : {unit.WanIp}", LogKind.Info);

                // Chon don vi do trong o tim kiem
                if (searchOneClickUnit != null)
                {
                    searchOneClickUnit.SelectUnit(unit);
                    OneClickLog("Đã chọn đơn vị trong ô tìm kiếm.", LogKind.Success);
                }
            }
            catch (Exception ex)
            {
                OneClickLog("Lỗi nhận diện: " + ex.Message, LogKind.Error);
            }
        }

        /// <summary>Them dong vao nhat ky cua tab Cau hinh IP mot cham.</summary>
        private void OneClickLog(string text, LogKind kind = LogKind.Info)
        {
            if (txtOneClickLog == null) return;

            Color color = kind switch
            {
                LogKind.Success => Color.FromArgb(120, 235, 130),
                LogKind.Warn => ClrLogGold,
                LogKind.Error => ClrLogRed,
                LogKind.Step => ClrLogText,
                _ => ClrLogText
            };

            string stamp = DateTime.Now.ToString("HH:mm:ss");
            txtOneClickLog.SelectionStart = txtOneClickLog.TextLength;
            txtOneClickLog.SelectionLength = 0;
            txtOneClickLog.SelectionColor = color;
            if (kind == LogKind.Step) txtOneClickLog.SelectionFont = new Font("Consolas", 9f, FontStyle.Bold);
            txtOneClickLog.AppendText($"[{stamp}] {text}\n");
            txtOneClickLog.SelectionStart = txtOneClickLog.TextLength;
            txtOneClickLog.ScrollToCaret();
        }

        /// <summary>Nut chinh: chay quy trinh cau hinh IP mot cham.</summary>
        private async void BtnOneClick_Click(object? sender, EventArgs e)
        {
            if (CurrentOneClickUnit is not IpPlan.Unit unit)
            {
                OneClickLog("Hãy nhập tên đơn vị ở ô tìm kiếm và chọn trong danh sách gợi ý.", LogKind.Warn);
                return;
            }

            // Xac nhan truoc khi thay doi cau hinh mang
            var answer = MessageBox.Show(
                $"Cấu hình IP tĩnh cho đơn vị:\n\n" +
                $"   {unit.Name}\n" +
                $"   Dải LAN : {unit.LanCidr}\n" +
                $"   Gateway : {unit.LanGateway}\n" +
                $"   DNS     : {IpPlan.MilitaryDns}\n\n" +
                "Phần mềm sẽ tự tìm một địa chỉ IP trống trong dải LAN và áp dụng.\n" +
                "Nếu không ping được gateway, cấu hình cũ sẽ được khôi phục tự động.\n\n" +
                "Tiếp tục?",
                "Xác nhận cấu hình IP một chạm",
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button2);

            if (answer != DialogResult.Yes) return;

            btnOneClick.Enabled = false;
            btnOneClickDetect.Enabled = false;
            barOneClick.Style = ProgressBarStyle.Marquee;
            barOneClick.MarqueeAnimationSpeed = 30;

            OneClickLog("=== BẮT ĐẦU CẤU HÌNH IP MỘT CHẠM ===", LogKind.Step);
            OneClickLog($"Đơn vị: {unit.Name} ({unit.LanCidr})", LogKind.Info);

            try
            {
                var outcome = await OneClickIpService.RunAsync(
                    unit,
                    (stage, msg) => OneClickLog($"[{StageText(stage)}] {msg}", LogKind.Info));

                if (outcome.Success)
                {
                    barOneClick.Style = ProgressBarStyle.Continuous;
                    barOneClick.Value = 100;

                    OneClickLog("", LogKind.Info);
                    OneClickLog("HOÀN TẤT!", LogKind.Success);
                    foreach (var line in outcome.Message.Split('\n'))
                        OneClickLog(line.TrimEnd(), LogKind.Success);

                    if (!string.IsNullOrEmpty(outcome.BackupPath))
                        OneClickLog($"Cấu hình cũ đã lưu tại: {outcome.BackupPath}", LogKind.Info);
                }
                else
                {
                    barOneClick.Style = ProgressBarStyle.Continuous;
                    barOneClick.Value = 0;

                    OneClickLog("", LogKind.Info);
                    OneClickLog("THẤT BẠI!", LogKind.Error);
                    foreach (var line in outcome.Message.Split('\n'))
                        OneClickLog(line.TrimEnd(), LogKind.Error);
                }

                UpdateOneClickCurrent();
            }
            catch (Exception ex)
            {
                barOneClick.Style = ProgressBarStyle.Continuous;
                barOneClick.Value = 0;
                OneClickLog("LỖI KHÔNG MONG ĐỢI: " + ex.Message, LogKind.Error);
            }
            finally
            {
                btnOneClick.Enabled = true;
                btnOneClickDetect.Enabled = true;
            }
        }

        private static string StageText(OneClickIpService.Stage stage) => stage switch
        {
            OneClickIpService.Stage.DetectAdapter => "CARD MẠNG",
            OneClickIpService.Stage.ResolveUnit => "ĐƠN VỊ",
            OneClickIpService.Stage.FindFreeIp => "TÌM IP",
            OneClickIpService.Stage.Backup => "SAO LƯU",
            OneClickIpService.Stage.Apply => "ÁP DỤNG",
            OneClickIpService.Stage.Verify => "KIỂM TRA",
            OneClickIpService.Stage.Done => "XONG",
            OneClickIpService.Stage.RolledBack => "HOÀN TÁC",
            _ => stage.ToString()
        };

        /// <summary>Khoi phuc IP tu file sao luu gan nhat.</summary>
        private void BtnOneClickRestore_Click(object? sender, EventArgs e)
        {
            try
            {
                string dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "Danny", "backup");

                if (!Directory.Exists(dir))
                {
                    MessageBox.Show("Chưa có bản sao lưu nào.", "Khôi phục IP",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                var files = new DirectoryInfo(dir).GetFiles("ip-backup-*.txt")
                    .OrderByDescending(f => f.LastWriteTime)
                    .ToList();

                if (files.Count == 0)
                {
                    MessageBox.Show("Chưa có bản sao lưu nào.", "Khôi phục IP",
                        MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                var latest = files[0];
                var answer = MessageBox.Show(
                    "Khôi phục cấu hình IP từ bản sao lưu gần nhất?\n\n" +
                    $"File : {latest.Name}\n\n" +
                    "Mở file để xem lệnh khôi phục.",
                    "Khôi phục IP",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question);

                if (answer != DialogResult.Yes) return;

                OneClickLog($"Mở bản sao lưu: {latest.FullName}", LogKind.Info);
                Process.Start(new ProcessStartInfo(latest.FullName) { UseShellExecute = true });
                OneClickLog("File đã mở bằng trình soạn thảo mặc định. Chạy lệnh trong CMD quyền Administrator.", LogKind.Warn);
            }
            catch (Exception ex)
            {
                OneClickLog("Lỗi khôi phục: " + ex.Message, LogKind.Error);
            }
        }

        // ==================================================================
        // TAB 3: CAU HINH MANG
        // ==================================================================

        private void BuildNetTab(TabPage tab)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 270));  // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 1 - huong dan
            tab.Controls.Add(layout);

            // --- Bang dieu khien ---
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 7,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 8),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 150));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // 0 - tieu de
            for (int i = 1; i <= 5; i++) tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // 6 - nut bam

            var lblTitle = new Label
            {
                Text = "CẤU HÌNH IP TĨNH & DNS",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 2);

            string[] labels = { "Tên Card mạng:", "IP Address:", "Subnet Mask:", "Default Gateway:", "DNS Server:" };
            string[] defaults = { "Ethernet", "192.168.1.100", "255.255.255.0", "192.168.1.1", "8.8.8.8" };
            TextBox[] boxes = new TextBox[5];

            for (int i = 0; i < 5; i++)
            {
                tbl.Controls.Add(MakeLabel(labels[i], 0, 0), 0, i + 1);
                boxes[i] = MakeTextBox(defaults[i], 0, 0, 260);
                boxes[i].Dock = DockStyle.Fill;
                boxes[i].Margin = new Padding(0, 3, 0, 3);
                tbl.Controls.Add(boxes[i], 1, i + 1);
            }
            txtAdapter = boxes[0]; txtIP = boxes[1]; txtSubnet = boxes[2];
            txtGateway = boxes[3]; txtDNS = boxes[4];

            btnChangeIP = MakeButton("Thiết lập IP & DNS", 0, 0, 260, 32, ClrMidGreen);
            btnChangeIP.Click += BtnChangeIP_Click;
            btnChangeIP.Dock = DockStyle.Fill;
            btnChangeIP.Margin = new Padding(0, 4, 0, 0);
            // Row 6 - hang rieng cho nut (truoc day dat o row 5 se de len o DNS Server)
            tbl.Controls.Add(btnChangeIP, 0, 6);
            tbl.SetColumnSpan(btnChangeIP, 2);

            layout.Controls.Add(tbl, 0, 0);

            // --- Huong dan ---
            var info = new Label
            {
                Text = "Sau khi thiết lập, quay lại tab \"KIỂM TRA KẾT NỐI\" để kiểm tra gateway, DNS và đường truyền.\n\n" +
                       "Địa chỉ DNS quân sự cố định: 86.0.188.1",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 9f),
                Dock = DockStyle.Fill,
                Padding = new Padding(12, 10, 12, 10),
                AutoSize = false,
                Margin = Padding.Empty
            };
            layout.Controls.Add(info, 0, 1);
        }

        // ==================================================================
        // TAB 4: BAO MAT & TIEN ICH
        // ==================================================================

        private void BuildToolsTab(TabPage tab)
        {
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 2,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 186));  // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 1 - huong dan
            tab.Controls.Add(layout);

            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 4,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 8),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));  // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // 1 - KVRT
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 38));  // 2 - event viewer
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100)); // 3 - o dia

            var lblTitle = new Label
            {
                Text = "BẢO MẬT & TIỆN ÍCH",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 3);

            btnRunKVRT = MakeButton("Chạy Kaspersky (KVRT)", 0, 0, 300, 34, ClrRed);
            btnRunKVRT.Click += BtnRunKVRT_Click;
            btnRunKVRT.Dock = DockStyle.Fill;
            btnRunKVRT.Margin = new Padding(0, 3, 0, 3);
            tbl.Controls.Add(btnRunKVRT, 0, 1);
            tbl.SetColumnSpan(btnRunKVRT, 3);

            btnClearLogs = MakeButton("Xóa nhật ký Event Viewer", 0, 0, 300, 34, ClrDarkGold);
            btnClearLogs.Click += BtnClearLogs_Click;
            btnClearLogs.Dock = DockStyle.Fill;
            btnClearLogs.Margin = new Padding(0, 3, 0, 3);
            tbl.Controls.Add(btnClearLogs, 0, 2);
            tbl.SetColumnSpan(btnClearLogs, 3);

            tbl.Controls.Add(MakeLabel("Ổ đĩa:", 0, 0), 0, 3);

            cmbDrives = new ComboBox
            {
                Dock = DockStyle.Fill,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Margin = new Padding(0, 3, 8, 3)
            };
            tbl.Controls.Add(cmbDrives, 1, 3);

            var pnlDrvBtns = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlDrvBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlDrvBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlDrvBtns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnRefreshDrives = MakeButton("Làm mới", 0, 0, 88, 25, ClrDarkGold);
            btnRefreshDrives.Click += (s, e) => LoadDrives();
            btnRefreshDrives.Dock = DockStyle.Fill;
            btnRefreshDrives.Margin = new Padding(0, 3, 4, 3);
            pnlDrvBtns.Controls.Add(btnRefreshDrives, 0, 0);

            btnUncoverFiles = MakeButton("Hiện File/Folder ẩn", 0, 0, 194, 25, ClrMidGreen);
            btnUncoverFiles.Click += BtnUncoverFiles_Click;
            btnUncoverFiles.Dock = DockStyle.Fill;
            btnUncoverFiles.Margin = new Padding(4, 3, 0, 3);
            pnlDrvBtns.Controls.Add(btnUncoverFiles, 1, 0);

            tbl.Controls.Add(pnlDrvBtns, 2, 3);

            layout.Controls.Add(tbl, 0, 0);

            var info = new Label
            {
                Text = "Kaspersky (KVRT): công cụ quét virus ngoại tuyến.\n" +
                       "Xóa nhật ký Event Viewer: dọn dẹp lịch sử hệ thống.\n" +
                       "Hiện File/Folder ẩn: khôi phục file bị đánh dấu ẩn trên ổ đĩa.",
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 9f),
                Dock = DockStyle.Fill,
                Padding = new Padding(12, 10, 12, 10),
                AutoSize = false,
                Margin = Padding.Empty
            };
            layout.Controls.Add(info, 0, 1);
        }

        // ==================================================================
        // TAB 5: LAM SACH PC MOT CHAM
        // ==================================================================
        private void BuildCleanTab(TabPage tab)
        {
            // 5 hang: tu chon / tom tat / progress / log / nut
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 224));  // 0 - tuy chon
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 34));   // 1 - tom tat
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - log
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));   // 4 - nut
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildCleanOptionsPanel(), 0, 0);

            lblCleanSummary = new Label
            {
                Text = "Chưa chạy.",
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(240, 243, 238),
                ForeColor = ClrMuted,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(12, 0, 0, 0),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 2, 0, 2)
            };
            layout.Controls.Add(lblCleanSummary, 0, 1);

            barClean = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barClean, 0, 2);

            txtCleanLog = new RichTextBox
            {
                Dock = DockStyle.Fill,
                BackColor = ClrLogBg,
                ForeColor = ClrLogText,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9f),
                ReadOnly = true,
                WordWrap = false,
                Margin = Padding.Empty
            };
            layout.Controls.Add(txtCleanLog, 0, 3);

            // --- Hang nut ---
            var pnlBtns = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Margin = Padding.Empty,
                Padding = new Padding(0, 6, 0, 0)
            };
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
            pnlBtns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnCleanNow = MakeButton("BẮT ĐẦU LÀM SẠCH", 0, 0, 320, 38, ClrRed);
            btnCleanNow.Click += BtnCleanNow_Click;
            btnCleanNow.Dock = DockStyle.Fill;
            btnCleanNow.Margin = new Padding(0, 0, 4, 0);
            pnlBtns.Controls.Add(btnCleanNow, 0, 0);

            btnCleanStop = MakeButton("DỪNG", 0, 0, 320, 38, ClrDarkGold);
            btnCleanStop.Click += BtnCleanStop_Click;
            btnCleanStop.Dock = DockStyle.Fill;
            btnCleanStop.Enabled = false;
            btnCleanStop.Margin = new Padding(4, 0, 0, 0);
            pnlBtns.Controls.Add(btnCleanStop, 1, 0);

            var btnHelp = MakeButton("Hướng dẫn nhanh", 0, 0, 180, 38, ClrMidGreen);
            btnHelp.Click += (s, e) => ShowCleanHelp();
            btnHelp.Dock = DockStyle.Fill;
            btnHelp.Margin = new Padding(4, 0, 0, 0);
            pnlBtns.Controls.Add(btnHelp, 2, 0);

            layout.Controls.Add(pnlBtns, 0, 4);
        }

        /// <summary>Panel lựa chọn các nhóm hạng mục làm sạch.</summary>
        private Control BuildCleanOptionsPanel()
        {
            // 7 hang: 0 tieu de / 1-4 hang checkbox / 5 canh bao / 6 phan dem
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 7,
                BackColor = ClrPanel,
                Padding = new Padding(12, 6, 12, 6),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));   // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));   // 1
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));   // 2
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));   // 3
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));   // 4 - KVRT
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));   // 5 - canh bao
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 6 - phan dem

            var lblTitle = new Label
            {
                Text = "CHỌN HẠNG MỤC CẦN LÀM SẠCH   (mặc định: chọn toàn bộ)",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 3);

            chkCleanMiAV = MakeCheck("Xóa log MiAV (mục 6 nhóm A+B)", true);
            chkCleanBrowser = MakeCheck("Xóa lịch sử trình duyệt", true);
            chkCleanSrum = MakeCheck("Xóa SRUM (SRUDB.dat)", true);
            chkCleanDns = MakeCheck("Xóa DNS cache + ARP", true);
            chkCleanPrefetch = MakeCheck("Xóa Prefetch", true);
            chkCleanAmcache = MakeCheck("Xóa Amcache", true);
            chkCleanRunMru = MakeCheck("Xóa RunMRU/TypedPaths", true);
            chkCleanJumpList = MakeCheck("Xóa Jump List", true);
            chkCleanEventLog = MakeCheck("Xóa Windows Event Log", true);
            chkCleanKvrt = MakeCheck("Quét & khử nhiễm KVRT", true);
            chkInstallMiAV = MakeCheck("Cài lại phần mềm MiAV (BTL86)", true);
            chkCleanReboot = MakeCheck("Khởi động lại sau khi quét", true);

            // Hang 1 - nhom A (MiAV) + lich su trinh duyet
            tbl.Controls.Add(chkCleanMiAV, 0, 1);
            tbl.Controls.Add(chkCleanBrowser, 1, 1);
            tbl.Controls.Add(chkCleanSrum, 2, 1);

            // Hang 2 - nhom B + nhom C
            tbl.Controls.Add(chkCleanDns, 0, 2);
            tbl.Controls.Add(chkCleanPrefetch, 1, 2);
            tbl.Controls.Add(chkCleanAmcache, 2, 2);

            // Hang 3
            tbl.Controls.Add(chkCleanRunMru, 0, 3);
            tbl.Controls.Add(chkCleanJumpList, 1, 3);
            tbl.Controls.Add(chkCleanEventLog, 2, 3);

            // Hang 4 - KVRT + reboot
            tbl.Controls.Add(chkCleanKvrt, 0, 4);
            tbl.Controls.Add(chkInstallMiAV, 1, 4);
            tbl.Controls.Add(chkCleanReboot, 2, 4);

            // Hang 5 - canh bao
            var lblWarn = new Label
            {
                Text = "⚠ Nên NGẮT INTERNET trước khi chạy. Xóa log cục bộ không thu hồi được dữ liệu đã gửi lên server FMS.",
                ForeColor = ClrRed,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblWarn, 0, 5);
            tbl.SetColumnSpan(lblWarn, 3);

            return tbl;
        }

        private static CheckBox MakeCheck(string text, bool value)
        {
            return new CheckBox
            {
                Text = text,
                Checked = value,
                AutoSize = true,
                ForeColor = ClrText,
                Font = new Font("Segoe UI", 9f),
                BackColor = Color.Transparent,
                Margin = new Padding(4, 4, 0, 0),
                Anchor = AnchorStyles.Left
            };
        }

        private void ShowCleanHelp()
        {
            MessageBox.Show(
                "LÀM SẠCH PC MỘT CHẠM — HƯỚNG DẪN\n\n" +
                "Chức năng này tự động thực hiện quy trình vệ sinh môi trường\n" +
                "trước khi máy tính được đưa vào mạng truyền số liệu quân sự.\n\n" +
                "NHÓM A — LOG MIAV (bắt buộc):\n" +
                "  • Xóa toàn bộ bảng Logs trong data.db (sự kiện Internet/Plug-in)\n" +
                "  • Xóa 6 file policy.* (kết quả đo trạng thái Internet)\n" +
                "  • Xóa thư mục logs\\, Debug\\ và file log.txt, syslog.ini\n" +
                "  • Dừng/bật lại 4 service MiAV trong lúc xóa\n\n" +
                "NHÓM B — artifact MiAV khác:\n" +
                "  • data\\config.ini, auto\\, 0dpm\\, 2109\\, rasoat\\, Blackip.txt\n" +
                "  • Bảng LocalFiles (danh sách AutoRun đã thu thập)\n\n" +
                "NHÓM C — artifact Windows (không ảnh hưởng kết luận của MiAV):\n" +
                "  • Lịch sử Chrome/Edge/Firefox/IE, SRUM, DNS cache, Prefetch,\n" +
                "    Amcache, RunMRU/TypedPaths, Jump List, Windows Event Log\n\n" +
                "CUỐI CÙNG:\n" +
                "  • Chạy Kaspersky KVRT quét toàn bộ ổ đĩa và tự khử nhiễm\n" +
                "  • Cài lại phần mềm MiAV (BTL86) — 4 service được tạo mới\n" +
                "  • Tùy chọn khởi động lại máy\n\n" +
                "Bản sao lưu và báo cáo được lưu tại:\n  C:\\_Danny_Cleanup\\<thời điểm>\\\n\n" +
                "Lưu ý: dữ liệu đã gửi lên server FMS/BTL86 không thể thu hồi\n" +
                "bằng thao tác cục bộ — cần đề nghị quản trị viên server xóa.",
                "Hướng dẫn — Làm sạch PC một chạm",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private async void BtnCleanNow_Click(object? sender, EventArgs e)
        {
            if (cleanRunning) return;

            var opt = new CleanOptions
            {
                CleanBrowserHistory = chkCleanBrowser.Checked,
                CleanSrum = chkCleanSrum.Checked,
                CleanDnsCache = chkCleanDns.Checked,
                CleanPrefetch = chkCleanPrefetch.Checked,
                CleanAmcache = chkCleanAmcache.Checked,
                CleanRunMru = chkCleanRunMru.Checked,
                CleanJumpList = chkCleanJumpList.Checked,
                CleanEventLog = chkCleanEventLog.Checked,
                CleanMiAV = chkCleanMiAV.Checked,
                RunKvrt = chkCleanKvrt.Checked,
                InstallMiAV = chkInstallMiAV.Checked,
                RebootAfterKvrt = chkCleanReboot.Checked
            };

            if (!opt.CleanMiAV && !opt.CleanBrowserHistory && !opt.CleanSrum &&
                !opt.CleanDnsCache && !opt.CleanPrefetch && !opt.CleanAmcache &&
                !opt.CleanRunMru && !opt.CleanJumpList && !opt.CleanEventLog && !opt.RunKvrt
                && !opt.InstallMiAV)
            {
                MessageBox.Show("Chưa chọn hạng mục nào để làm sạch.", "Làm sạch PC",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string warn =
                "Sẽ XÓA lịch sử trình duyệt, log MiAV, SRUM, Prefetch, Amcache,\n" +
                "RunMRU, Jump List và toàn bộ Windows Event Log.\n\n" +
                "Sau đó chạy Kaspersky KVRT quét toàn bộ ổ đĩa (có thể mất 30–120 phút)\n";
            if (opt.InstallMiAV)
                warn += "→ Cài đặt LẠI phần mềm MiAV (BTL86) — 4 service sẽ được tạo mới.\n";
            if (opt.RebootAfterKvrt)
                warn += "→ KHỞI ĐỘNG LẠI máy khi quét xong.\n";
            warn +=
                "\nBản sao lưu sẽ được tạo tại C:\\_Danny_Cleanup\\.\n\n" +
                "Tiếp tục?";
            if (MessageBox.Show(warn, "Xác nhận làm sạch PC một chạm",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
                return;

            cleanRunning = true;
            btnCleanNow.Enabled = false;
            btnCleanStop.Enabled = true;
            btnCleanNow.Text = "ĐANG CHẠY...";
            txtCleanLog.Clear();
            lblCleanSummary.Text = "Đang thực hiện...";
            lblCleanSummary.ForeColor = ClrMidGreen;
            barClean.Value = 0;

            ctsClean = new CancellationTokenSource();
            var token = ctsClean.Token;

            CleanResult result = await Task.Run(() => PcCleaner.Run(opt,
                (msg, kind) => BeginInvokeSafe(() => CleanLog(msg, kind)),
                (c, t) => BeginInvokeSafe(() =>
                {
                    barClean.Maximum = Math.Max(1, t);
                    barClean.Value = Math.Min(c, Math.Max(1, t));
                }),
                token));

            cleanRunning = false;
            btnCleanNow.Enabled = true;
            btnCleanStop.Enabled = false;
            btnCleanNow.Text = "BẮT ĐẦU LÀM SẠCH";

            string summary = $"Xong: {result.Succeeded} thành công · {result.Failed} lỗi · {result.Skipped} bỏ qua";
            lblCleanSummary.Text = summary;
            lblCleanSummary.ForeColor = result.Failed == 0 ? ClrMidGreen : ClrRed;
            barClean.Maximum = 100;
            barClean.Value = 100;

            CleanLog("=== HOÀN TẤT ===", CleanLogKind.Heading);
            CleanLog(summary, CleanLogKind.Heading);
            CleanLog($"Bản sao lưu / báo cáo: {opt.BackupRoot}", CleanLogKind.Info);
            if (result.MiAVInstalled)
                CleanLog("✓ Đã cài lại phần mềm MiAV — 4 service (MiAVWD / MiAVUpdate / MiAVProtect / Defense) đang hoạt động.",
                    CleanLogKind.Success);
            else if (opt.InstallMiAV)
                CleanLog("⚠ Chưa cài lại được MiAV. Máy sẽ không có giám sát EDR — cần cài thủ công SetupMiAV.exe.",
                    CleanLogKind.Warn);
            if (result.MiAVInternetUnsent > 0)
                CleanLog($"⚠ Còn {result.MiAVInternetUnsent} dòng 'Internet' CHƯA gửi — "
                       + "hãy kiểm tra lại sau khi bật lại service.", CleanLogKind.Warn);
            if (result.MiAVInternetRows > result.MiAVInternetUnsent)
                CleanLog("⚠ Có dòng 'Internet' đã gửi lên server FMS → cần đề nghị quản trị viên FMS xóa.",
                    CleanLogKind.Warn);

            if (opt.RunKvrt && opt.RebootAfterKvrt)
            {
                string extra = opt.InstallMiAV
                    ? "Phần mềm MiAV đã được cài lại.\n\n"
                    : "";
                DialogResult rb = MessageBox.Show(
                    extra + "Đã hoàn tất quét KVRT.\n\nKhởi động lại máy ngay (đếm ngược 60 giây)?\n" +
                    "Nếu không, hãy khởi động lại thủ công sau khi đóng phần mềm.",
                    "Khởi động lại máy",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Question);
                if (rb == DialogResult.Yes)
                {
                    PcCleaner.ScheduleReboot(60);
                    CleanLog("Đã lên lịch khởi động lại máy sau 60 giây.", CleanLogKind.Success);
                }
            }
        }

        private void BtnCleanStop_Click(object? sender, EventArgs e)
        {
            try
            {
                ctsClean?.Cancel();
                CleanLog("Đã yêu cầu dừng. Hạng mục đang chạy sẽ hoàn tất rồi mới dừng.", CleanLogKind.Warn);
            }
            catch { }
        }

        private void BeginInvokeSafe(Action action)
        {
            try
            {
                if (IsDisposed || Disposing) return;
                if (InvokeRequired) BeginInvoke(action);
                else action();
            }
            catch { }
        }

        private void CleanLog(string message, CleanLogKind kind)
        {
            if (txtCleanLog == null) return;
            string stamp = DateTime.Now.ToString("HH:mm:ss");
            Color color = kind switch
            {
                CleanLogKind.Success => Color.FromArgb(120, 235, 130),
                CleanLogKind.Warn => ClrLogGold,
                CleanLogKind.Error => ClrLogRed,
                CleanLogKind.Step => ClrLogBlue,
                CleanLogKind.Heading => ClrLogGold,
                _ => ClrLogText
            };
            string prefix = kind switch
            {
                CleanLogKind.Success => "[ OK ] ",
                CleanLogKind.Warn => "[CẢNH BÁO] ",
                CleanLogKind.Error => "[LỖI]  ",
                CleanLogKind.Step => "[...]  ",
                CleanLogKind.Heading => "== ",
                _ => "       "
            };
            if (kind == CleanLogKind.Heading)
            {
                txtCleanLog.SelectionStart = txtCleanLog.TextLength;
                txtCleanLog.SelectionLength = 0;
                txtCleanLog.SelectionColor = ClrLogGold;
                txtCleanLog.AppendText("=====================================================\n");
            }
            txtCleanLog.SelectionStart = txtCleanLog.TextLength;
            txtCleanLog.SelectionLength = 0;
            txtCleanLog.SelectionColor = Color.FromArgb(90, 130, 100);
            txtCleanLog.AppendText(stamp + "  ");
            txtCleanLog.SelectionColor = color;
            txtCleanLog.AppendText(prefix + message + "\n");
            txtCleanLog.SelectionStart = txtCleanLog.TextLength;
            txtCleanLog.ScrollToCaret();
        }

        // ==================================================================
        // HELPER TAO GIAO DIEN
        // ==================================================================

        private static Label MakeLabel(string text, int x, int y, Color? color = null)
        {
            return new Label
            {
                Text = text,
                Location = new Point(x, y),
                AutoSize = true,
                ForeColor = color ?? ClrText,
                Font = new Font("Segoe UI", 9f),
                BackColor = Color.Transparent,
                Margin = Padding.Empty
            };
        }

        private static TextBox MakeTextBox(string text, int x, int y, int width)
        {
            return new TextBox
            {
                Text = text,
                Location = new Point(x, y),
                Width = width,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Segoe UI", 9f)
            };
        }

        /// <summary>
        /// Tao nut phang mau quan doi.
        /// Luon dung AutoSize = false + TextAlign = MiddleCenter de chu
        /// hien thi can giua khi nut duoc Dock = Fill trong TableLayoutPanel
        /// (truong hop chu "bien mat" do nut bi keo gian cao khong dung nho chu).
        /// </summary>
        private static Button MakeButton(string text, int x, int y, int width, int height, Color back)
        {
            var b = new Button
            {
                Text = text,
                Location = new Point(x, y),
                Width = width,
                Height = height,
                BackColor = back,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                UseVisualStyleBackColor = false,
                ForeColor = Color.White,
                AutoSize = false,
                TextAlign = ContentAlignment.MiddleCenter,
                AutoEllipsis = false,
                Margin = Padding.Empty
            };
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = Color.FromArgb(20, 40, 28);
            return b;
        }

        // ==================================================================
        // LOG PANEL
        // ==================================================================

        private enum LogKind { Info, Success, Warn, Error, Step, Heading }

        private void Log(string message, LogKind kind = LogKind.Info)
        {
            if (txtLog == null) return;

            string stamp = DateTime.Now.ToString("HH:mm:ss");
            Color color = kind switch
            {
                LogKind.Success => Color.FromArgb(120, 235, 130),
                LogKind.Warn => ClrLogGold,
                LogKind.Error => ClrLogRed,
                LogKind.Step => ClrLogBlue,
                LogKind.Heading => ClrLogGold,
                _ => ClrLogText
            };

            string prefix = kind switch
            {
                LogKind.Success => "[ OK ] ",
                LogKind.Warn => "[CẢNH BÁO] ",
                LogKind.Error => "[LỖI]  ",
                LogKind.Step => "[...]  ",
                LogKind.Heading => "== ",
                _ => "       "
            };

            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.SelectionLength = 0;
            txtLog.SelectionColor = Color.FromArgb(90, 130, 100);
            txtLog.AppendText(stamp + "  ");
            txtLog.SelectionColor = color;
            if (kind == LogKind.Heading)
                txtLog.AppendText("=====================================================\n");
            txtLog.AppendText(prefix + message + "\n");
            txtLog.SelectionStart = txtLog.TextLength;
            txtLog.ScrollToCaret();
        }

        private void LogMultiline(string text, LogKind kind = LogKind.Info)
        {
            foreach (string line in text.Replace("\r\n", "\n").Split('\n'))
            {
                if (line.Trim().Length == 0) continue;
                Log(line.TrimEnd(), kind);
            }
        }

        // ==================================================================
        // PHAN USB AN TOAN 2.6
        // ==================================================================

        private void LoadUsbDrives()
        {
            if (cmbUsbDrives == null) return;
            cmbUsbDrives.Items.Clear();
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady && drive.DriveType == DriveType.Removable)
                {
                    string label = "";
                    try { label = drive.VolumeLabel; } catch { }
                    cmbUsbDrives.Items.Add(string.IsNullOrWhiteSpace(label)
                        ? drive.Name
                        : drive.Name + "  (" + label + ")");
                }
            }

            if (cmbUsbDrives.Items.Count > 0)
            {
                cmbUsbDrives.SelectedIndex = 0;
                UpdateUsbInfo();
            }
            else if (lblUsbInfo != null)
            {
                lblUsbInfo.Text = "Không tìm thấy ổ USB removable nào đang cắm.";
                lblUsbInfo.ForeColor = ClrRed;
            }
        }

        private string? GetSelectedUsbRoot()
        {
            if (cmbUsbDrives?.SelectedItem == null) return null;
            string s = cmbUsbDrives.SelectedItem.ToString();
            int idx = s.IndexOf('\\');
            return idx > 0 ? s.Substring(0, idx + 1) : null;
        }

        private void UpdateUsbInfo()
        {
            string? root = GetSelectedUsbRoot();
            if (root == null) return;

            try
            {
                var di = new DriveInfo(root);
                string fs = UsbFormatter.GetFileSystem(root);
                lblUsbInfo.Text = di.Name + " — " + fs + " — dung lượng trống "
                    + (di.AvailableFreeSpace / 1024.0 / 1024.0).ToString("F0") + " MB — "
                    + (fs == "NTFS" ? "đủ điều kiện tạo USB an toàn"
                                    : "cần định dạng NTFS (sẽ xoá dữ liệu)");
                lblUsbInfo.ForeColor = fs == "NTFS" ? ClrDarkGreen : ClrDarkGold;
            }
            catch (Exception ex)
            {
                lblUsbInfo.Text = "Không đọc được thông tin ổ: " + ex.Message;
                lblUsbInfo.ForeColor = ClrRed;
            }
        }

        private async void BtnMakeUsbSafe_Click(object? sender, EventArgs e)
        {
            string? root = GetSelectedUsbRoot();
            if (root == null)
            {
                Log("Chưa có ổ USB nào. Vui lòng cắm USB rồi bấm \"Làm mới\".", LogKind.Error);
                return;
            }

            string version = txtVersion.Text.Trim();
            string vendor = txtVendor.Text.Trim();
            string seed = txtSeed.Text.Trim();

            if (version.Length == 0 || vendor.Length == 0 || seed.Length == 0)
            {
                Log("Phiên bản, hãng SX và seed không được để trống.", LogKind.Error);
                return;
            }

            string fs = UsbFormatter.GetFileSystem(root);
            bool needFormat = !fs.Equals("NTFS", StringComparison.OrdinalIgnoreCase);

            Log("=====================================================", LogKind.Heading);
            Log("Bắt đầu tạo USB An Toàn 2.6 trên ổ " + root, LogKind.Heading);
            Log("Định dạng hiện tại: " + fs + (needFormat ? "  →  cần định dạng NTFS" : "  →  giữ nguyên"));
            Log("Tham số: version=\"" + version + "\" vendor=\"" + vendor + "\" seed=\"" + seed + "\"");

            if (needFormat)
            {
                Log("Định dạng NTFS sẽ XOÁ TOÀN BỘ DỮ LIỆU trên ổ.", LogKind.Warn);
                Log("Vui lòng sao lưu dữ liệu trước khi tiếp tục.", LogKind.Warn);

                var res = MessageBox.Show(
                    "ĐỊNH DẠNG LẠI Ổ ĐỂ NTFS — SẼ XOÁ TOÀN BỘ DỮ LIỆU\n\n" +
                    "Ổ đích   : " + root + "\n" +
                    "Nhãn cũ  : " + SafeLabel(root) + "\n" +
                    "Định dạng: " + fs + "  →  NTFS\n\n" +
                    "LÝ DO: chỉ NTFS mới hỗ trợ DACL. MiAV kiểm tra quyền ghi bằng AccessCheck\n" +
                    "trên <ổ>:\\ — nếu ổ còn FAT32/exFAT thì không gắn được ACL, người dùng vẫn\n" +
                    "ghi được, MiAV sẽ phân loại \"Khong an toan\" và KHOÁ ổ ở tầng kernel.\n\n" +
                    "TOÀN BỘ DỮ LIỆU SẼ BỊ XOÁ VÀ KHÔNG KHÔI PHỤC ĐƯỢC.\n" +
                    "Hãy COPY SANG NƠI KHÁC TRƯỚC KHI TIẾP TỤC.\n\n" +
                    "Tiếp tục?",
                    "Xác nhận định dạng NTFS (mất dữ liệu)",
                    MessageBoxButtons.YesNo, MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2);
                if (res != DialogResult.Yes)
                {
                    Log("Người dùng hủy thao tác.", LogKind.Warn);
                    return;
                }
                Log("Người dùng xác nhận định dạng NTFS.", LogKind.Step);
            }

            btnMakeUsbSafe.Enabled = false;
            btnMakeUsbSafe.Text = needFormat ? "ĐANG ĐỊNH DẠNG NTFS..." : "ĐANG TẠO...";
            lblUsbInfo.Text = "Đang xử lý, vui lòng đợi...";
            lblUsbInfo.ForeColor = ClrDarkGold;

            string report = "";
            try
            {
                report = await Task.Run(() =>
                    UsbSafeService.MakeSafeUsb(root, version, vendor, seed, needFormat));
            }
            catch (Exception ex)
            {
                report = "LỖI: " + ex.Message;
            }

            btnMakeUsbSafe.Enabled = true;
            btnMakeUsbSafe.Text = "TẠO USB AN TOÀN 2.6";

            LogMultiline(report,
                report.Contains("KHONG THE") || report.StartsWith("LOI") ? LogKind.Error : LogKind.Success);

            UpdateUsbInfo();
        }

        private static string SafeLabel(string root)
        {
            try { return new DriveInfo(root).VolumeLabel; }
            catch { return "(không đọc được)"; }
        }

        private async void BtnCheckUsbSafe_Click(object? sender, EventArgs e)
        {
            string? root = GetSelectedUsbRoot();
            if (root == null)
            {
                Log("Chưa có ổ USB nào.", LogKind.Error);
                return;
            }

            btnCheckUsbSafe.Enabled = false;
            btnCheckUsbSafe.Text = "ĐANG KIỂM TRA...";

            string report = await Task.Run(() => UsbSafeService.InspectUsbSafe(root));

            btnCheckUsbSafe.Enabled = true;
            btnCheckUsbSafe.Text = "Kiểm tra trạng thái";

            Log("=====================================================", LogKind.Heading);
            Log("Kiểm tra trạng thái USB An Toàn trên " + root, LogKind.Heading);
            LogMultiline(report, report.Contains("HOP LE") ? LogKind.Success : LogKind.Warn);
        }

        private async void BtnUnlockUsb_Click(object? sender, EventArgs e)
        {
            string? root = GetSelectedUsbRoot();
            if (root == null)
            {
                Log("Chưa có ổ USB nào.", LogKind.Error);
                return;
            }

            Log("=====================================================", LogKind.Heading);
            Log("Mở khóa quyền ghi trên " + root, LogKind.Heading);
            Log("Lưu ý: sau khi mở khóa, MiAV sẽ phân loại ổ này là \"Khong an toan\" và KHOÁ ổ ở tầng kernel.",
                LogKind.Warn);

            btnUnlockUsb.Enabled = false;
            btnUnlockUsb.Text = "ĐANG MỞ KHÓA...";

            string report = "";
            try
            {
                report = await Task.Run(() =>
                {
                    UsbSafeMaker.RestoreWriteAccess(root);
                    foreach (string f in new[] { UsbSafeMaker.FileInf, UsbSafeMaker.FileMtext, UsbSafeMaker.FileAutorun, UsbSafeMaker.FileIco })
                    {
                        try
                        {
                            string p = Path.Combine(root, f);
                            if (File.Exists(p))
                                File.SetAttributes(p, File.GetAttributes(p) & ~(FileAttributes.Hidden | FileAttributes.System));
                        }
                        catch { }
                    }
                    return "Đã gỡ khóa quyền ghi trên " + root + ". MiAV sẽ coi ổ này là \"Khong an toan\".";
                });
            }
            catch (Exception ex)
            {
                report = "LỖI: " + ex.Message;
            }

            btnUnlockUsb.Enabled = true;
            btnUnlockUsb.Text = "Mở khóa quyền ghi";
            LogMultiline(report, report.StartsWith("LOI") ? LogKind.Error : LogKind.Success);
            UpdateUsbInfo();
        }

        // ==================================================================
        // CAC HAM XU LY LOGIC CON LAI
        // ==================================================================

        private async void BtnClearLogs_Click(object? sender, EventArgs e)
        {
            var result = MessageBox.Show("Đồng chí có chắc chắn muốn xóa toàn bộ lịch sử hệ thống (Event Viewer) không?", "Xác nhận", MessageBoxButtons.YesNo, MessageBoxIcon.Question);
            if (result == DialogResult.Yes)
            {
                btnClearLogs.Enabled = false;
                btnClearLogs.Text = "Đang dọn dẹp...";

                await Task.Run(() =>
                {
                    try
                    {
                        EventLog[] eventLogs = EventLog.GetEventLogs();
                        foreach (EventLog log in eventLogs)
                        {
                            log.Clear();
                        }
                    }
                    catch (Exception)
                    {
                        ExecuteCommand("cmd.exe", "/c for /F \"tokens=*\" %1 in ('wevtutil.exe el') DO wevtutil.exe cl \"%1\"");
                    }
                });

                btnClearLogs.Enabled = true;
                btnClearLogs.Text = "Xóa nhật ký Event Viewer";
                Log("Đã xóa toàn bộ nhật ký hệ thống (Event Viewer).", LogKind.Success);
            }
        }

        private void LoadDrives()
        {
            if (cmbDrives == null) return;
            cmbDrives.Items.Clear();
            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                if (drive.IsReady)
                    cmbDrives.Items.Add(drive.Name + " (" +
                        (drive.DriveType == DriveType.Removable ? "USB" : "Ổ cứng") + ")");
            }
            if (cmbDrives.Items.Count > 0) cmbDrives.SelectedIndex = 0;
        }

        private async void BtnUncoverFiles_Click(object? sender, EventArgs e)
        {
            if (cmbDrives?.SelectedItem == null) return;
            string driveLetter = cmbDrives.SelectedItem.ToString().Substring(0, 3);
            btnUncoverFiles.Enabled = false;
            btnUncoverFiles.Text = "Đang xử lý...";

            await Task.Run(() =>
            {
                ExecuteCommand("cmd.exe", "/c attrib -s -h -r \"" + driveLetter + "*.*\" /s /d");
            });

            btnUncoverFiles.Enabled = true;
            btnUncoverFiles.Text = "Hiện File/Folder ẩn";
            Log("Đã khôi phục file ẩn trên ổ " + driveLetter + ".", LogKind.Success);
        }

        private void BtnChangeIP_Click(object? sender, EventArgs e)
        {
            try
            {
                ExecuteCommand("netsh", "interface ip set address \"" + txtAdapter.Text + "\" static "
                    + txtIP.Text + " " + txtSubnet.Text + " " + txtGateway.Text);
                if (!string.IsNullOrWhiteSpace(txtDNS.Text))
                    ExecuteCommand("netsh", "interface ip set dns \"" + txtAdapter.Text + "\" static " + txtDNS.Text);
                Log("Đã cấu hình IP/DNS cho card \"" + txtAdapter.Text + "\": "
                    + txtIP.Text + "/" + txtSubnet.Text + ", GW " + txtGateway.Text
                    + ", DNS " + txtDNS.Text, LogKind.Success);
            }
            catch (Exception ex) { Log("Lỗi cấu hình IP: " + ex.Message, LogKind.Error); }
        }

        private void BtnRunKVRT_Click(object? sender, EventArgs e)
        {
            try
            {
                // KVRT.exe dat rieng trong thu muc "tools/" canh ban phan phoi
                // (khong embed trong exe de giam kich thuoc goi).
                string toolsDir = Path.Combine(AppContext.BaseDirectory, "tools");
                string kvrtPath = Path.Combine(toolsDir, "KVRT.exe");

                if (!File.Exists(kvrtPath))
                {
                    // Thu ban sao trong thu muc tam (neu nguoi dung da copy san)
                    kvrtPath = Path.Combine(Path.GetTempPath(), "KVRT_Offline.exe");
                    if (!File.Exists(kvrtPath))
                    {
                        MessageBox.Show(
                            "Khong tim thay file KVRT.exe.\n\n" +
                            "File nay nam trong thu muc \"tools\\\" canh ben Danny.exe.\n" +
                            "Vui long copy day du thu muc tools sang may may.",
                            "Thieu file", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                        return;
                    }
                }

                Process.Start(new ProcessStartInfo(kvrtPath) { UseShellExecute = true });
                Log("Đã khởi chạy Kaspersky (KVRT).", LogKind.Success);
            }
            catch (Exception ex) { Log("Lỗi chạy KVRT: " + ex.Message, LogKind.Error); }
        }

        private void ExecuteCommand(string cmd, string args)
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = cmd,
                Arguments = args,
                CreateNoWindow = true,
                WindowStyle = ProcessWindowStyle.Hidden,
                UseShellExecute = false
            })?.WaitForExit();
        }
    }
}
