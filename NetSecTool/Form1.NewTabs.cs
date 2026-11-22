using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetSecTool
{
    /// <summary>
    /// Các tab mới bổ sung trong Danny ver5.7.
    ///
    /// <para>Gộp vào một file riêng để Form1.cs (đã ~3.400 dòng) không bị phình
    /// thêm — cùng namespace, cùng partial class nên các helper (MakeButton,
    /// MakeLabel, BeginInvokeSafe…) dùng chung được.</para>
    ///
    /// <para>Bao gồm:
    ///   • Tab "HIỆN FILE/FOLDER ẨN"   (Ver5.7 Phần 2.2)
    ///   • Tab "SAO LƯU MÁY TÍNH"       (Ver5.7 Phần 2.4)
    ///   • Tab "KIỂM TRA AN TOÀN TT"   (Ver5.7 Phần 2.5 — Forensic DFIR)</para>
    /// </summary>
    public partial class Form1
    {
        // ==================================================================
        // TAB: HIEN FILE/FOLDER AN
        // ==================================================================
        private ComboBox cmbUncoverTarget = null!;
        private TextBox txtUncoverPath = null!;
        private CheckBox chkUncoverRecursive = null!, chkUncoverDryRun = null!;
        private Button btnUncoverScan = null!, btnUncoverStop = null!;
        private ProgressBar barUncover = null!;
        private Label lblUncoverSummary = null!;
        private ListView lstUncover = null!;
        private CancellationTokenSource? ctsUncover;

        private void BuildUncoverTab(TabPage tab)
        {
            // 5 hang: dieu khien / tom tat / progress / bang ket qua / nut
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 168));  // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 1 - tom tat
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - bang
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));   // 4 - nut
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildUncoverControlPanel(), 0, 0);

            lblUncoverSummary = new Label
            {
                Text = "Chưa quét. Chọn ổ đĩa hoặc nhập đường dẫn thư mục rồi bấm \"Xem trước\".",
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(240, 243, 238),
                ForeColor = ClrMuted,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(12, 0, 0, 0),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 2, 0, 2)
            };
            layout.Controls.Add(lblUncoverSummary, 0, 1);

            barUncover = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barUncover, 0, 2);

            lstUncover = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                MultiSelect = true,
                BackColor = Color.White,
                Font = new Font("Consolas", 9f),
                Margin = Padding.Empty
            };
            lstUncover.Columns.Add("Loại", 70);
            lstUncover.Columns.Add("Đường dẫn", 620);
            lstUncover.Columns.Add("Kích thước", 100);
            lstUncover.Columns.Add("Sửa lần cuối", 140);
            lstUncover.Columns.Add("Thuộc tính cũ", 160);
            lstUncover.Columns.Add("Kết quả", 130);
            layout.Controls.Add(lstUncover, 0, 3);

            var pnlBtns = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 1,
                Margin = Padding.Empty,
                Padding = new Padding(0, 6, 0, 0)
            };
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 180));
            pnlBtns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnUncoverScan = MakeButton("XEM TRƯỚC", 0, 0, 240, 38, ClrMidGreen);
            btnUncoverScan.Click += (s, e) => RunUncover(dryRun: true);
            btnUncoverScan.Dock = DockStyle.Fill;
            btnUncoverScan.Margin = new Padding(0, 0, 4, 0);
            pnlBtns.Controls.Add(btnUncoverScan, 0, 0);

            btnUncoverStop = MakeButton("KHÔI PHỤC", 0, 0, 240, 38, ClrRed);
            btnUncoverStop.Click += (s, e) => RunUncover(dryRun: false);
            btnUncoverStop.Dock = DockStyle.Fill;
            btnUncoverStop.Margin = new Padding(4, 0, 4, 0);
            pnlBtns.Controls.Add(btnUncoverStop, 1, 0);

            var btnRefreshUnc = MakeButton("Làm mới danh sách", 0, 0, 200, 38, ClrDarkGold);
            btnRefreshUnc.Click += (s, e) => LoadUncoverTargets();
            btnRefreshUnc.Dock = DockStyle.Fill;
            btnRefreshUnc.Margin = new Padding(4, 0, 4, 0);
            pnlBtns.Controls.Add(btnRefreshUnc, 2, 0);

            var btnHelpUnc = MakeButton("Hướng dẫn", 0, 0, 170, 38, ClrDarkGreen);
            btnHelpUnc.Click += (s, e) => MessageBox.Show(
                "HIỆN FILE/FOLDER ẨN\n\n" +
                "Tính năng này gỡ thuộc tính ẩn (Hidden), System và ReadOnly\n" +
                "cho các tệp/thư mục trên ổ đĩa hoặc trong một thư mục chỉ định.\n\n" +
                "• XEM TRƯỚC  : chỉ liệt kê, KHÔNG thay đổi gì (an toàn để xem trước).\n" +
                "• KHÔI PHỤC : gỡ cờ ẩn thật (tương đương attrib -h -s).\n\n" +
                "Lưu ý: quét đệ quy trên ổ hệ thống có thể mất vài phút.\n" +
                "Các thư mục hệ thống được bảo vệ vẫn có thể không gỡ được —\n" +
                "phần mềm sẽ báo rõ từng trường hợp trong danh sách.",
                "Hướng dẫn", MessageBoxButtons.OK, MessageBoxIcon.Information);
            btnHelpUnc.Dock = DockStyle.Fill;
            btnHelpUnc.Margin = new Padding(4, 0, 0, 0);
            pnlBtns.Controls.Add(btnHelpUnc, 3, 0);

            layout.Controls.Add(pnlBtns, 0, 4);

            LoadUncoverTargets();
        }

        /// <summary>Panel điều khiển tab Hiện File/Folder ẩn.</summary>
        private Control BuildUncoverControlPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 4,
                BackColor = ClrPanel,
                Padding = new Padding(12, 8, 12, 8),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 90));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 250));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));   // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 1 - o dia
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 2 - duong dan
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - tuy chon

            var lblTitle = new Label
            {
                Text = "KHÔI PHỤC FILE / THƯ MỤC ẨN",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 4);

            // --- Hang 1: chon o dia ---
            tbl.Controls.Add(MakeLabel("Ổ đĩa:", 0, 0), 0, 1);
            cmbUncoverTarget = new ComboBox
            {
                Dock = DockStyle.Fill,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Margin = new Padding(0, 3, 8, 3)
            };
            cmbUncoverTarget.SelectedIndexChanged += (s, e) =>
            {
                if (cmbUncoverTarget.SelectedItem is string sel && sel.Length >= 3 && txtUncoverPath != null)
                    txtUncoverPath.Text = sel.Substring(0, 3);
            };
            tbl.Controls.Add(cmbUncoverTarget, 1, 1);
            tbl.SetColumnSpan(cmbUncoverTarget, 3);

            // --- Hang 2: duong dan thu muc ---
            tbl.Controls.Add(MakeLabel("Thư mục:", 0, 0), 0, 2);
            txtUncoverPath = new TextBox
            {
                Text = "C:\\",
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9.5f),
                Margin = new Padding(0, 3, 8, 3)
            };
            tbl.Controls.Add(txtUncoverPath, 1, 2);
            tbl.SetColumnSpan(txtUncoverPath, 3);

            // --- Hang 3: tuy chon ---
            chkUncoverRecursive = MakeCheck("Quét đệ quy (bao gồm thư mục con)", true);
            chkUncoverDryRun = MakeCheck("Chỉ xem trước — không thay đổi (DRY-RUN)", false);

            var pnlOpts = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 20));
            pnlOpts.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            pnlOpts.Controls.Add(chkUncoverRecursive, 0, 0);
            pnlOpts.Controls.Add(chkUncoverDryRun, 1, 0);
            tbl.Controls.Add(pnlOpts, 1, 3);
            tbl.SetColumnSpan(pnlOpts, 3);

            return tbl;
        }

        private void LoadUncoverTargets()
        {
            if (cmbUncoverTarget == null) return;
            cmbUncoverTarget.Items.Clear();
            foreach (DriveInfo d in DriveInfo.GetDrives())
            {
                if (!d.IsReady) continue;
                string label = "";
                try { label = d.VolumeLabel; } catch { }
                cmbUncoverTarget.Items.Add(string.IsNullOrWhiteSpace(label)
                    ? d.Name
                    : d.Name + "  (" + label + ")");
            }
            if (cmbUncoverTarget.Items.Count > 0) cmbUncoverTarget.SelectedIndex = 0;
        }

        private async void RunUncover(bool dryRun)
        {
            string root = (txtUncoverPath?.Text ?? "").Trim();
            if (root.Length == 0)
            {
                MessageBox.Show("Hãy nhập đường dẫn thư mục cần quét.", "Thiếu đường dẫn",
                    MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }
            if (!root.EndsWith("\\") && !root.EndsWith("/")) root += "\\";

            if (!dryRun)
            {
                var r = MessageBox.Show(
                    "Xác nhận KHÔI PHỤC (gỡ cờ ẩn) cho toàn bộ file/thư mục trong:\n\n" +
                    root + "\n\n" +
                    "Thao tác này sẽ thay đổi thuộc tính của các tệp bị đánh dấu ẩn.\n" +
                    "Tiếp tục?",
                    "Xác nhận khôi phục", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                    MessageBoxDefaultButton.Button2);
                if (r != DialogResult.Yes) return;
            }

            ctsUncover = new CancellationTokenSource();
            var ct = ctsUncover.Token;
            bool recursive = chkUncoverRecursive.Checked;
            bool dry = dryRun || chkUncoverDryRun.Checked;

            btnUncoverScan.Enabled = false;
            btnUncoverStop.Enabled = false;
            lstUncover.Items.Clear();
            barUncover.Style = ProgressBarStyle.Marquee;
            barUncover.MarqueeAnimationSpeed = 30;
            lblUncoverSummary.Text = dry ? "Đang XEM TRƯỚC..." : "Đang KHÔI PHỤC...";
            lblUncoverSummary.ForeColor = ClrMidGreen;

            UncoverResult res = await Task.Run(
                () => UncoverFiles.Scan(root, recursive, dry,
                    (n, p) => BeginInvokeSafe(() =>
                    {
                        barUncover.Style = ProgressBarStyle.Continuous;
                        barUncover.Maximum = Math.Max(1, n);
                        barUncover.Value = Math.Min(n, barUncover.Maximum);
                    }),
                    ct),
                ct);

            barUncover.Style = ProgressBarStyle.Continuous;
            btnUncoverScan.Enabled = true;
            btnUncoverStop.Enabled = true;

            // Do duong dan -> cot "Ket qua" co the bi tran truot khi scroll
            foreach (UncoverItem it in res.Items)
            {
                var li = new ListViewItem(it.IsDirectory ? "Thư mục" : "Tệp");
                li.SubItems.Add(it.FullPath);
                li.SubItems.Add(it.IsDirectory ? "" : FormatBytes(it.SizeBytes));
                li.SubItems.Add(it.Modified == DateTime.MinValue ? "" : it.Modified.ToString("yyyy-MM-dd HH:mm"));
                li.SubItems.Add(it.OriginalAttributes);
                li.SubItems.Add(it.Restored ? "Đã khôi phục" : (it.Note ?? "Bỏ qua"));
                li.ForeColor = it.Restored ? ClrDarkGreen : ClrDarkGold;
                lstUncover.Items.Add(li);
            }

            lblUncoverSummary.Text = dry
                ? $"Xem trước: {res.Items.Count} mục ẩn · {res.BytesScanned / 1024.0 / 1024.0:F1} MB · {res.Elapsed.TotalSeconds:F1}s"
                : $"Hoàn tất: {res.Restored} khôi phục · {res.Failed} lỗi · {res.Items.Count} mục · {res.Elapsed.TotalSeconds:F1}s";
            lblUncoverSummary.ForeColor = res.Failed == 0 ? ClrMidGreen : ClrRed;
            barUncover.Value = barUncover.Maximum;

            if (res.Errors.Count > 0)
                MessageBox.Show(
                    $"Có {res.Errors.Count} mục không xử lý được (thường là tệp hệ thống được bảo vệ).\n\n" +
                    string.Join("\n", res.Errors.Take(8)) +
                    (res.Errors.Count > 8 ? $"\n... và {res.Errors.Count - 8} mục khác." : ""),
                    "Một số mục không xử lý được", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private static string FormatBytes(long b)
        {
            if (b < 1024) return b + " B";
            if (b < 1024 * 1024) return (b / 1024.0).ToString("F1") + " KB";
            if (b < 1024L * 1024 * 1024) return (b / 1024.0 / 1024).ToString("F1") + " MB";
            return (b / 1024.0 / 1024 / 1024).ToString("F2") + " GB";
        }
    }
}
