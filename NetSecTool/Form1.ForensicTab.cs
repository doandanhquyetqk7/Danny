using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using NetSecTool.Forensic;

namespace NetSecTool
{
    /// <summary>Tab "KIỂM TRA AN TOÀN THÔNG TIN" — Ver5.7 Phần 2.5 (Forensic DFIR).</summary>
    public partial class Form1
    {
        private Button btnForensicRun = null!, btnForensicCancel = null!, btnForensicOpen = null!,
                        btnForensicExportRules = null!;
        private ProgressBar barForensic = null!;
        private Label lblForensicScore = null!, lblForensicVerdict = null!;
        private TreeView treeForensic = null!;
        private RichTextBox txtForensicLog = null!;
        private TextBox txtForensicOutDir = null!;
        private CheckBox chkForensicSkipHash = null!;
        private CancellationTokenSource? ctsForensic;
        private bool forensicRunning;

        private void BuildForensicTab(TabPage tab)
        {
            // 5 hang: dieu khien / diem + ket luan / progress / cay ket qua / log
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 130));  // 0 - dieu khien
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 58));   // 1 - diem + ket luan
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - cay ket qua
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 140));  // 4 - log
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildForensicControlPanel(), 0, 0);

            // --- Diem + ket luan ---
            var pnlScore = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = Padding.Empty,
                Padding = new Padding(0, 2, 0, 2),
                BackColor = Color.FromArgb(240, 243, 238)
            };
            pnlScore.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
            pnlScore.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pnlScore.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            lblForensicScore = new Label
            {
                Text = "--/100",
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 22f, FontStyle.Bold),
                ForeColor = ClrMuted,
                TextAlign = ContentAlignment.MiddleCenter,
                BackColor = Color.FromArgb(240, 243, 238)
            };
            pnlScore.Controls.Add(lblForensicScore, 0, 0);

            lblForensicVerdict = new Label
            {
                Text = "Chưa chạy kiểm tra. Bấm \"BẮT ĐẦU KIỂM TRA\" để thu thập và phân tích chứng cứ.",
                Dock = DockStyle.Fill,
                ForeColor = ClrMuted,
                Font = new Font("Segoe UI", 10f),
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                BackColor = Color.FromArgb(240, 243, 238),
                Padding = new Padding(12, 0, 12, 0)
            };
            pnlScore.Controls.Add(lblForensicVerdict, 1, 0);
            layout.Controls.Add(pnlScore, 0, 1);

            barForensic = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barForensic, 0, 2);

            // --- Cay ket qua ---
            treeForensic = new TreeView
            {
                Dock = DockStyle.Fill,
                Font = new Font("Segoe UI", 9f),
                BorderStyle = BorderStyle.FixedSingle,
                HideSelection = false,
                Margin = Padding.Empty
            };
            layout.Controls.Add(treeForensic, 0, 3);

            // --- Log ---
            txtForensicLog = new RichTextBox
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
            layout.Controls.Add(txtForensicLog, 0, 4);
        }

        private Control BuildForensicControlPanel()
        {
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 4,
                BackColor = ClrPanel,
                Padding = new Padding(12, 6, 12, 6),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 230));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));   // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 1 - thu muc dich
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 2 - tuy chon
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - nut

            var lblTitle = new Label
            {
                Text = "KIỂM TRA AN TOÀN THÔNG TIN — PHÁP Y SỐ (DFIR)",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 4);

            // --- Thu muc dich ---
            tbl.Controls.Add(MakeLabel("Thư mục lưu:", 0, 0), 0, 1);

            txtForensicOutDir = new TextBox
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5f),
                Margin = new Padding(0, 3, 6, 3),
                Text = Path.Combine(AppContext.BaseDirectory, "Bao-cao")
            };
            tbl.Controls.Add(txtForensicOutDir, 1, 1);
            tbl.SetColumnSpan(txtForensicOutDir, 2);

            var btnBrowseF = MakeButton("Chọn thư mục...", 0, 0, 220, 25, ClrDarkGold);
            btnBrowseF.Click += (s, e) =>
            {
                using var dlg = new FolderBrowserDialog
                {
                    Description = "Chọn thư mục lưu gói chứng cứ",
                    SelectedPath = txtForensicOutDir.Text
                };
                if (dlg.ShowDialog(this) == DialogResult.OK)
                    txtForensicOutDir.Text = dlg.SelectedPath;
            };
            btnBrowseF.Dock = DockStyle.Fill;
            btnBrowseF.Margin = new Padding(0, 3, 0, 3);
            tbl.Controls.Add(btnBrowseF, 3, 1);

            // --- Tu chon ---
            chkForensicSkipHash = MakeCheck("Bỏ qua băm SHA-256 file lớn (nhanh hơn)", false);

            var pnlOpts = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 2,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
            pnlOpts.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            pnlOpts.Controls.Add(chkForensicSkipHash, 0, 0);

            var lblMode = new Label
            {
                Text = "Chế độ: CHỈ ĐỌC — không sửa/xóa dữ liệu trên máy.",
                ForeColor = ClrDarkGreen,
                Font = new Font("Segoe UI", 8.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            pnlOpts.Controls.Add(lblMode, 1, 0);
            tbl.Controls.Add(pnlOpts, 1, 2);
            tbl.SetColumnSpan(pnlOpts, 3);

            // --- Nut ---
            var pnlBtns = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 240));
            pnlBtns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnForensicRun = MakeButton("BẮT ĐẦU KIỂM TRA", 0, 0, 250, 40, ClrRed);
            btnForensicRun.Click += (s, e) => RunForensic();
            btnForensicRun.Dock = DockStyle.Fill;
            btnForensicRun.Margin = new Padding(0, 4, 4, 0);
            pnlBtns.Controls.Add(btnForensicRun, 0, 0);

            btnForensicCancel = MakeButton("HỦY", 0, 0, 150, 40, ClrDarkGold);
            btnForensicCancel.Click += (s, e) =>
            {
                try { ctsForensic?.Cancel(); } catch { }
            };
            btnForensicCancel.Dock = DockStyle.Fill;
            btnForensicCancel.Enabled = false;
            btnForensicCancel.Margin = new Padding(4, 4, 4, 0);
            pnlBtns.Controls.Add(btnForensicCancel, 1, 0);

            btnForensicOpen = MakeButton("Mở gói chứng cứ", 0, 0, 200, 40, ClrMidGreen);
            btnForensicOpen.Click += (s, e) =>
            {
                try
                {
                    string dir = (txtForensicOutDir?.Text ?? "").Trim();
                    if (dir.Length == 0) dir = Path.Combine(AppContext.BaseDirectory, "Bao-cao");
                    if (!Directory.Exists(dir)) { MessageBox.Show("Chưa có thư mục báo cáo.", "Chưa có dữ liệu"); return; }
                    Process.Start(new ProcessStartInfo(dir) { UseShellExecute = true });
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Không mở được: " + ex.Message, "Lỗi",
                        MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            btnForensicOpen.Dock = DockStyle.Fill;
            btnForensicOpen.Margin = new Padding(4, 4, 4, 0);
            pnlBtns.Controls.Add(btnForensicOpen, 2, 0);

            btnForensicExportRules = MakeButton("Xuất bộ quy tắc mặc định", 0, 0, 230, 40, ClrDarkGreen);
            btnForensicExportRules.Click += (s, e) =>
            {
                try
                {
                    string p = ForensicEngine.WriteDefaultRulesFile();
                    ForensicLog("Đã xuất bộ quy tắc mặc định: " + p, ForensicLogKind.Success);
                    MessageBox.Show(
                        "Đã tạo file quy tắc:\n" + p + "\n\n" +
                        "Sửa file này để thêm/bỏ quy tắc riêng của đơn vị.\n" +
                        "Phần mềm sẽ tự nạp lại file này ở lần kiểm tra kế tiếp.",
                        "Xuất quy tắc", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Lỗi: " + ex.Message, "Lỗi", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };
            btnForensicExportRules.Dock = DockStyle.Fill;
            btnForensicExportRules.Margin = new Padding(4, 4, 0, 0);
            pnlBtns.Controls.Add(btnForensicExportRules, 3, 0);

            tbl.Controls.Add(pnlBtns, 0, 3);
            tbl.SetColumnSpan(pnlBtns, 4);

            return tbl;
        }

        private async void RunForensic()
        {
            if (forensicRunning) return;

            var r = MessageBox.Show(
                "KIỂM TRA AN TOÀN THÔNG TIN (Pháp y số)\n\n" +
                "Chương trình sẽ:\n" +
                "• Thu thập chứng cứ ở chế độ CHỈ ĐỌC (không sửa/xóa gì trên máy).\n" +
                "• Băm SHA-256 toàn bộ artifact thu thập được.\n" +
                "• Phân tích theo bộ quy tắc (Internet trái phép, lộ lọt tài liệu, anti-forensics).\n" +
                "• Dựng dòng thời gian & xuất báo cáo HTML/Markdown/CSV/JSON + manifest.sha256.\n\n" +
                "Thời gian ước tính: 1–5 phút tùy ổ đĩa.\n\n" +
                "Tiếp tục?",
                "Xác nhận kiểm tra", MessageBoxButtons.YesNo, MessageBoxIcon.Question,
                MessageBoxDefaultButton.Button1);
            if (r != DialogResult.Yes) return;

            var opt = new ForensicOptions
            {
                OutputDirectory = (txtForensicOutDir?.Text ?? "").Trim(),
                SkipLargeFileHashing = chkForensicSkipHash.Checked
            };

            forensicRunning = true;
            ctsForensic = new CancellationTokenSource();
            var ct = ctsForensic.Token;

            btnForensicRun.Enabled = false;
            btnForensicCancel.Enabled = true;
            treeForensic.Nodes.Clear();
            txtForensicLog.Clear();
            barForensic.Style = ProgressBarStyle.Marquee;
            barForensic.MarqueeAnimationSpeed = 30;
            lblForensicScore.Text = "...";
            lblForensicScore.ForeColor = ClrMuted;
            lblForensicVerdict.Text = "Đang thu thập chứng cứ...";
            lblForensicVerdict.ForeColor = ClrDarkGold;

            EvidenceBundle bundle = await Task.Run(
                () => ForensicEngine.RunAsync(opt,
                    msg => BeginInvokeSafe(() => ForensicLog(msg, ForensicLogKind.Info)),
                    new Progress<int>(p => BeginInvokeSafe(() =>
                    {
                        barForensic.Style = ProgressBarStyle.Continuous;
                        barForensic.Value = Math.Min(p, barForensic.Maximum);
                    })),
                    ct),
                ct);

            forensicRunning = false;
            btnForensicRun.Enabled = true;
            btnForensicCancel.Enabled = false;
            barForensic.Style = ProgressBarStyle.Continuous;
            barForensic.Value = barForensic.Maximum;

            // --- Hien thi ket qua ---
            lblForensicScore.Text = bundle.TotalScore + "/100";
            lblForensicScore.ForeColor = bundle.TotalScore >= 60 ? ClrRed
                                     : bundle.TotalScore >= 30 ? ClrDarkGold : ClrDarkGreen;
            lblForensicVerdict.Text = bundle.Verdict;
            lblForensicVerdict.ForeColor = bundle.TotalScore >= 60 ? ClrRed : ClrDarkGreen;

            BuildForensicTree(bundle);

            ForensicLog("=== HOÀN TẤT ===", ForensicLogKind.Heading);
            ForensicLog($"Điểm nghi ngờ: {bundle.TotalScore}/100", ForensicLogKind.Heading);
            ForensicLog(bundle.Verdict, ForensicLogKind.Heading);
            ForensicLog($"Gói chứng cứ: {bundle.OutputDirectory}", ForensicLogKind.Success);

            MessageBox.Show(
                bundle.Verdict + "\n\n" +
                $"Điểm nghi ngờ: {bundle.TotalScore}/100\n" +
                $"Phát hiện: {bundle.Findings.Count} " +
                $"(CRITICAL {bundle.Findings.Count(f => f.Severity == Severity.Critical)}, " +
                $"HIGH {bundle.Findings.Count(f => f.Severity == Severity.High)})\n" +
                $"Artifact: {bundle.Artifacts.Count}\n\n" +
                "Gói chứng cứ đã lưu tại:\n" + bundle.OutputDirectory,
                "Kết quả kiểm tra",
                MessageBoxButtons.OK,
                bundle.TotalScore >= 60 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
        }

        private void BuildForensicTree(EvidenceBundle bundle)
        {
            treeForensic.BeginUpdate();
            try
            {
                // --- Phat hien ---
                var nodeFind = new TreeNode("PHÁT HIỆN (" + bundle.Findings.Count + ")");
                foreach (var group in bundle.Findings
                    .GroupBy(f => f.Severity)
                    .OrderByDescending(g => (int)g.Key))
                {
                    var gn = new TreeNode($"{group.Key} ({group.Count()})");
                    foreach (Finding f in group)
                    {
                        var fn = new TreeNode($"[{f.RuleId}] {f.Title}");
                        fn.Tag = f;
                        fn.ForeColor = group.Key switch
                        {
                            Severity.Critical => ClrRed,
                            Severity.High => Color.FromArgb(190, 90, 20),
                            Severity.Medium => ClrDarkGold,
                            _ => ClrDarkGreen
                        };
                        foreach (string ev in f.Evidence)
                            fn.Nodes.Add(ev.Length > 160 ? ev.Substring(0, 160) + "…" : ev);
                        gn.Nodes.Add(fn);
                    }
                    nodeFind.Nodes.Add(gn);
                }
                nodeFind.NodeFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                treeForensic.Nodes.Add(nodeFind);

                // --- Timeline ---
                var nodeTime = new TreeNode("DÒNG THỜI GIAN (" + bundle.Timeline.Count + ")");
                foreach (var group in bundle.Timeline
                    .Where(e => e.Chain.Length > 0)
                    .GroupBy(e => e.Chain)
                    .OrderBy(g => g.Key))
                {
                    var gn = new TreeNode(group.Key);
                    foreach (TimelineEvent e in group.Take(80))
                    {
                        var en = new TreeNode($"{e.TimestampUtc:yyyy-MM-dd HH:mm:ss}  {e.Description}");
                        en.Tag = e;
                        if (e.Severity >= Severity.High) en.ForeColor = ClrRed;
                        gn.Nodes.Add(en);
                    }
                    nodeTime.Nodes.Add(gn);
                }
                nodeTime.NodeFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                treeForensic.Nodes.Add(nodeTime);

                // --- Artifact theo nguon ---
                var nodeArt = new TreeNode("ARTIFACT (" + bundle.Artifacts.Count + ")");
                foreach (var group in bundle.Artifacts.GroupBy(a => a.Source).OrderBy(g => g.Key))
                {
                    var gn = new TreeNode($"{group.Key} ({group.Count()})");
                    foreach (Artifact a in group.Take(300))
                    {
                        var an = new TreeNode(a.Path.Length > 120 ? a.Path.Substring(0, 120) + "…" : a.Path);
                        an.ToolTipText = a.Category + " · SHA-256 " + a.Sha256;
                        gn.Nodes.Add(an);
                    }
                    if (group.Count() > 300)
                        gn.Nodes.Add($"… và {group.Count() - 300} mục khác");
                    nodeArt.Nodes.Add(gn);
                }
                nodeArt.NodeFont = new Font("Segoe UI", 9.5f, FontStyle.Bold);
                treeForensic.Nodes.Add(nodeArt);

                // --- Loi ---
                if (bundle.CollectorErrors.Count > 0)
                {
                    var nodeErr = new TreeNode("LỖI THU THẬP (" + bundle.CollectorErrors.Count + ")");
                    foreach (string e in bundle.CollectorErrors.Take(100))
                        nodeErr.Nodes.Add(e.Length > 140 ? e.Substring(0, 140) + "…" : e);
                    nodeErr.ForeColor = ClrDarkGold;
                    treeForensic.Nodes.Add(nodeErr);
                }
            }
            finally
            {
                treeForensic.EndUpdate();
                treeForensic.ExpandAll();
            }
        }

        // ==================================================================
        //  LOG
        // ==================================================================
        private enum ForensicLogKind { Info, Success, Warn, Error, Heading }

        private void ForensicLog(string message, ForensicLogKind kind = ForensicLogKind.Info)
        {
            if (txtForensicLog == null) return;

            string stamp = DateTime.Now.ToString("HH:mm:ss");
            Color color = kind switch
            {
                ForensicLogKind.Success => Color.FromArgb(120, 235, 130),
                ForensicLogKind.Warn => ClrLogGold,
                ForensicLogKind.Error => ClrLogRed,
                ForensicLogKind.Heading => ClrLogGold,
                _ => ClrLogText
            };
            string prefix = kind switch
            {
                ForensicLogKind.Success => "[ OK ] ",
                ForensicLogKind.Warn => "[CẢNH BÁO] ",
                ForensicLogKind.Error => "[LỖI]  ",
                ForensicLogKind.Heading => "== ",
                _ => "       "
            };

            if (kind == ForensicLogKind.Heading)
            {
                txtForensicLog.SelectionStart = txtForensicLog.TextLength;
                txtForensicLog.SelectionLength = 0;
                txtForensicLog.SelectionColor = ClrLogGold;
                txtForensicLog.AppendText("=====================================================\n");
            }
            txtForensicLog.SelectionStart = txtForensicLog.TextLength;
            txtForensicLog.SelectionLength = 0;
            txtForensicLog.SelectionColor = Color.FromArgb(90, 130, 100);
            txtForensicLog.AppendText(stamp + "  ");
            txtForensicLog.SelectionColor = color;
            txtForensicLog.AppendText(prefix + message + "\n");
            txtForensicLog.SelectionStart = txtForensicLog.TextLength;
            txtForensicLog.ScrollToCaret();
        }
    }
}
