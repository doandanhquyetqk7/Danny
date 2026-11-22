using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace NetSecTool
{
    /// <summary>Tab "SAO LƯU MÁY TÍNH" — Ver5.7 Phần 2.4 (partial class Form1).</summary>
    public partial class Form1
    {
        private ComboBox cmbBackupTarget = null!;
        private ListView lstBackupDisks = null!;
        private CheckBox chkBackupSystemImage = null!, chkBackupUserData = null!, chkBackupDryRun = null!;
        private CheckedListBox lstBackupUserDrives = null!;
        private TextBox txtAcronisPath = null!;
        private Button btnBackupScan = null!, btnBackupStart = null!, btnBackupCancel = null!;
        private ProgressBar barBackup = null!;
        private Label lblBackupStatus = null!;
        private RichTextBox txtBackupLog = null!;
        private CancellationTokenSource? ctsBackup;
        private bool backupRunning;

        private void BuildBackupTab(TabPage tab)
        {
            // 5 hang: o dich / tuy chon / trang thai / progress / log + nut
            var layout = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 5,
                Margin = Padding.Empty,
                Padding = Padding.Empty
            };
            layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 210));  // 0 - o dich + tuy chon
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));   // 1 - trang thai
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 16));   // 2 - progress
            layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - log
            layout.RowStyles.Add(new RowStyle(SizeType.Absolute, 50));   // 4 - nut
            tab.Controls.Add(layout);

            layout.Controls.Add(BuildBackupControlPanel(), 0, 0);

            lblBackupStatus = new Label
            {
                Text = "Chưa quét ổ đĩa. Bấm \"Quét ổ đĩa\" để kiểm tra ổ đích hợp lệ.",
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(240, 243, 238),
                ForeColor = ClrMuted,
                TextAlign = ContentAlignment.MiddleLeft,
                Padding = new Padding(12, 0, 0, 0),
                Font = new Font("Segoe UI", 9.5f, FontStyle.Bold),
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(0, 2, 0, 2)
            };
            layout.Controls.Add(lblBackupStatus, 0, 1);

            barBackup = new ProgressBar
            {
                Dock = DockStyle.Fill,
                Style = ProgressBarStyle.Continuous,
                ForeColor = ClrMidGreen,
                Margin = Padding.Empty
            };
            layout.Controls.Add(barBackup, 0, 2);

            txtBackupLog = new RichTextBox
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
            layout.Controls.Add(txtBackupLog, 0, 3);

            // --- Hang nut ---
            var pnlBtns = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 4,
                RowCount = 1,
                Margin = Padding.Empty,
                Padding = new Padding(0, 6, 0, 0)
            };
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 26));
            pnlBtns.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 210));
            pnlBtns.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            btnBackupScan = MakeButton("Quét ổ đĩa", 0, 0, 200, 38, ClrDarkGold);
            btnBackupScan.Click += (s, e) => ScanBackupDisks();
            btnBackupScan.Dock = DockStyle.Fill;
            btnBackupScan.Margin = new Padding(0, 0, 4, 0);
            pnlBtns.Controls.Add(btnBackupScan, 0, 0);

            btnBackupStart = MakeButton("BẮT ĐẦU SAO LƯU", 0, 0, 240, 38, ClrRed);
            btnBackupStart.Click += (s, e) => StartBackup();
            btnBackupStart.Dock = DockStyle.Fill;
            btnBackupStart.Enabled = false;
            btnBackupStart.Margin = new Padding(4, 0, 4, 0);
            pnlBtns.Controls.Add(btnBackupStart, 1, 0);

            btnBackupCancel = MakeButton("HỦY", 0, 0, 160, 38, ClrDarkGold);
            btnBackupCancel.Click += (s, e) =>
            {
                try { ctsBackup?.Cancel(); } catch { }
            };
            btnBackupCancel.Dock = DockStyle.Fill;
            btnBackupCancel.Enabled = false;
            btnBackupCancel.Margin = new Padding(4, 0, 4, 0);
            pnlBtns.Controls.Add(btnBackupCancel, 2, 0);

            var btnHelpBk = MakeButton("Hướng dẫn", 0, 0, 200, 38, ClrDarkGreen);
            btnHelpBk.Click += (s, e) => ShowBackupHelp();
            btnHelpBk.Dock = DockStyle.Fill;
            btnHelpBk.Margin = new Padding(4, 0, 0, 0);
            pnlBtns.Controls.Add(btnHelpBk, 3, 0);

            layout.Controls.Add(pnlBtns, 0, 4);
        }

        private Control BuildBackupControlPanel()
        {
            // 4 hang: tieu de / danh sach o dia + chon o dich / tuy chon noi dung / acronis
            var tbl = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 4,
                BackColor = ClrPanel,
                Padding = new Padding(12, 6, 12, 6),
                Margin = Padding.Empty
            };
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 62));
            tbl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 38));
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 24));   // 0 - tieu de
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));   // 1 - danh sach o dia
            tbl.RowStyles.Add(new RowStyle(SizeType.Absolute, 52));   // 2 - tuy chon
            tbl.RowStyles.Add(new RowStyle(SizeType.Percent, 100));  // 3 - acronis

            var lblTitle = new Label
            {
                Text = "SAO LƯU HỆ THỐNG & DỮ LIỆU NGƯỜI DÙNG",
                ForeColor = ClrMidGreen,
                Font = new Font("Segoe UI", 10.5f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            tbl.Controls.Add(lblTitle, 0, 0);
            tbl.SetColumnSpan(lblTitle, 3);

            // --- Cot 0: danh sach o dia vat ly ---
            lstBackupDisks = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = Color.White,
                Font = new Font("Consolas", 8.5f),
                Margin = new Padding(0, 2, 6, 2)
            };
            lstBackupDisks.Columns.Add("Thiết bị", 90);
            lstBackupDisks.Columns.Add("Model", 210);
            lstBackupDisks.Columns.Add("Dung lượng", 90);
            lstBackupDisks.Columns.Add("Giao diện", 80);
            lstBackupDisks.Columns.Add("Ổ", 60);
            lstBackupDisks.Columns.Add("Đánh giá", 120);
            tbl.Controls.Add(lstBackupDisks, 0, 1);
            tbl.SetColumnSpan(lstBackupDisks, 2);

            // --- Cot 2: chon o dich + tuy chon noi dung ---
            var pnlRight = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 1,
                RowCount = 3,
                Margin = Padding.Empty
            };
            pnlRight.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pnlRight.RowStyles.Add(new RowStyle(SizeType.Absolute, 28));
            pnlRight.RowStyles.Add(new RowStyle(SizeType.Absolute, 74));
            pnlRight.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            var lblTarget = new Label
            {
                Text = "Ổ đích (bắt buộc di động ≥ 1 TB):",
                ForeColor = ClrText,
                Font = new Font("Segoe UI", 9f, FontStyle.Bold),
                Dock = DockStyle.Fill,
                TextAlign = ContentAlignment.MiddleLeft,
                AutoSize = false,
                Margin = Padding.Empty
            };
            pnlRight.Controls.Add(lblTarget, 0, 0);

            cmbBackupTarget = new ComboBox
            {
                Dock = DockStyle.Fill,
                DropDownStyle = ComboBoxStyle.DropDownList,
                Margin = new Padding(0, 2, 0, 2)
            };
            cmbBackupTarget.SelectedIndexChanged += (s, e) => ValidateBackupTarget();
            pnlRight.Controls.Add(cmbBackupTarget, 0, 1);

            lstBackupUserDrives = new CheckedListBox
            {
                Dock = DockStyle.Fill,
                CheckOnClick = true,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5f),
                Margin = Padding.Empty
            };
            pnlRight.Controls.Add(lstBackupUserDrives, 0, 2);

            tbl.Controls.Add(pnlRight, 2, 1);

            // --- Hang 2: tuy chon ---
            chkBackupSystemImage = MakeCheck("Ảnh hệ thống (Acronis — Full Disk)", true);
            chkBackupUserData = MakeCheck("Dữ liệu người dùng (Robocopy)", true);
            chkBackupDryRun = MakeCheck("DRY-RUN (không ghi thật — dùng để kiểm thử)", false);

            var pnlOpts = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 34));
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
            pnlOpts.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 33));
            pnlOpts.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            pnlOpts.Controls.Add(chkBackupSystemImage, 0, 0);
            pnlOpts.Controls.Add(chkBackupUserData, 1, 0);
            pnlOpts.Controls.Add(chkBackupDryRun, 2, 0);
            tbl.Controls.Add(pnlOpts, 0, 2);
            tbl.SetColumnSpan(pnlOpts, 3);

            // --- Hang 3: duong dan engine Acronis ---
            var pnlAcr = new TableLayoutPanel
            {
                Dock = DockStyle.Fill,
                ColumnCount = 3,
                RowCount = 1,
                Margin = Padding.Empty
            };
            pnlAcr.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 160));
            pnlAcr.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            pnlAcr.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 190));
            pnlAcr.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

            pnlAcr.Controls.Add(MakeLabel("Engine Acronis CLI:", 0, 0), 0, 0);

            txtAcronisPath = new TextBox
            {
                Dock = DockStyle.Fill,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 8.5f),
                Margin = new Padding(0, 3, 6, 3)
            };
            pnlAcr.Controls.Add(txtAcronisPath, 1, 0);

            var btnBrowseAcr = MakeButton("Duyệt...", 0, 0, 90, 25, ClrDarkGold);
            btnBrowseAcr.Click += (s, e) =>
            {
                using var dlg = new OpenFileDialog
                {
                    Title = "Chọn engine Acronis CLI",
                    Filter = "Acronis CLI (*.exe)|*.exe|Tất cả (*.*)|*.*",
                    InitialDirectory = Path.Combine(AppContext.BaseDirectory, "tools")
                };
                if (dlg.ShowDialog(this) == DialogResult.OK) txtAcronisPath.Text = dlg.FileName;
            };
            btnBrowseAcr.Dock = DockStyle.Fill;
            btnBrowseAcr.Margin = new Padding(0, 3, 0, 3);
            pnlAcr.Controls.Add(btnBrowseAcr, 2, 0);

            tbl.Controls.Add(pnlAcr, 0, 3);
            tbl.SetColumnSpan(pnlAcr, 3);

            return tbl;
        }

        private void ScanBackupDisks()
        {
            lblBackupStatus.Text = "Đang quét ổ đĩa vật lý qua WMI...";
            lblBackupStatus.ForeColor = ClrDarkGold;

            DiskScanResult scan = BackupService.ScanDisks();

            lstBackupDisks.Items.Clear();
            cmbBackupTarget.Items.Clear();
            lstBackupUserDrives.Items.Clear();

            foreach (PhysicalDisk d in scan.Disks)
            {
                string verdict = d.IsExternal
                    ? (d.SizeBytes >= BackupService.MinTargetBytes ||
                       d.SizeBytes >= BackupService.MinTargetBytesGiB ? "HỢP LỆ (di động ≥1TB)" : "Di động — NHỎ < 1TB")
                    : "Ổ GẮN TRONG — KHÔNG ĐƯỢC DÙNG";

                var li = new ListViewItem(d.DeviceId);
                li.SubItems.Add(d.Model);
                li.SubItems.Add(d.SizeText);
                li.SubItems.Add(d.InterfaceType);
                li.SubItems.Add(string.Join(",", d.DriveLetters));
                li.SubItems.Add(verdict);
                li.ForeColor = d.IsExternal
                    ? (verdict.StartsWith("HỢP LỆ") ? ClrDarkGreen : ClrDarkGold)
                    : ClrRed;
                lstBackupDisks.Items.Add(li);

                if (d.IsExternal &&
                    (d.SizeBytes >= BackupService.MinTargetBytes ||
                     d.SizeBytes >= BackupService.MinTargetBytesGiB))
                {
                    foreach (string letter in d.DriveLetters)
                        cmbBackupTarget.Items.Add(letter + "  —  " + d.Model + " (" + d.SizeText + ")");
                }
            }

            foreach (string drv in BackupService.DetectUserDataDrives())
                lstBackupUserDrives.Items.Add(drv, true);

            if (cmbBackupTarget.Items.Count > 0) cmbBackupTarget.SelectedIndex = 0;

            if (scan.ValidExternalTargets.Count == 0)
            {
                lblBackupStatus.Text = "KHÔNG có ổ cứng di động ≥ 1 TB. Hãy cắm ổ di động tối thiểu 1 TB rồi quét lại.";
                lblBackupStatus.ForeColor = ClrRed;
                btnBackupStart.Enabled = false;
                MessageBox.Show(
                    "KHÔNG TÌM THẤY Ổ CỨNG DI ĐỘNG ĐỦ ĐIỀU KIỆN.\n\n" +
                    "Yêu cầu: ổ cứng di động (USB / External) có dung lượng vật lý TỐI THIỂU 1 TB.\n" +
                    "(Lưu ý: ổ 1 TB thật hiển thị ~931 GiB trên Windows — đã tính ngưỡng tương ứng.)\n\n" +
                    "Tuyệt đối không cho phép lưu bản sao lưu vào ổ cứng GẮN TRONG.",
                    "Không có ổ đích hợp lệ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else
            {
                ValidateBackupTarget();
            }

            if (scan.Errors.Count > 0)
                BackupLog("Lỗi khi quét: " + string.Join("; ", scan.Errors), BackupLogKind.Warn);
        }

        private void ValidateBackupTarget()
        {
            if (cmbBackupTarget == null || cmbBackupTarget.SelectedItem == null)
            {
                if (btnBackupStart != null) btnBackupStart.Enabled = false;
                return;
            }

            string sel = cmbBackupTarget.SelectedItem.ToString() ?? "";
            string letter = sel.Substring(0, 2);

            string? reject = BackupService.ValidateTarget(letter, out PhysicalDisk? disk);
            if (reject != null)
            {
                lblBackupStatus.Text = "✗ " + reject;
                lblBackupStatus.ForeColor = ClrRed;
                btnBackupStart.Enabled = false;
                return;
            }

            lblBackupStatus.Text = $"✓ Ổ đích hợp lệ: {disk!.Model} ({disk.SizeText}) — {disk.DeviceId}";
            lblBackupStatus.ForeColor = ClrDarkGreen;
            btnBackupStart.Enabled = true;
        }

        private async void StartBackup()
        {
            if (backupRunning) return;
            if (cmbBackupTarget?.SelectedItem == null) return;

            string letter = (cmbBackupTarget.SelectedItem.ToString() ?? "").Substring(0, 2);
            string? reject = BackupService.ValidateTarget(letter, out _);
            if (reject != null)
            {
                MessageBox.Show(reject, "Ổ đích không hợp lệ", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                return;
            }

            var opt = new BackupOptions
            {
                TargetDrive = letter,
                BackupSystemImage = chkBackupSystemImage.Checked,
                BackupUserData = chkBackupUserData.Checked,
                AcronisEnginePath = (txtAcronisPath?.Text ?? "").Trim(),
                MachineName = Environment.MachineName,
                DryRun = chkBackupDryRun.Checked
            };
            foreach (object item in lstBackupUserDrives.CheckedItems)
                opt.UserDrives.Add(item.ToString() ?? "");

            if (!opt.BackupSystemImage && !opt.BackupUserData)
            {
                MessageBox.Show("Hãy chọn ít nhất một phần: Ảnh hệ thống hoặc Dữ liệu người dùng.",
                    "Chưa chọn nội dung", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            string warn =
                "SẼ SAO LƯU vào ổ " + letter + "\\" + "\n\n" +
                "• Ảnh hệ thống: " + (opt.BackupSystemImage ? "CÓ (Acronis — có thể mất 30–180 phút)" : "KHÔNG") + "\n" +
                "• Dữ liệu người dùng: " + (opt.BackupUserData ? "CÓ (" + opt.UserDrives.Count + " ổ)" : "KHÔNG") + "\n";
            if (opt.DryRun) warn += "• CHẾ ĐỘ DRY-RUN: không ghi dữ liệu thật.\n";
            warn += "\nThư mục đích: <Ổ đích>\\<TenMay>_<yyyyMMdd_HHmmss>\\\n\nTiếp tục?";
            if (MessageBox.Show(warn, "Xác nhận sao lưu", MessageBoxButtons.YesNo,
                    MessageBoxIcon.Warning, MessageBoxDefaultButton.Button2) != DialogResult.Yes)
                return;

            backupRunning = true;
            ctsBackup = new CancellationTokenSource();
            var ct = ctsBackup.Token;

            btnBackupStart.Enabled = false;
            btnBackupCancel.Enabled = true;
            btnBackupScan.Enabled = false;
            txtBackupLog.Clear();
            barBackup.Style = ProgressBarStyle.Marquee;
            barBackup.MarqueeAnimationSpeed = 30;
            lblBackupStatus.Text = "Đang sao lưu...";
            lblBackupStatus.ForeColor = ClrDarkGold;

            BackupResult res = await Task.Run(
                () => BackupService.RunAsync(opt,
                    msg => BeginInvokeSafe(() => BackupLog(msg, BackupLogKind.Info)),
                    null,
                    ct),
                ct);

            backupRunning = false;
            btnBackupStart.Enabled = true;
            btnBackupCancel.Enabled = false;
            btnBackupScan.Enabled = true;
            barBackup.Style = ProgressBarStyle.Continuous;
            barBackup.Value = barBackup.Maximum;

            foreach (string e in res.Errors)
                BackupLog(e, BackupLogKind.Error);
            foreach (string w in res.Warnings)
                BackupLog(w, BackupLogKind.Warn);

            lblBackupStatus.Text = res.Message;
            lblBackupStatus.ForeColor = res.Success ? ClrDarkGreen : (res.Cancelled ? ClrDarkGold : ClrRed);

            BackupLog("=== " + (res.Success ? "HOÀN TẤT" : (res.Cancelled ? "ĐÃ HỦY" : "HOÀN TẤT CÓ LỖI")) + " ===", BackupLogKind.Heading);
            BackupLog(res.Message, BackupLogKind.Heading);

            MessageBox.Show(res.Message,
                res.Success ? "Sao lưu hoàn tất" : "Sao lưu kết thúc",
                MessageBoxButtons.OK,
                res.Success ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }

        private void ShowBackupHelp()
        {
            MessageBox.Show(
                "SAO LƯU MÁY TÍNH — HƯỚNG DẪN\n\n" +
                "RÀNG BUỘC Ổ ĐÍCH (bắt buộc):\n" +
                "• Chỉ chấp nhận ổ cứng DI ĐỘNG gắn ngoài (USB / External).\n" +
                "• Dung lượng vật lý tối thiểu 1 TB (tương đương ~931 GiB hiển thị).\n" +
                "• TUYỆT ĐỐI KHÔNG lưu vào ổ cứng gắn trong (internal disk).\n\n" +
                "CHỨC NĂNG 1 — ẢNH HỆ THỐNG (Acronis CLI):\n" +
                "• Full Disk: gồm EFI System Partition, MSR, Recovery, phân vùng\n" +
                "  Windows (C:) và bảng phân vùng GPT/MBR → khôi phục được\n" +
                "  trên phần cứng mới.\n" +
                "• Cần đặt engine: tools\\acronis\\acrocmd.exe (hoặc AcronisTrueImageCmd.exe)\n" +
                "  cạnh phần mềm, hoặc cài Acronis True Image và chọn đường dẫn.\n\n" +
                "CHỨC NĂNG 2 — DỮ LIỆU NGƯỜI DÙNG (Robocopy):\n" +
                "• Tự phát hiện ổ dữ liệu gắn trong (D:\\, E:\\...) — loại trừ C: và ổ di động.\n" +
                "• Tham số: /E /COPY:DAT /DCOPY:T /R:2 /W:3 /MT:8 /XJ\n" +
                "  (tránh lặp junction, bỏ qua $RECYCLE.BIN và System Volume Information).\n\n" +
                "CẤU TRÚC THƯ MỤC KẾT QUẢ:\n" +
                "  <Ổ đích>\\<TenMay>_<yyyyMMdd_HHmmss>\\\n" +
                "      SystemImage\\   (ảnh hệ thống + acronis.log)\n" +
                "      UserData\\Drive_D\\, Drive_E\\...\n\n" +
                "DRY-RUN: bỏ chọn hẳn thao tác ghi thật để kiểm thử an toàn.",
                "Hướng dẫn — Sao lưu máy tính",
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        // ==================================================================
        //  LOG
        // ==================================================================
        private enum BackupLogKind { Info, Success, Warn, Error, Heading }

        private void BackupLog(string message, BackupLogKind kind = BackupLogKind.Info)
        {
            if (txtBackupLog == null) return;

            string stamp = DateTime.Now.ToString("HH:mm:ss");
            Color color = kind switch
            {
                BackupLogKind.Success => Color.FromArgb(120, 235, 130),
                BackupLogKind.Warn => ClrLogGold,
                BackupLogKind.Error => ClrLogRed,
                BackupLogKind.Heading => ClrLogGold,
                _ => ClrLogText
            };
            string prefix = kind switch
            {
                BackupLogKind.Success => "[ OK ] ",
                BackupLogKind.Warn => "[CẢNH BÁO] ",
                BackupLogKind.Error => "[LỖI]  ",
                BackupLogKind.Heading => "== ",
                _ => "       "
            };

            if (kind == BackupLogKind.Heading)
            {
                txtBackupLog.SelectionStart = txtBackupLog.TextLength;
                txtBackupLog.SelectionLength = 0;
                txtBackupLog.SelectionColor = ClrLogGold;
                txtBackupLog.AppendText("=====================================================\n");
            }
            txtBackupLog.SelectionStart = txtBackupLog.TextLength;
            txtBackupLog.SelectionLength = 0;
            txtBackupLog.SelectionColor = Color.FromArgb(90, 130, 100);
            txtBackupLog.AppendText(stamp + "  ");
            txtBackupLog.SelectionColor = color;
            txtBackupLog.AppendText(prefix + message + "\n");
            txtBackupLog.SelectionStart = txtBackupLog.TextLength;
            txtBackupLog.ScrollToCaret();
        }
    }
}
