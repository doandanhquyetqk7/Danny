using System;
using System.Collections.Generic;
using System.Drawing;
using System.Linq;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace NetSecTool;

/// <summary>
/// ListBox khong bao gio "nuot" focus khi nguoi dung click vao.
///
/// Ly do: neu ListBox nhan focus, o tim kiem mat focus -> Windows huy
/// trang thai IME (Unikey/VietB) -> nguoi dung go tiep se bi "don" hoac
/// mat dau. WM_MOUSEACTIVATE tra ve MA_NOACTIVATE nen chuot van bam
/// duoc tren tung dong nhung focus van nam o o nhap.
/// </summary>
internal sealed class NoFocusListBox : ListBox
{
    private const int WM_MOUSEACTIVATE = 0x0021;
    private const int MA_NOACTIVATE = 3;

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_MOUSEACTIVATE)
        {
            m.Result = (IntPtr)MA_NOACTIVATE;
            return;
        }
        base.WndProc(ref m);
    }
}

/// <summary>
/// O tim kiem don vi voi bang goi y (auto-suggest) hien thi NGAY TRONG form.
///
/// Vì sao khong dung ToolStripDropDown?
/// ---------------------------------------
/// ToolStripDropDown / ComboBox dropdown la MOT CUA SO RIENG. Khi no mo,
/// Windows chuyen focus sang cua so do, dung nguon IME cua TextBox ->
///   1. Gõ tiếng Việt co dau se BI DOC (chi giao duoc 1 ky tu roi ket).
///   2. Bam chuot vao dong goi ye se bi an ngay (mat focus truoc khi
///      su kien click chay) -> khong chon duoc.
///
/// Ban nay dung mot Panel/ListBox nội tuyến (child cua Form chinh), nen:
///   - Focus luon o TextBox -> IME tiếng Việt chay binh thuong.
///   - Chuot click vao dong goi ye duoc xu ly binh thuong.
///   - Khong can doi chieu nguon su kien phuc tap.
/// </summary>
internal sealed class UnitSearchBox : Panel
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int SendMessage(IntPtr hWnd, int msg, int wParam, string lParam);

    private const int EM_SETCUEBANNER = 0x1501;

    private readonly TextBox _txt;
    private readonly ListBox _list;
    private readonly System.Windows.Forms.Timer _debounce;

    private List<UnitSearch.Hit> _hits = new();
    private bool _suppress;
    private bool _panelVisible;

    /// <summary>Bang chon don vi khi nguoi dung chon mot dong goi y.</summary>
    public event EventHandler? UnitSelected;

    /// <summary>Don vi dang duoc chon (null neu chua chon).</summary>
    public UnitSearch.Hit? Selected { get; private set; }

    public string Placeholder
    {
        get => _txt.PlaceholderText;
        set => _txt.PlaceholderText = value;
    }

    public UnitSearchBox()
    {
        Dock = DockStyle.Fill;
        Margin = new Padding(0);
        BackColor = SystemColors.Window;

        _txt = new TextBox
        {
            Dock = DockStyle.Fill,
            Font = new Font("Segoe UI", 9f),
            BorderStyle = BorderStyle.FixedSingle,
            Margin = Padding.Empty,

            // --- QUAN TRONG cho viec go tieng Viet co dau ---
            // ImeMode = NoControl: dung IME cua Windows (Unikey/VNI/OSK)
            // de go chu co dau. Neu de mac dinh (Inherit) thi TextBox co the
            // bi Windows tep "disable" IME -> chi giao duoc ky tu ASCII,
            // hoac ky tu dau bi chay mat khi xu ly dong bo.
            ImeMode = ImeMode.NoControl
        };
        _txt.TextChanged += Txt_TextChanged;
        _txt.KeyDown += Txt_KeyDown;
        _txt.GotFocus += (s, e) =>
        {
            SendMessage(_txt.Handle, EM_SETCUEBANNER, 1, _txt.PlaceholderText);

            // Neu o dang chua ten don vi da chon -> bo chon toan bo de nguoi dung
            // go thay the (khong go noi vao ten cu).
            if (_txt.Text.Trim().Length > 0 && !_suppress)
                _txt.SelectAll();
        };
        _txt.LostFocus += (s, e) => BeginInvoke(new Action(HidePanel));
        Controls.Add(_txt);

        // --- Bang goi y nội tuyến (add vao Form, KHONG phai cua so rieng) ---
        _list = new NoFocusListBox
        {
            BorderStyle = BorderStyle.FixedSingle,
            IntegralHeight = false,
            Font = new Font("Segoe UI", 9f),
            BackColor = Color.White,
            ForeColor = Theme.Text,
            TabStop = false
        };
        _list.MouseDown += List_MouseDown;

        _debounce = new System.Windows.Forms.Timer { Interval = 200 };
        _debounce.Tick += (s, e) =>
        {
            _debounce.Stop();
            ApplyFilter();
        };
    }

    /// <summary>
    /// Chon don vi theo ten (dung khi muon dong bo 2 tab hoac khi nhan dien duoc).
    /// </summary>
    public void SelectUnit(IpPlan.Unit unit)
    {
        _suppress = true;
        _txt.Text = unit.Name;
        _txt.SelectionStart = _txt.TextLength;
        _suppress = false;

        Selected = new UnitSearch.Hit { Unit = unit, Score = 0, Reason = "chon thu cong" };
        UnitSelected?.Invoke(this, EventArgs.Empty);
    }

    // ==================================================================
    // LOC + HIEN THI
    // ==================================================================

    private void Txt_TextChanged(object? sender, EventArgs e)
    {
        if (_suppress) return;

        _debounce.Stop();
        _debounce.Start();
    }

    /// <summary>Loc danh sach theo tu khoa hien tai.</summary>
    private void ApplyFilter()
    {
        string q = _txt.Text.Trim();

        if (q.Length == 0) { ShowAll(); return; }

        _hits = UnitSearch.Search(q, 40);

        if (_hits.Count == 0)
        {
            _list.Items.Clear();
            _list.Items.Add("   (không tìm thấy đơn vị nào phù hợp)");
            ShowPanel();
            return;
        }

        FillList();
        ShowPanel();
    }

    private void ShowAll()
    {
        _hits = UnitSearch.AllUnits(300);
        FillList();
        ShowPanel();
    }

    private void FillList()
    {
        _list.BeginUpdate();
        _list.Items.Clear();

        foreach (var h in _hits)
        {
            string label = h.HasLanPlan
                ? $"{h.Name}    —  LAN {h.Unit!.LanCidr}   GW {h.Unit.LanGateway}"
                : h.Name;

            _list.Items.Add(label);
        }

        _list.EndUpdate();
    }

    // ==================================================================
    // HIEN THI / AN BANG GOI Y (nội tuyến trong Form)
    // ==================================================================

    /// <summary>Tim Form chua control nay de them bang goi y.</summary>
    private Form? HostForm => FindHost(this);

        private static Form? FindHost(Control c)
    {
        while (c != null)
        {
            if (c is Form f) return f;
            c = c.Parent;
        }
        return null;
    }

    private void ShowPanel()
    {
        var host = HostForm;
        if (host == null) return;

        if (!_panelVisible)
        {
            // Them bang goi y vao Form (khong phai ToolStrip -> khong phai cua so rieng)
            host.Controls.Add(_list);
            _list.BringToFront();
            _panelVisible = true;
        }

        // Tinh vi tri: ngay ben duoi o tim kiem, dung toa do man hinh
        Point p = _txt.PointToScreen(new Point(0, _txt.Height));

        var area = Screen.FromPoint(p).WorkingArea;
        int w = Math.Max(_txt.Width, 460);
        w = Math.Min(w, area.Width - 20);

        int maxH = Math.Min(260, area.Height - area.Top - 20);
        int itemH = _list.ItemHeight;
        int rows = Math.Max(1, _list.Items.Count);
        int h = Math.Min(maxH, rows * itemH + 6);

        // Neu keo xuong khong du cho roi -> hien len tren textbox
        if (p.Y + h > area.Bottom)
        {
            Point up = _txt.PointToScreen(new Point(0, 0));
            p = new Point(up.X, up.Y - h);

            if (p.Y < area.Top)
            {
                p.Y = area.Top;
                h = Math.Min(h, area.Height - area.Top - 10);
            }
        }

        // Chuyen toa do man hinh -> toa do client cua Form
        Point local = host.PointToClient(p);

        _list.SetBounds(local.X, local.Y, w, h);
        _list.BringToFront();
        _list.Visible = true;
    }

    /// <summary>An bang goi y (goi khi doi tab hoac dong form).</summary>
    public void HideSuggestions()
    {
        HidePanel();
    }

    private void HidePanel()
    {
        if (!_panelVisible) return;
        _list.Visible = false;
    }

    /// <summary>
    /// Click chuot vao dong goi ye -> chon ngay (khong an bang truoc).
    /// </summary>
    private void List_MouseDown(object? sender, MouseEventArgs e)
    {
        int idx = _list.IndexFromPoint(e.Location);
        if (idx < 0 || idx >= _hits.Count) return;

        // Chon ngay khi bam chuot xuong (MouseDown) de khong bi truoc khi
        // su kien Click cua ListBox co thi LostFocus -> an bang.
        PickIndex(idx);
    }

    // ==================================================================
    // PHIM TAT
    // ==================================================================

    private void Txt_KeyDown(object? sender, KeyEventArgs e)
    {
        switch (e.KeyCode)
        {
            case Keys.Down:
                if (!_list.Visible) { ApplyFilter(); e.Handled = true; break; }
                if (_list.Items.Count > 0)
                {
                    _list.SelectedIndex = Math.Min(_list.SelectedIndex + 1, _list.Items.Count - 1);
                    e.Handled = true;
                }
                break;

            case Keys.Up:
                if (_list.Visible && _list.Items.Count > 0)
                {
                    _list.SelectedIndex = Math.Max(_list.SelectedIndex - 1, 0);
                    e.Handled = true;
                }
                break;

            case Keys.Enter:
                if (_list.Visible && _list.Items.Count > 0)
                {
                    int idx = _list.SelectedIndex;
                    if (idx < 0) idx = 0;
                    PickIndex(idx);
                    e.Handled = true;
                    e.SuppressKeyPress = true;
                }
                break;

            case Keys.Escape:
                HidePanel();
                e.Handled = true;
                break;

            case Keys.Back:
            case Keys.Delete:
                // De control xu ly binh thuong, nhung phai an bang goi y
                // neu chuoi bi xoa het.
                BeginInvoke(new Action(() =>
                {
                    if (_txt.Text.Trim().Length == 0) ShowAll();
                }));
                break;
        }
    }

    private void PickIndex(int idx)
    {
        if (idx < 0 || idx >= _hits.Count) { HidePanel(); return; }

        var hit = _hits[idx];

        _suppress = true;
        _txt.Text = hit.Name;
        _txt.SelectionStart = _txt.TextLength;
        _suppress = false;

        Selected = hit;
        HidePanel();

        // Tra focus ve o nhap (giu IME) va bo chon toan bo de nguoi dung
        // co the go tiep ngay.
        _txt.Focus();
        _txt.SelectAll();

        UnitSelected?.Invoke(this, EventArgs.Empty);
    }
}
