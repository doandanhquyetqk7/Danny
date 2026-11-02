using System.Drawing;

namespace NetSecTool;

/// <summary>
/// Bang mau chuan quan doi - tung do, vang, do.
/// </summary>
internal static class Theme
{
    // --- Xanh la cay dam (mau chu dao) ---
    public static readonly Color DarkGreen = Color.FromArgb(23, 74, 44);      // nen tieu de
    public static readonly Color MidGreen = Color.FromArgb(34, 104, 62);      // nen nut chinh
    public static readonly Color DeepGreen = Color.FromArgb(16, 52, 32);      // nen toi
    public static readonly Color GreenBorder = Color.FromArgb(0, 92, 44);

    // --- Do ---
    public static readonly Color Red = Color.FromArgb(158, 22, 22);
    public static readonly Color BrightRed = Color.FromArgb(196, 42, 42);
    public static readonly Color LightRed = Color.FromArgb(250, 228, 228);

    // --- Vang ---
    public static readonly Color Gold = Color.FromArgb(214, 176, 58);
    public static readonly Color DarkGold = Color.FromArgb(160, 126, 26);
    public static readonly Color LightGold = Color.FromArgb(252, 245, 220);

    // --- Nen / chu ---
    public static readonly Color Background = Color.FromArgb(235, 239, 233);
    public static readonly Color PanelBg = Color.FromArgb(250, 251, 248);
    public static readonly Color Text = Color.FromArgb(28, 34, 29);
    public static readonly Color MutedText = Color.FromArgb(96, 104, 97);
    public static readonly Color White = Color.White;

    // --- Log panel (terminal) ---
    public static readonly Color LogBg = Color.FromArgb(14, 30, 20);
    public static readonly Color LogText = Color.FromArgb(142, 232, 150);
    public static readonly Color LogAccent = Color.FromArgb(214, 176, 58);

    public static Font FontNormal(float size = 9f) => new("Segoe UI", size);
    public static Font FontBold(float size = 9f) => new("Segoe UI", size, FontStyle.Bold);
    public static Font FontTitle(float size = 14f) => new("Segoe UI", size, FontStyle.Bold);
    public static Font FontMono(float size = 8.5f) => new("Consolas", size);
}
