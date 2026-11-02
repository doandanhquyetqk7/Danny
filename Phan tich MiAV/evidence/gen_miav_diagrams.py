#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r"""
gen_miav_diagrams.py
Sinh SVG thu cong (khong can node/mermaid) cho ba so do:
  1) Kien truc thanh phan MiAV
  2) Luong phat hien Internet (Plug-in/Plug-out)
  3) Luong duong dan artifact de lam sach log
Usage: python gen_miav_diagrams.py <output_dir>
"""
import os
import sys

FONT = "Segoe UI, Arial, sans-serif"
MONO = "Consolas, 'Courier New', monospace"

RED = "#8C1D18"
YELLOW = "#C89B1E"
GREEN = "#1F5C2E"
DARK = "#20301C"
PAPER = "#F7F5EE"
GREY = "#6B6B6B"


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def text(x, y, s, size=13, fill=DARK, anchor="start", weight="normal", font=FONT, style=""):
    st = (' style="%s"' % style) if style else ""
    return ('<text x="%s" y="%s" font-family="%s" font-size="%s" fill="%s" '
            'text-anchor="%s" font-weight="%s"%s>%s</text>'
            % (x, y, font, size, fill, anchor, weight, st, esc(s)))


def box(x, y, w, h, title, lines, fill="#FFFFFF", stroke=DARK, sw=2, tsize=13, lsize=11):
    out = ['<rect x="%s" y="%s" width="%s" height="%s" rx="6" fill="%s" stroke="%s" stroke-width="%s"/>'
           % (x, y, w, h, fill, stroke, sw)]
    out.append(text(x + w / 2, y + 20, title, tsize, stroke, "middle", "bold"))
    ty = y + 40
    for ln in lines:
        out.append(text(x + 10, ty, ln, lsize, DARK))
        ty += lsize + 5
    return "\n".join(out)


def arrow(x1, y1, x2, y2, color=DARK, label=None, dashed=False, lw=2):
    out = ['<line x1="%s" y1="%s" x2="%s" y2="%s" stroke="%s" stroke-width="%s"%s marker-end="url(#ah)"/>'
           % (x1, y1, x2, y2, color, lw, ' stroke-dasharray="6,4"' if dashed else "")]
    if label:
        mx, my = (x1 + x2) / 2.0, (y1 + y2) / 2.0
        out.append('<rect x="%s" y="%s" width="%s" height="17" fill="%s" opacity="0.92" rx="3"/>'
                   % (mx - len(label) * 3.2 - 4, my - 14, len(label) * 6.4 + 8, PAPER))
        out.append(text(mx, my - 2, label, 10.5, color, "middle"))
    return "\n".join(out)


def svg_head(w, h, title):
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<svg xmlns="http://www.w3.org/2000/svg" width="%s" height="%s" viewBox="0 0 %s %s">\n'
            '<defs>\n'
            '<marker id="ah" markerWidth="10" markerHeight="8" refX="9" refY="4" orient="auto">'
            '<path d="M0,0 L10,4 L0,8 z" fill="%s"/></marker>\n'
            '</defs>\n'
            '<rect width="100%%" height="100%%" fill="%s"/>\n'
            '%s\n'
            % (w, h, w, h, DARK, PAPER, text(30, 38, title, 21, DARK, "start", "bold")))


def svg_tail():
    return "</svg>\n"


def diag_arch(out):
    W, H = 1180, 760
    s = [svg_head(W, H, "Kien truc thanh phan MiAV 4.1.1.2 (BTL86)")]

    s.append(text(30, 68, "Cai dat: Inno Setup 6.6.1 -> C:\\Users\\Public\\Documents\\AgentFMC\\   |   "
                          "4 service tu khoi dong + 1 khoa Run", 12, GREY))

    s.append(box(40, 95, 250, 120, "SetupMiAV.exe",
                 ["Inno Setup 6.6.1", "AppVersion 4.1.1.2", "Publisher: BTL86, Inc.",
                  "LZMA compression"], "#FFFFFF", DARK))

    svc_y = 280
    svcs = [
        ("MiAVWD", "MiAV_WD.exe", "Watchdog", GREEN),
        ("MiAVUpdate", "MiAV_Update.exe", "Dong bo IOC / policy", GREEN),
        ("MiAVProtect", "MiAV_Protect.exe", "Agent giam sat chinh (32 MB)", RED),
        ("Defense", "SerDefense.exe", "WebSocket + WMI", YELLOW),
    ]
    x = 40
    for name, exe, desc, col in svcs:
        s.append(box(x, svc_y, 255, 95, name, [exe, desc], "#FFFFFF", col, 2.5))
        s.append(arrow(165, 215, x + 127, svc_y, DARK))
        x += 285

    s.append(box(40, 420, 250, 80, "MiAV.exe (GUI)",
                 ["Delphi 10.4 - EDR engine", "AutoRun: HKLM\\...\\Run\\MiAV"], "#FFFFFF", DARK))

    s.append(box(340, 545, 380, 115, "Tang kernel - CBFSFilter",
                 ["cbfsfilter20.dll + cbfsfilter20_dta",
                  "GUID {713CC6CE-B3E2-4fd9-838D-E28F558F6866}",
                  "CBRegistry / CBProcess / CBFile",
                  "Cai boi InstallCallBackFilter.exe"], "#F3EFE2", RED, 3))

    s.append(box(770, 545, 370, 115, "Artifact cuc bo",
                 ["data\\data.db (SQLite: Logs / LocalFiles / Hashs)",
                  "logs\\ , log.txt , syslog.ini",
                  "policy.info / policy.ping / policy.net / policy.tracert*"], "#F3EFE2", GREEN, 2.5))

    s.append(box(770, 280, 370, 145, "Server FMS (BTL86)",
                 ["http://fms.bqp",
                  "http://27.68.131.116:8080  (public)",
                  "http://10.152.4.2            (noi bo)",
                  "REST: /api/v1/events/insert",
                  "        /api/v1/alerts/insert",
                  "        /api/v1/active-devices/insert"], "#FFFFFF", RED, 2.5))

    s.append(arrow(555, 375, 555, 545, RED, "callback driver", True))
    s.append(arrow(290, 460, 420, 545, DARK, "ghi log", True))
    s.append(arrow(960, 545, 960, 425, GREEN, "gui telemetry", True))
    s.append(arrow(712, 330, 770, 330, RED, "HTTPS"))
    s.append(arrow(712, 420, 770, 390, GREEN, "gui log"))
    s.append(arrow(165, 420, 165, 375, DARK, "run"))

    s.append(text(40, 700, "Nhan xet: MiAV la mot bo EDR/AV hoan chinh. Viec giam sat 'lich su Internet' "
                           "nam o lop user-mode (MiAV.exe + MiAV_Protect.exe),", 12, DARK))
    s.append(text(40, 718, "khong nam o driver. Driver CBFSFilter chi theo doi hanh vi file/registry/tien trinh.", 12, DARK))

    s.append(svg_tail())
    open(os.path.join(out, "01-kien-truc-miav.svg"), "w", encoding="utf-8").write("\n".join(s))


def diag_internet(out):
    W, H = 1180, 830
    s = [svg_head(W, H, "Co che phat hien may co lich su ket noi Internet")]

    s.append(text(30, 66, "Khong doc lich su trinh duyet / SRUM / DNS cache. "
                          "Thay vao do: do trang thai ket noi hien tai + gom bang ket noi + ghi su kien.",
                  12, GREY))

    s.append(box(40, 100, 340, 175, "1. Lenh mang (MiAV.exe)",
                 ["cmd.exe /C ipconfig/all  -> policy.info",
                  "cmd.exe /C ping 8.8.8.8  -> policy.ping",
                  "cmd.exe /C netstat -nao   -> policy.net",
                  "cmd.exe /C tracert wikipedia.org",
                  "        -> policy.tracertWiki",
                  "cmd.exe /C tracert 27.68.131.116",
                  "        -> policy.tracertpBTL",
                  "cmd.exe /C tracert 10.152.4.2",
                  "        -> policy.tracertlBTL"], "#FFFFFF", RED, 2.5))

    s.append(box(40, 310, 340, 120, "2. Gom bang ket noi (MiAV_Protect)",
                 ["netstat -nao  (C:\\windows\\system32)",
                  "-> truong \"connections\" trong JSON:",
                  '{"OS":..,"network":..,"connections":..,',
                  ' "list_process":..,"list_auto_run":..}'], "#FFFFFF", RED, 2.5))

    s.append(box(40, 465, 340, 120, "3. Canh bao URL",
                 ['{"src_mac":..,"src_ip":..,"alert_type":..,',
                  ' "alert_desc":..,"alert_url":..,"alert_level":..}',
                  "-> URL muc tieu bi ghi lai"], "#FFFFFF", RED, 2.5))

    s.append(box(430, 100, 330, 160, "4. Ghi su kien (nhan nhom)",
                 ['type   = "Internet"',
                  'name   = "Plug-in" / "Plug-out"',
                  'level  = "Alert"',
                  'data   = {"ComputerName":%s,"FullMac":%s,',
                  '          "Time":%s,"description":%s}',
                  "xac minh: VA 0x00981ed7 / 0x00981fa4"], "#FDF6E3", YELLOW, 3))

    s.append(box(430, 310, 330, 140, "5. Bang Logs (SQLite)",
                 ["C:\\Users\\Public\\Documents\\AgentFMC\\",
                  "  data\\data.db -> bang \"Logs\"",
                  "  type, name, log_time, data,",
                  "  time_sent, level, id",
                  "cot time_sent = da gui di hay chua"], "#F3EFE2", GREEN, 2.5))

    s.append(box(430, 490, 330, 95, "6. File log dang text",
                 ["..\\AgentFMC\\logs\\", "..\\AgentFMC\\log.txt",
                  "..\\AgentFMC\\syslog.ini"], "#F3EFE2", GREEN, 2.5))

    s.append(box(830, 100, 310, 200, "7. Gui len server FMS",
                 ["/api/v1/events/insert",
                  "/api/v1/alerts/insert",
                  "/api/v1/active-devices/insert",
                  "/api/v1/hashs/by-date",
                  "",
                  "HTTPS (OpenSSL: libeay32/ssleay32)",
                  "Xac thuc: public.pem (RSA) + JWT RS256"], "#FFFFFF", RED, 2.5))

    s.append(box(830, 340, 310, 150, "8. Lop song song: SerDefense",
                 ['Service "MiAV_Defense"',
                  "cmd.exe /C , sc.exe , wmic bios",
                  "WMI: Win32_NetworkAdapterConfiguration",
                  "Loc: Loopback / WAN Miniport / Async /",
                  "      Kaspersky / Virtual / 169.254",
                  "Kenh WebSocket (sgcWebSockets)"], "#FFFFFF", YELLOW, 2.5))

    s.append(arrow(380, 185, 430, 160, RED, "ket qua"))
    s.append(arrow(380, 370, 430, 370, RED))
    s.append(arrow(380, 525, 430, 350, RED))
    s.append(arrow(760, 170, 830, 170, RED, "POST"))
    s.append(arrow(760, 380, 830, 250, GREEN, "POST"))
    s.append(arrow(760, 535, 830, 230, GREEN, "POST"))
    s.append(arrow(595, 260, 595, 310, DARK))
    s.append(arrow(595, 450, 595, 490, DARK))

    s.append(text(40, 640, "KET LUAN", 15, RED, "start", "bold"))
    concl = [
        "MiAV khong doc lich su trinh duyet, SRUM, DNS cache, prefetch, amcache, RunMRU -> KHONG can xoa cac artifact nay de 'danh trao' voi MiAV.",
        "Bang chung 'da tung noi Internet' cua MiAV nam o: file policy.*, bang Logs trong data.db, thu muc logs\\ va log.txt.",
        "MiAV ghi nhat theo thoi diem: moi lan 'Plug-in' (may ket noi duoc Internet) deu bi ghi va gui di.",
        "Du lieu da gui len server KHONG thu hoi duoc bang thao tac cuc bo -> can de nghi quan tri vien phia FMS/BTL86 xoa lich su thiet bi.",
    ]
    for i, ln in enumerate(concl):
        s.append(text(40, 665 + i * 19, "- " + ln, 12, DARK))

    s.append(svg_tail())
    open(os.path.join(out, "02-co-che-phat-hien-internet.svg"), "w", encoding="utf-8").write("\n".join(s))


def diag_cleanup(out):
    W, H = 1180, 900
    s = [svg_head(W, H, "Ban do artifact can lam sach (thu tu uu tien)")]

    s.append(text(30, 66, "Muc tieu: xoa moi dau vet cuc bo ma MiAV dung de ket luan may da tung noi Internet.",
                  12, GREY))

    cols = [
        ("BAT BUOC", RED, [
            ("C:\\Users\\Public\\Documents\\AgentFMC\\data\\data.db",
             ["Bang \"Logs\" - nhat ky su kien Internet/Plug-in/Plug-out",
              "Bang \"LocalFiles\" - danh sach AutoRun",
              "Bang \"Hashs\" - 978 IOC"], "SQLite"),
            ("..\\AgentFMC\\logs\\", ["Nhieu tep log theo ngay/doi tuong"], "thu muc"),
            ("..\\AgentFMC\\log.txt", ["Log dang text cua agent"], "tep"),
            ("..\\AgentFMC\\policy.*", ["policy.info / .ping / .net / .tracertWiki",
                                        "policy.tracertpBTL / policy.tracertlBTL"], "6 tep"),
            ("..\\AgentFMC\\syslog.ini", ["Cau hinh syslog"], "tep"),
            ("..\\AgentFMC\\Debug\\ + debugmiav.txt", ["Log debug"], "thu muc/tep"),
        ]),
        ("NEN LAM", YELLOW, [
            ("C:\\Users\\Public\\Documents\\AgentFMC\\auto\\", ["Module/plugin tai ve"], "thu muc"),
            ("C:\\Users\\Public\\Documents\\AgentFMC\\0dpm\\", ["Module/plugin tai ve"], "thu muc"),
            ("C:\\Users\\Public\\Documents\\AgentFMC\\2109\\", ["Module/plugin tai ve"], "thu muc"),
            ("..\\AgentFMC\\rasoat\\", ["MiAV_Listdlls.exe + .tempcmd.bat + .tempp.pid"], "thu muc"),
            ("C:\\Users\\Public\\Documents\\AgentFMC\\data\\config.ini",
             ["[Time] last_update_hash, [Drive] usb_no_at", "[AppInfo], [Server], [api_log], [Alert], [Event]"], "tep"),
        ]),
        ("TUY CHON", GREEN, [
            ("Lich su trinh duyet", ["Chrome/Edge: History, Login Data, Cookies, Web Data",
                                     "Firefox: places.sqlite, formhistory.sqlite",
                                     "IE: WebCacheV01.dat"], "khong anh huong MiAV"),
            ("DNS cache", ["ipconfig /flushdns"], "khong anh huong MiAV"),
            ("Prefetch / Amcache", ["Xoa thu muc Prefetch, file Amcache.hve"], "khong anh huong MiAV"),
            ("Jump List / RunMRU", ["AutomaticDestinations, TypedPaths, RunMRU"], "khong anh huong MiAV"),
        ]),
    ]

    x = 30
    for title, col, items in cols:
        w = 370
        s.append(box(x, 95, w, 42, title, [], col, 2.5, 14))
        y = 150
        for name, lines, tag in items:
            h = 34 + len(lines) * 16
            s.append('<rect x="%s" y="%s" width="%s" height="%s" rx="5" fill="#FFFFFF" stroke="%s" stroke-width="1.6"/>'
                     % (x, y, w, h, col))
            s.append(text(x + 10, y + 18, name, 11.5, col, "start", "bold", MONO))
            ty = y + 34
            for ln in lines:
                s.append(text(x + 14, ty, ln, 10.5, DARK))
                ty += 16
            s.append(text(x + w - 10, y + 18, tag, 9.5, GREY, "end", "normal", FONT, "font-style:italic"))
            y += h + 10
        x += 390

    s.append(box(30, 700, 1130, 62, "THU TU THUC HIEN", [
        "1. Dung service:  sc stop MiAVProtect / MiAVUpdate / MiAVWD / Defense   (va tat MiAV.exe trong Task Manager)",
        "2. Sao luu c:\\_MiAV_backup\\ roi xoa cac muc BAT BUOC o cot 1",
        "3. Xoa cac muc NEN LAM o cot 2   ->   4. (tuy chon) cot 3",
        "5. Bat lai service va kiem tra: sau khi khoi dong lai, MiAV se tao lai policy.* -> day la dau hieu no da do lai",
    ], "#FDF6E3", YELLOW, 2.5))

    s.append(text(30, 800, "LUU Y QUAN TRONG", 14, RED, "start", "bold"))
    notes = [
        "Xoa log cuc bo KHONG xoa duoc du lieu da gui len server FMS. Cot time_sent trong bang Logs cho biet du lieu nao da di.",
        "Neu may da tung noi Internet, MiAV se TU TAO LAI file policy.* o lan chay ke tiep -> vi vay phai lam sach khi may DA NGAT mang Internet.",
        "Can thoi gian cho du lau (xem bao cao muc 6) de moi su kien da ghi da kip gui di hoac bi xoa.",
        "Moi thao tac phai thuc hien TRUOC khi noi vao mang truyen so lieu quan su.",
    ]
    for i, ln in enumerate(notes):
        s.append(text(40, 822 + i * 18, "- " + ln, 11.5, DARK))

    s.append(svg_tail())
    open(os.path.join(out, "03-ban-do-lam-sach-log.svg"), "w", encoding="utf-8").write("\n".join(s))


def main():
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(out, exist_ok=True)
    diag_arch(out)
    diag_internet(out)
    diag_cleanup(out)
    print("Da sinh 3 SVG vao:", os.path.abspath(out))


if __name__ == "__main__":
    main()
