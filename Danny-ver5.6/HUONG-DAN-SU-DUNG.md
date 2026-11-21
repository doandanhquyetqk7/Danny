# DANNY ver5.6 ΓÇö H╞░ß╗¢ng dß║½n sß╗¡ dß╗Ñng

**Trß╗ú l├╜ C├┤ng nghß╗ç th├┤ng tin**
Phß║ºn mß╗üm ─æ╞░ß╗úc viß║┐t bß╗ƒi **Trung t├í ─Éo├án Danh Quyß║┐t** ΓÇö Trß╗ú l├╜ C├┤ng nghß╗ç th├┤ng tin ΓÇö Cellphone: 0366.714.139

---

## 0. Nß╗Öi dung mß╗¢i cß╗ºa bß║ún 5.6

| # | Thay ─æß╗òi | Chi tiß║┐t |
|---|---|---|
| 1 | **Thay thß║┐ UltraVNC bß║▒ng RustDesk** | Chß╗⌐c n─âng ΓÇ£Hß╗ù trß╗ú kß╗╣ thuß║¡t tß╗½ xaΓÇ¥ chuyß╗ân tß╗½ **UltraVNC 1.4.2.0** sang **RustDesk 1.5.3** ΓÇö **gß╗í sß║ích to├án bß╗Ö m├ú nguß╗ôn, hß║▒ng sß╗æ v├á t├ái nguy├¬n UltraVNC** |
| 2 | **Chß║┐ ─æß╗Ö Direct IP Access ΓÇö 100% OFFLINE** | Kß║┐t nß╗æi **trß╗▒c tiß║┐p** qua ─æß╗ïa chß╗ë IP nß╗Öi bß╗Ö, **kh├┤ng cß║ºn ID Server / Relay Server**, **kh├┤ng cß║ºn Internet** |
| 3 | **Cß╗òng chuß║⌐n 21118** | Thay cho cß╗òng 5500 cß╗ºa UltraVNC ΓÇö cß║Ñu h├¼nh qua `direct-access-port` |
| 4 | **Whitelist IP theo dß║úi CIDR** | ├ö ΓÇ£Whitelist IP (dß║úi CIDR)ΓÇ¥, **mß║╖c ─æß╗ïnh `86.134.32.150/24`** (dß║úi IP quß║ún trß╗ï), **ng╞░ß╗¥i d├╣ng sß╗¡a tay ─æ╞░ß╗úc** |
| 5 | **X├íc nhß║¡n an to├án bß║»t buß╗Öc** | `approve-mode = click` ΓÇö m├íy cß║ºn hß╗ù trß╗ú phß║úi **bß║Ñm ΓÇ£─Éß╗ông ├╜ΓÇ¥** mß╗¢i cho ph├⌐p kß║┐t nß╗æi; k├¿m `use-temporary-password` |
| 6 | **C├ái RustDesk th├ánh service (--install-service)** | C├│ quyß╗ün Admin ΓåÆ c├ái service + thao t├íc ─æ╞░ß╗úc tr├¬n **cß╗¡a sß╗ò UAC**; kh├┤ng c├│ quyß╗ün ΓåÆ tß╗▒ l├╣i vß╗ü portable + cß║únh b├ío nhß║╣ |
| 7 | **Tß╗▒ ─æß╗Öng mß╗ƒ/─æ├│ng Firewall an to├án** | Bß║¡t ΓåÆ tß║ío rule inbound TCP 21118 (**kho├í theo RemoteAddress** cß╗ºa whitelist); Dß╗½ng ΓåÆ **xo├í ngay rule** |
| 8 | **Gß╗í bß╗Å ho├án to├án DSM/UltraVNC** | Kh├┤ng c├▓n `ultravnc.ini`, `winvnc`, `vncviewer`, plugin `.dsm`, cß╗òng 5500/5900 |
| 9 | **Cß╗¥ CLI mß╗¢i `--whitelist`** | `--remote-listen` / `--remote-connect` nay nhß║¡n th├¬m dß║úi IP cho ph├⌐p |
| 10 | **Ghi log ─æß║ºy ─æß╗º, bß╗ìc try/catch** | Mß╗ìi thao t├íc hß╗ç thß╗æng (ghi TOML, `netsh`, c├ái service, khß╗ƒi tiß║┐n tr├¼nh) ─æß╗üu c├│ log lß╗ùi r├╡ r├áng |

> Bß║ún 5.6 kß║┐ thß╗½a to├án bß╗Ö t├¡nh n─âng cß╗ºa bß║ún 5.5 v├á thay **duy nhß║Ñt** module hß╗ù trß╗ú tß╗½ xa.

---

## 1. Cß║Ñu tr├║c bß╗Ö c├ái ─æß║╖t

```
Danny-ver5.6/
Γö£ΓöÇΓöÇ Danny-ver5.6.exe            69,16 MB  ΓåÉ bß║ún khuyß║┐n nghß╗ï (chß║íy ─æ╞░ß╗úc mß╗ìi m├íy)
Γö£ΓöÇΓöÇ Danny-ver5.6-nethost.exe     1,41 MB  ΓåÉ bß║ún nhß║╣ (cß║ºn .NET 8 Desktop Runtime)
Γö£ΓöÇΓöÇ tools\
Γöé   Γö£ΓöÇΓöÇ KVRT.exe               116,28 MB  ΓåÉ Kaspersky Virus Removal Tool
Γöé   ΓööΓöÇΓöÇ RustDesk\                          ΓåÉ bß╗Ö c├┤ng cß╗Ñ hß╗ù trß╗ú tß╗½ xa
Γöé       Γö£ΓöÇΓöÇ rustdesk.exe            25,02 MB  ΓåÉ RustDesk client 1.5.3 (chß║┐ ─æß╗Ö Direct IP)
Γöé       ΓööΓöÇΓöÇ server\                          ΓåÉ RustDesk Server tß╗▒ host (t├╣y chß╗ìn)
Γöé           Γö£ΓöÇΓöÇ hbbs.exe             6,77 MB  ΓåÉ ID server
Γöé           Γö£ΓöÇΓöÇ hbbr.exe             2,77 MB  ΓåÉ Relay server
Γöé           ΓööΓöÇΓöÇ rustdesk-utils.exe   0,40 MB  ΓåÉ sinh cß║╖p kho├í server
ΓööΓöÇΓöÇ HUONG-DAN-SU-DUNG.md
```

> **Bß║»t buß╗Öc:** giß╗» nguy├¬n th╞░ mß╗Ñc `tools\` cß║ính file `.exe` (─æß║╖c biß╗çt `tools\RustDesk\`).
> Tab ΓÇ£Hß╗ù trß╗ú kß╗╣ thuß║¡t tß╗½ xaΓÇ¥ sß║╜ b├ío r├╡ r├áng nß║┐u kh├┤ng t├¼m thß║Ñy `rustdesk.exe`.

| File | D├╣ng khi n├áo |
|---|---|
| **Danny-ver5.6.exe** | M├íy ch╞░a c├ái .NET ΓÇö **khuyß║┐n nghß╗ï d├╣ng bß║ún n├áy** |
| Danny-ver5.6-nethost.exe | M├íy ─æ├ú c├│ .NET 8 Desktop Runtime (khß╗ƒi ─æß╗Öng nhanh h╞ín ~1 gi├óy) |

---

## 2. Y├¬u cß║ºu hß╗ç thß╗æng

- Windows 10 / Windows 11 (32-bit hoß║╖c 64-bit)
- **Quyß╗ün Administrator** ΓÇö phß║ºn mß╗üm tß╗▒ y├¬u cß║ºu (biß╗âu t╞░ß╗úng UAC)
- Hai m├íy phß║úi **c├╣ng nß║▒m trong mß╗Öt mß║íng LAN** (mß║íng nß╗Öi bß╗Ö ─æ╞ín vß╗ï)
- Dung l╞░ß╗úng trß╗æng tß╗æi thiß╗âu: ~220 MB (Kaspersky 116 MB + RustDesk 25 MB + bß║ún sao l╞░u)

---

## 3. Mß╗ƒ phß║ºn mß╗üm

Nhß║Ñp ─æ├║p `Danny-ver5.6.exe` ΓåÆ chß║Ñp thuß║¡n quyß╗ün Administrator ΓåÆ phß║ºn mß╗üm hiß╗çn **7 tab**:

| # | Tab | Chß╗⌐c n─âng |
|---|---|---|
| 1 | **KIß╗éM TRA Kß║╛T Nß╗ÉI** | Chß║⌐n ─æo├ín 4 b╞░ß╗¢c, tra cß╗⌐u 130 ─æ╞ín vß╗ï, xuß║Ñt b├ío c├ío |
| 2 | **USB AN TO├ÇN 2.6** | Tß║ío USB an to├án cho MiAV (kh├┤ng bß╗ï chß║╖n ß╗ƒ tß║ºng kernel) |
| 3 | **Cß║ñU H├îNH IP Mß╗ÿT CHß║áM** | ─Éß║╖t IP t─⌐nh LAN ─æ├║ng dß║úi ─æ╞ín vß╗ï, c├│ rollback |
| 4 | **Cß║ñU H├îNH Mß║áNG** | Cß║Ñu h├¼nh IP/DNS thß╗º c├┤ng |
| 5 | **L├ÇM Sß║áCH PC Mß╗ÿT CHß║áM** | Quy tr├¼nh vß╗ç sinh tß╗▒ ─æß╗Öng + qu├⌐t virus + c├ái lß║íi MiAV |
| 6 | **Hß╗û TRß╗ó Kß╗╕ THUß║¼T Tß╗¬ XA** | Kß║┐t nß╗æi/─æiß╗üu khiß╗ân m├íy t├¡nh tß╗½ xa bß║▒ng **RustDesk Direct IP** |
| 7 | **Bß║óO Mß║¼T & TIß╗åN ├ìCH** | Chß║íy KVRT thß╗º c├┤ng, x├│a Event Viewer, hiß╗çn file ß║⌐n |

---

## 4. TAB ΓÇ£Hß╗û TRß╗ó Kß╗╕ THUß║¼T Tß╗¬ XAΓÇ¥

### 4.1. Nguy├¬n tß║»c hoß║ít ─æß╗Öng ΓÇö Direct IP Access (100% offline)

Chß╗⌐c n─âng dß╗▒a tr├¬n **RustDesk 1.5.3** ß╗ƒ chß║┐ ─æß╗Ö **Direct IP Access**:

```
        M├üY NHß║¼N Kß║╛T Nß╗ÉI                          M├üY Cß║ªN Hß╗û TRß╗ó
        (m├íy kß╗╣ thuß║¡t vi├¬n)                      (m├íy qu├ón sß╗▒)
        ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ                      ΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇΓöÇ
        rustdesk.exe --server             ΓöÇΓöÇΓû║     rustdesk.exe --connect
        (mß╗ƒ listener TCP 21118)                    <IP-m├íy-KT>:21118
                                                  (kß║┐t nß╗æi TRß╗░C TIß║╛P)
```

**─Éiß╗âm kh├íc biß╗çt quan trß╗ìng so vß╗¢i UltraVNC:**

| | UltraVNC (ver5.5) | RustDesk (ver5.6) |
|---|---|---|
| Chß║┐ ─æß╗Ö | Reverse connection (kß║┐t nß╗æi ng╞░ß╗úc) | **Direct IP Access** ΓÇö kß║┐t nß╗æi thß║│ng |
| Cß║ºn Internet / ID Server | Kh├┤ng | **Kh├┤ng ΓÇö 100% offline** |
| Cß╗òng | 5500 | **21118** |
| X├íc nhß║¡n | Mß║¡t khß║⌐u VNC | **Xin ph├⌐p thß╗º c├┤ng (click)** + mß║¡t khß║⌐u tß║ím thß╗¥i |
| M├ú ho├í | Plugin DSM (`.dsm`) | **RustDesk m├ú ho├í sß║╡n (chß║╖t h╞ín)** |
| Lß╗ìc IP theo nguß╗ôn | Kh├┤ng | **Whitelist IP/CIDR (kho├í firewall)** |

> **L╞░u ├╜:** Trong cß╗¡a sß╗ò RustDesk, trß║íng th├íi **ΓÇ£Not readyΓÇ¥** hiß╗ân thß╗ï bß║▒ng **chß╗» ─æß╗Å**
> l├á **B├îNH TH╞»ß╗£NG** khi chß║íy offline ß╗ƒ chß║┐ ─æß╗Ö Direct IP ΓÇö ─æ├óy l├á trß║íng th├íi ΓÇ£ch╞░a ─æ─âng nhß║¡p
> ─æ╞░ß╗úc ID serverΓÇ¥, **kh├┤ng phß║úi lß╗ùi**. Phi├¬n kß║┐t nß╗æi trß╗▒c tiß║┐p vß║½n hoß║ít ─æß╗Öng b├¼nh th╞░ß╗¥ng.

### 4.2. Giao diß╗çn

| Th├ánh phß║ºn | ├¥ ngh─⌐a |
|---|---|
| **M├üY NHß║¼N Kß║╛T Nß╗ÉI** | Chß╗ìn khi m├íy n├áy l├á m├íy cß╗ºa kß╗╣ thuß║¡t vi├¬n (sß║╜ chß╗¥ ng╞░ß╗¥i d├╣ng gß╗ìi tß╗¢i) |
| **M├üY Cß║ªN Hß╗û TRß╗ó** | Chß╗ìn khi m├íy n├áy cß║ºn ─æ╞░ß╗úc hß╗ù trß╗ú (sß║╜ gß╗ìi tß╗¢i m├íy kß╗╣ thuß║¡t vi├¬n) |
| **IP m├íy cß║ºn hß╗ù trß╗ú** | Chß╗ë d├╣ng ß╗ƒ chß║┐ ─æß╗Ö *M├íy cß║ºn hß╗ù trß╗ú* ΓÇö nhß║¡p IP hoß║╖c `IP:Port` cß╗ºa m├íy kß╗╣ thuß║¡t vi├¬n |
| **Mß║¡t khß║⌐u** | Mß║¡t khß║⌐u RustDesk (tß║ím thß╗¥i hoß║╖c th╞░ß╗¥ng) ΓÇö ─æß╗â truyß╗ün cho lß╗çnh `--connect` |
| **Whitelist IP (dß║úi CIDR)** | Danh s├ích IP ─æ╞░ß╗úc ph├⌐p kß║┐t nß╗æi. **Mß║╖c ─æß╗ïnh `86.134.32.150/24`**, sß╗¡a tay ─æ╞░ß╗úc. ─Éß╗â trß╗æng = kh├┤ng giß╗¢i hß║ín |
| **Cß╗òng Direct IP** | Mß║╖c ─æß╗ïnh **21118** ΓÇö sß╗¡a ─æ╞░ß╗úc nß║┐u tr├╣ng cß╗òng |
| **Xin ph├⌐p thß╗º c├┤ng** | Mß║╖c ─æß╗ïnh **Bß║¼T** (`approve-mode=click`) ΓÇö m├íy b├¬n kia phß║úi bß║Ñm ΓÇ£─Éß╗ông ├╜ΓÇ¥ |
| **C├ái RustDesk th├ánh service** | ─Éß╗â hß╗ù trß╗ú ─æ╞░ß╗úc cß║ú khi ─æ├ú ─æ─âng xuß║Ñt Windows + thao t├íc ─æ╞░ß╗úc cß╗¡a sß╗ò UAC |
| **Tß║ío shortcut tr├¬n Desktop** | Tß║ío lß╗æi tß║»t ΓÇ£RustDesk - Bß║¡t hß╗ù trß╗ú tß╗½ xaΓÇ¥ |
| **IP m├íy n├áy (LAN)** | IP tß╗▒ ─æß╗Öng d├▓ tß╗½ card mß║íng vß║¡t l├╜ (bß╗Å qua card ß║úo/loopback/APIPA) ΓÇö n├║t **ΓÇ£Ch├⌐p IPΓÇ¥** |

### 4.3. QUY TR├îNH A ΓÇö M├íy NHß║¼N kß║┐t nß╗æi (m├íy kß╗╣ thuß║¡t vi├¬n)

**B╞░ß╗¢c 1.** Mß╗ƒ tab **Hß╗û TRß╗ó Kß╗╕ THUß║¼T Tß╗¬ XA** ΓåÆ chß╗ìn **ΓÇ£M├üY NHß║¼N Kß║╛T Nß╗ÉIΓÇ¥**.

**B╞░ß╗¢c 2.** Kiß╗âm tra ├┤ **ΓÇ£IP m├íy n├áy (LAN)ΓÇ¥** ΓÇö ─æ├óy l├á ─æß╗ïa chß╗ë bß║ín sß║╜ gß╗¡i cho ng╞░ß╗¥i d├╣ng.
Nhß║Ñn **ΓÇ£Ch├⌐p IPΓÇ¥** ─æß╗â copy v├áo clipboard.

**B╞░ß╗¢c 3.** Kiß╗âm tra ├┤ **ΓÇ£Whitelist IP (dß║úi CIDR)ΓÇ¥** ΓÇö mß║╖c ─æß╗ïnh `86.134.32.150/24`.
Sß╗¡a nß║┐u dß║úi IP quß║ún trß╗ï cß╗ºa ─æ╞ín vß╗ï kh├íc. Cß╗òng Direct IP mß║╖c ─æß╗ïnh `21118`.

**B╞░ß╗¢c 4.** Nhß║Ñn **ΓÇ£Bß║¼T Hß╗û TRß╗ó Tß╗¬ XAΓÇ¥**. Phß║ºn mß╗üm tß╗▒ ─æß╗Öng thß╗▒c hiß╗çn **4 b╞░ß╗¢c**:

```
B╞»ß╗ÜC 1  Mß╗ƒ cß╗òng TCP 21118 trong Windows Defender Firewall
         netsh advfirewall firewall add rule
           name="Danny RustDesk Direct IP TCP 21118"
           dir=in action=allow protocol=TCP localport=21118
           profile=any remoteip=86.134.32.150/24

B╞»ß╗ÜC 2  Ghi cß║Ñu h├¼nh Direct IP Access v├áo RustDesk2.toml
         %APPDATA%\RustDesk\config\RustDesk2.toml   (chß║┐ ─æß╗Ö User)
         C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\
              RustDesk\config\RustDesk2.toml          (chß║┐ ─æß╗Ö Service)

         [options]
         direct-server = 'Y'
         direct-access-port = '21118'
         enable-lan-discovery = 'N'
         whitelist = '86.134.32.150/24'
         approve-mode = 'click'
         verification-method = 'use-temporary-password'

B╞»ß╗ÜC 3  Tß║ío shortcut tr├¬n Desktop:
         "RustDesk - Bß║¡t hß╗ù trß╗ú tß╗½ xa.lnk"
         Target: ...\tools\RustDesk\rustdesk.exe
         Args  : --server

B╞»ß╗ÜC 4  C├ái RustDesk th├ánh service + khß╗ƒi ─æß╗Öng
         rustdesk.exe --install-service
         (ImagePath ─æ╞░ß╗úc trß╗Å lß║íi vß╗ü bß║ún ─æ├ú giß║úi n├⌐n trong %LOCALAPPDATA%\rustdesk\)
         sc start RustDesk
         ΓåÆ ─æß╗úi ─æß║┐n khi cß╗òng 21118 thß╗▒c sß╗▒ lß║»ng nghe (tß╗æi ─æa 15 gi├óy)
```

**B╞░ß╗¢c 5.** Chß╗¥ th├┤ng b├ío **ΓÇ£DA SAN SANG NHAN KET NOI tren cong 21118ΓÇ¥**.

**B╞░ß╗¢c 6.** Gß╗¡i cho ng╞░ß╗¥i d├╣ng: **IP** cß╗ºa bß║ín + **cß╗òng 21118**.

> Nß║┐u kh├┤ng nhß║¡n ─æ╞░ß╗úc kß║┐t nß╗æi: nhß║Ñn **ΓÇ£Dß╗¬NG / Dß╗ìn Dß║╕PΓÇ¥** rß╗ôi **ΓÇ£Bß║¼T Hß╗û TRß╗ó Tß╗¬ XAΓÇ¥** lß║íi.

### 4.4. QUY TR├îNH B ΓÇö M├íy Cß║ªN hß╗ù trß╗ú (m├íy qu├ón sß╗▒)

**B╞░ß╗¢c 1.** Mß╗ƒ tab ΓåÆ chß╗ìn **ΓÇ£M├üY Cß║ªN Hß╗û TRß╗óΓÇ¥**.

**B╞░ß╗¢c 2.** Nhß║¡p **IP m├íy kß╗╣ thuß║¡t vi├¬n** v├áo ├┤ b├¬n tr├íi.
C├│ thß╗â nhß║¡p dß║íng `86.134.32.55` hoß║╖c `86.134.32.55:21118` (nß║┐u m├íy kia d├╣ng cß╗òng kh├íc).
Nhß║¡p **mß║¡t khß║⌐u** RustDesk nß║┐u m├íy kia y├¬u cß║ºu.

**B╞░ß╗¢c 3.** Nhß║Ñn **ΓÇ£Bß║¼T Hß╗û TRß╗ó Tß╗¬ XAΓÇ¥**. Phß║ºn mß╗üm tß╗▒ ─æß╗Öng thß╗▒c hiß╗çn **4 b╞░ß╗¢c**:

```
B╞»ß╗ÜC 1  Mß╗ƒ cß╗òng TCP 21118 trong Windows Defender Firewall

B╞»ß╗ÜC 2  Ghi cß║Ñu h├¼nh Direct IP Access v├áo RustDesk2.toml

B╞»ß╗ÜC 3  C├ái RustDesk th├ánh service (nß║┐u c├│ quyß╗ün Admin):
         rustdesk.exe --install-service
         sc start RustDesk
         (kh├┤ng c├│ quyß╗ün Admin ΓåÆ chß║íy portable + cß║únh b├ío nhß║╣)

B╞»ß╗ÜC 4  Mß╗ƒ phi├¬n kß║┐t nß╗æi trß╗▒c tiß║┐p:
         rustdesk.exe --connect <IP>:<Port> [--password <mß║¡t khß║⌐u>]
```

**B╞░ß╗¢c 4.** M├án h├¼nh m├íy n├áy sß║╜ hiß╗çn tr├¬n m├íy kß╗╣ thuß║¡t vi├¬n trong v├ái gi├óy.

> Nß║┐u m├íy kia bß║¡t ΓÇ£Xin ph├⌐p thß╗º c├┤ngΓÇ¥, ng╞░ß╗¥i d├╣ng phß║úi **bß║Ñm ΓÇ£─Éß╗ông ├╜ΓÇ¥** tr├¬n cß╗¡a sß╗ò
> RustDesk ΓÇö ─æ├óy l├á c╞í chß║┐ x├íc nhß║¡n an to├án bß║»t buß╗Öc.

### 4.5. Xß╗¡ l├╜ sß╗▒ cß╗æ

| Hiß╗çn t╞░ß╗úng | Nguy├¬n nh├ón | Khß║»c phß╗Ñc |
|---|---|---|
| ΓÇ£Kh├┤ng t├¼m thß║Ñy rustdesk.exeΓÇ¥ | Thiß║┐u th╞░ mß╗Ñc `tools\RustDesk` | Ch├⌐p lß║íi ─æß║ºy ─æß╗º `tools\RustDesk` tß╗½ bß╗Ö c├ái |
| ΓÇ£Cß╗òng 21118 ch╞░a sß║╡n s├ángΓÇ¥ | Firewall hoß║╖c RustDesk ch╞░a bind xong | Nhß║Ñn ΓÇ£Dß╗¬NG / Dß╗ìn Dß║╕PΓÇ¥ ΓåÆ ΓÇ£Bß║¼T Hß╗û TRß╗ó Tß╗¬ XAΓÇ¥ lß║íi |
| ΓÇ£Kh├┤ng khß╗ƒi ─æß╗Öng ─æ╞░ß╗úc service RustDeskΓÇ¥ | Bß║ún portable tß╗▒ giß║úi n├⌐n ch╞░a bung xong | Chß║íy `rustdesk.exe --server` mß╗Öt lß║ºn cho n├│ bung file, rß╗ôi thß╗¡ lß║íi |
| M├íy kia kh├┤ng thß║Ñy m├án h├¼nh | Sai IP / sai cß╗òng | Kiß╗âm tra lß║íi IP m├íy kß╗╣ thuß║¡t vi├¬n v├á cß╗òng ß╗ƒ cß║ú 2 ─æß║ºu |
| Kß║┐t nß╗æi bß╗ï tß╗½ chß╗æi | IP kß╗╣ thuß║¡t vi├¬n kh├┤ng nß║▒m trong whitelist | Th├¬m IP v├áo ├┤ Whitelist (hoß║╖c ─æß╗â trß╗æng) rß╗ôi chß║íy lß║íi |
| RustDesk hiß╗çn ΓÇ£Not readyΓÇ¥ ─æß╗Å | B├¼nh th╞░ß╗¥ng khi offline Direct IP | **Kh├┤ng phß║úi lß╗ùi** ΓÇö kß║┐t nß╗æi trß╗▒c tiß║┐p vß║½n chß║íy |
| Kh├┤ng ─æiß╗üu khiß╗ân ─æ╞░ß╗úc khi ─æ├ú ─æ─âng xuß║Ñt | Ch╞░a c├ái service | Bß║¡t t├╣y chß╗ìn ΓÇ£C├ái RustDesk th├ánh serviceΓÇ¥ |
| Kh├┤ng thao t├íc ─æ╞░ß╗úc cß╗¡a sß╗ò UAC | Chß║íy Danny kh├┤ng c├│ quyß╗ün Admin | Chß║íy lß║íi Danny vß╗¢i quyß╗ün Administrator |

### 4.6. Bß║úo mß║¡t phi├¬n l├ám viß╗çc

- **ΓÇ£Xin ph├⌐p thß╗º c├┤ngΓÇ¥ lu├┤n Bß║¼T** ΓÇö kh├┤ng bao giß╗¥ ─æß╗â truy cß║¡p tß╗▒ do kh├┤ng x├íc nhß║¡n.
- **Whitelist IP** giß╗¢i hß║ín chß╗ë IP/CIDR ─æ╞░ß╗úc ph├⌐p kß║┐t nß╗æi; rule firewall c┼⌐ng kho├í theo
  `RemoteAddress` t╞░╞íng ß╗⌐ng ΓåÆ IP ngo├ái danh s├ích bß╗ï chß║╖n ß╗ƒ **tß║ºng firewall**, kh├┤ng v├áo tß╗¢i RustDesk.
- **Mß║¡t khß║⌐u RustDesk** d├╣ng thay mß║¡t khß║⌐u Windows; `verification-method =
  use-temporary-password` d├╣ng mß║¡t khß║⌐u tß║ím thß╗¥i (─æß╗òi mß╗ùi lß║ºn khß╗ƒi ─æß╗Öng).
- **Chß╗ë d├╣ng trong mß║íng nß╗Öi bß╗Ö** cß╗ºa ─æ╞ín vß╗ï; **kh├┤ng** mß╗ƒ cß╗òng 21118 ra Internet / kh├┤ng
  forward cß╗òng tr├¬n router.
- Sau khi hß╗ù trß╗ú xong, nhß║Ñn **ΓÇ£Dß╗¬NG / Dß╗ìn Dß║╕PΓÇ¥** ─æß╗â **dß╗½ng tiß║┐n tr├¼nh RustDesk** v├á
  **xo├í rule firewall** ΓåÆ kh├┤ng ─æß╗â hß╗ƒ cß╗òng tr├¬n m├íy trß║ím.

---

## 5. CLI (chß║┐ ─æß╗Ö kh├┤ng giao diß╗çn)

```
Danny-ver5.6.exe --remote-listen [--port 21118] [--whitelist "86.134.32.150/24"]
    :: M├íy nhß║¡n kß║┐t nß╗æi ΓÇö mß╗ƒ firewall, cß║Ñu h├¼nh Direct IP, tß║ío shortcut, chß║íy RustDesk

Danny-ver5.6.exe --remote-connect --ip 86.134.32.55 [--port 21118] [--whitelist "..."] [--no-service]
    :: M├íy cß║ºn hß╗ù trß╗ú ΓÇö mß╗ƒ firewall, cß║Ñu h├¼nh Direct IP v├á mß╗ƒ phi├¬n kß║┐t nß╗æi trß╗▒c tiß║┐p
```

| Cß╗¥ | ├¥ ngh─⌐a |
|---|---|
| `--port <sß╗æ>` | Cß╗òng Direct IP (mß║╖c ─æß╗ïnh **21118**) |
| `--ip <─æß╗ïa chß╗ë>` | IP m├íy cß║ºn hß╗ù trß╗ú (bß║»t buß╗Öc vß╗¢i `--remote-connect`) |
| `--whitelist "<dß║úi>"` | Dß║úi IP/CIDR ─æ╞░ß╗úc ph├⌐p kß║┐t nß╗æi (mß║╖c ─æß╗ïnh `86.134.32.150/24`) |
| `--no-service` | Kh├┤ng c├ái RustDesk th├ánh service (chß╗ë chß║íy khi ─æang ─æ─âng nhß║¡p) |

> **L╞░u ├╜:** Phß║ºn CLI in ra **ASCII thuß║ºn** (─æ├ú bß╗Å dß║Ñu tiß║┐ng Viß╗çt) ─æß╗â hiß╗ân thß╗ï ─æ├║ng
> tr├¬n mß╗ìi m├ú trang cß╗ºa Windows Console.

C├íc lß╗çnh CLI kh├íc cß╗ºa bß║ún 5.0 vß║½n giß╗» nguy├¬n:
`--make-safe "X:\"`, `--check "X:\"`, `--diag [--full]`, `--clean`.

---

## 6. Quy tr├¼nh ΓÇ£L├ám sß║ích PC mß╗Öt chß║ímΓÇ¥ (giß╗» nguy├¬n tß╗½ bß║ún 5.0)

```
 1  Kiß╗âm tra trß║íng th├íi Internet            8  X├│a NH├ôM B (artifact MiAV)
 2  Kiß╗âm k├¬ d├▓ng Logs type='Internet'       9  X├íc minh
 3  Sao l╞░u AgentFMC                       10  Bß║¡t lß║íi 4 service MiAV
 4  Dß╗½ng 4 service MiAV                    11  Kaspersky KVRT ΓÇö qu├⌐t to├án bß╗Ö ß╗ò + khß╗¡ nhiß╗àm
 5  Dß╗½ng tiß║┐n tr├¼nh GUI MiAV               12  Γÿà C├ái lß║íi MiAV (SetupMiAV.exe /VERYSILENT)
 6  X├│a NH├ôM A (bß║úng Logs, policy.*)      13  B├ío c├ío CSV ΓåÆ Khß╗ƒi ─æß╗Öng lß║íi m├íy
 7  X├│a NH├ôM C (browser, SRUM, DNSΓÇª)
```

---

## 7. Ghi ch├║ kß╗╣ thuß║¡t

### 7.1. RustDesk 1.5.3 ΓÇö th├ánh phß║ºn

| Th├ánh phß║ºn | Nguß╗ôn |
|---|---|
| `rustdesk.exe` | Bß║ún ph├ón phß╗æi ch├¡nh thß╗⌐c `rustdesk-1.5.3-x86_64.exe` ΓÇö giß║Ñy ph├⌐p AGPL-3.0 |
| `hbbs.exe`, `hbbr.exe`, `rustdesk-utils.exe` | Bß║ún ph├ón phß╗æi ch├¡nh thß╗⌐c `rustdesk-server-windows-x86_64-unsigned.zip` (v1.1.16) |

### 7.2. Cß║Ñu h├¼nh `RustDesk2.toml` ΓÇö khß╗æi `[options]`

RustDesk t├ích cß║Ñu h├¼nh th├ánh **3 file** (`hbb_common/src/config.rs`):

| File | Nß╗Öi dung | Danny c├│ sß╗¡a? |
|---|---|---|
| `RustDesk.toml` | `Config` ΓÇö kho├í, `enc_id` | **Kh├┤ng** |
| `RustDesk2.toml` | `Config2` ΓÇö **khß╗æi `[options]`** | **C├│** |
| `RustDesk_local.toml` | `LocalConfig` ΓÇö giao diß╗çn | **Kh├┤ng** |

| Kho├í | Gi├í trß╗ï mß║╖c ─æß╗ïnh | ├¥ ngh─⌐a |
|---|---|---|
| `direct-server` | `Y` | Bß║¡t chß║┐ ─æß╗Ö nhß║¡n kß║┐t nß╗æi trß╗▒c tiß║┐p qua IP |
| `direct-access-port` | `21118` | Cß╗òng Direct IP Access |
| `enable-lan-discovery` | `N` | Tß║»t ph├ít hiß╗çn tr├¬n LAN (chß╗ë d├╣ng IP trß╗▒c tiß║┐p) |
| `whitelist` | `86.134.32.150/24` | Dß║úi IP ─æ╞░ß╗úc ph├⌐p (hß╗ù trß╗ú CIDR, ph├ón t├ích bß║▒ng dß║Ñu phß║⌐y) |
| `approve-mode` | `click` | `click` = phß║úi xin ph├⌐p thß╗º c├┤ng, `password`, `password-click` |
| `verification-method` | `use-temporary-password` | Loß║íi mß║¡t khß║⌐u ─æ╞░ß╗úc chß║Ñp nhß║¡n |

**Th╞░ mß╗Ñc config theo chß║┐ ─æß╗Ö chß║íy:**

| Chß║┐ ─æß╗Ö | ─É╞░ß╗¥ng dß║½n |
|---|---|
| User | `%APPDATA%\RustDesk\config\RustDesk2.toml` |
| Service | `C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml` |

### 7.3. Lß╗çnh d├▓ng lß╗çnh RustDesk ─æ├ú d├╣ng

| Lß╗çnh | ├¥ ngh─⌐a |
|---|---|
| `rustdesk.exe --server` | Chß║íy nß╗ün ß╗ƒ chß║┐ ─æß╗Ö chia sß║╗ m├án h├¼nh (mß╗ƒ listener Direct IP) |
| `rustdesk.exe --connect <IP>:<Port>` | Mß╗ƒ phi├¬n kß║┐t nß╗æi trß╗▒c tiß║┐p tß╗¢i IP:Port |
| `rustdesk.exe --connect <IP>:<Port> --password <pw>` | Kß║┐t nß╗æi k├¿m mß║¡t khß║⌐u |
| `rustdesk.exe --install-service` | C├ái Windows Service (tß╗▒ chß║íy khi khß╗ƒi ─æß╗Öng m├íy) |
| `rustdesk.exe --uninstall-service` | Gß╗í Windows Service |
| `rustdesk-utils.exe genkeypair` | Sinh cß║╖p kho├í c├┤ng khai/ri├¬ng cho server tß╗▒ host |

> **─É├ú x├íc minh trong m├ú nguß╗ôn RustDesk** (`hbb_common/src/lib.rs`):
> `is_ipv4_str()` chß║Ñp nhß║¡n dß║íng `IP:port`, v├á `check_port()` giß╗» nguy├¬n cß╗òng ─æ├ú chß╗ë ─æß╗ïnh ΓÇö
> n├¬n `--connect <IP>:<Port>` l├á **─æ├║ng c├║ ph├íp**, kh├┤ng cß║ºn ID Server.
> Log x├íc nhß║¡n: `Direct server listening on: Some(Ok(0.0.0.0:21118))` v├á
> `direct access from <IP>:<ephemeral>`.

### 7.4. Xß╗¡ l├╜ Windows Service ΓÇö ─æiß╗âm mß║Ñu chß╗æt ─æ├ú kiß╗âm chß╗⌐ng

Hai ─æiß╗âm dß╗à sai khi c├ái RustDesk l├ám service tr├¬n bß║ún portable:

1. **`--install-service` lu├┤n ghi ImagePath l├á**
   `"C:\Program Files\RustDesk\RustDesk.exe"` kß╗â cß║ú khi chß║íy bß║ún portable.
   ΓåÆ Danny tß╗▒ **trß╗Å lß║íi ImagePath** qua registry
   `HKLM\SYSTEM\CurrentControlSet\Services\RustDesk`.

2. **File `rustdesk.exe` ─æi k├¿m Danny l├á bß║ún portable tß╗▒ giß║úi n├⌐n (25 MB).**
   Khi SCM khß╗ƒi ─æß╗Öng n├│, tiß║┐n tr├¼nh bung file rß╗ôi **tho├ít ngay** ΓåÆ SCM b├ío
   **timeout 180 gi├óy** v├á service kh├┤ng bao giß╗¥ chß║íy.
   ΓåÆ Danny trß╗Å ImagePath vß╗ü **bß║ún ─æ├ú giß║úi n├⌐n** (~386 KB) trong
   `%LOCALAPPDATA%\rustdesk\rustdesk.exe` (n╞íi c├│ `librustdesk.dll` v├á c├íc plugin).

### 7.5. Nhß║¡t k├╜ & b├ío c├ío

- Nhß║¡t k├╜ thao t├íc nß║▒m trong ├┤ log m├áu xanh cß╗ºa tab.
- Cß║Ñu h├¼nh RustDesk c├│ thß╗â mß╗ƒ ─æß╗â kiß╗âm tra:
  `%APPDATA%\RustDesk\config\RustDesk2.toml`.
- Rule firewall do phß║ºn mß╗üm tß║ío c├│ t├¬n `Danny RustDesk Direct IP TCP <port>`.
- Log chi tiß║┐t cß╗ºa RustDesk: `%APPDATA%\RustDesk\log\server\rustdesk_rCURRENT.log`
  (t├¼m d├▓ng `Direct server listening` v├á `direct access from`).

---

## 8. Kß╗ïch bß║ún kiß╗âm thß╗¡ nhanh

```powershell
# 1. Mß╗ƒ/─æ├│ng cß╗òng
Test-NetConnection -ComputerName 127.0.0.1 -Port 21118

# 2. Kiß╗âm tra rule firewall
Get-NetFirewallRule -DisplayName "Danny RustDesk*"

# 3. Test tß╗▒ ─æß╗Öng dß╗ìn rule firewall khi tho├ít app
#    ΓåÆ bß║Ñm "Dß╗¬NG / Dß╗ìn Dß║╕P" ΓåÆ Get-NetFirewallRule -DisplayName "Danny RustDesk*" phß║úi rß╗ùng

# 4. Test kß║┐t nß╗æi giß╗»a 2 m├íy kh├íc ph├ón mß║íng
#    M├íy A (kß╗╣ thuß║¡t vi├¬n): chß╗ìn M├üY NHß║¼N Kß║╛T Nß╗ÉI ΓåÆ Bß║¼T Hß╗û TRß╗ó Tß╗¬ XA ΓåÆ ch├⌐p IP
#    M├íy B (qu├ón sß╗▒):       chß╗ìn M├üY Cß║ªN Hß╗û TRß╗ó ΓåÆ nhß║¡p IP cß╗ºa A ΓåÆ Bß║¼T Hß╗û TRß╗ó Tß╗¬ XA
```

---

## 9. Th├┤ng tin li├¬n hß╗ç

| | |
|---|---|
| **T├íc giß║ú** | Trung t├í ─Éo├án Danh Quyß║┐t ΓÇö Trß╗ú l├╜ C├┤ng nghß╗ç th├┤ng tin |
| **─É╞ín vß╗ï** | Bß╗Ö Chß╗ë huy Qu├ón sß╗▒ tß╗ënh L├óm ─Éß╗ông |
| **─Éiß╗çn thoß║íi** | 0366.714.139 |
| **M├ú nguß╗ôn** | https://github.com/doandanhquyetqk7/Danny |
| **Theo d├╡i phi├¬n bß║ún** | https://github.com/users/doandanhquyetqk7/projects/1 |
