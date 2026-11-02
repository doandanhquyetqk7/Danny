# Scope — MiAV 4.1.1.2 & USB An Toàn 2.6 USB management mechanism

## auth
- status: granted
- auth_basis: User directly supplied both installers (`SetupMiAV.exe`, `USB_AnToan_BTL86_Setup(2).exe`) and requested reverse engineering to understand the USB monitoring/management relationship.
- target_type: Two proprietary Windows PE installers (Inno Setup), Vietnamese government/defence endpoint-security product.
- operation: Read-only static analysis. Installers are unpacked but NEVER executed. No driver installed, no registry modified, no service started, no network traffic.

## network_profile
- mode: offline
- notes: No network calls were made at any point; no target infrastructure was contacted.

## in_scope
- assets:
  - SetupMiAV.exe
  - USB_AnToan_BTL86_Setup(2).exe
  - ext/MiAV/{app}/MiAV.exe
  - ext/MiAV/{app}/MiAV_Protect.exe
  - ext/MiAV/{app}/SerDefense.exe
  - ext/MiAV/{app}/MiAV_WD.exe
  - ext/MiAV/{app}/MiAV_Update.exe
  - ext/USB/app/USB_ATTT.exe
  - ext/USB/app/Mtext.bin
  - ext/MiAV/install_script.iss
  - ext/USB/install_script.iss
  - ext/USB2/{app}/USB_ATTT.exe
  - ext/USB2/install_script.iss
  - inf/inf.bin  (real sample supplied by the user, produced by USB_ATTT.exe run as Administrator)
- out_of_scope:
  - No dynamic execution of any installer or payload.
  - No modification of installer binaries.
  - No attempt to bypass the CBFS minifilter on a live system.
  - No forgery of `inf.bin` / `USB-AT2.6` label (documented as a weakness only).
  - No contact with the vendor infrastructure.

## goal
Determine how the two products are linked in the USB monitoring/management mechanism on military PCs
where MiAV is installed and USB An Toàn v2.6 (produced by the BTL86 USB An Toàn tool) is mandatory.
Deliver a full mechanism report.

## steps
1. Identify + unpack both Inno Setup installers — done
2. Extract Inno install scripts (services, registry, config.ini defaults) — done
3. PE triage: architecture, compiler, toolchain, signature — done (E-001)
4. Delphi RTTI + UnicodeString table dump of `MiAV.exe` — done
5. Locate USB policy engine by xref to `config.ini` keys — done (`0x90ECE0`)
6. Disassemble classification (`0x914EA8`), version detect (`0x914D40`, `0x91468C`), lock (`0x917B58`), alert (`0x90D560`) — done (E-002)
7. Reverse `USB_ATTT.exe` string tables: file footprint, volume label, ACL, crypto API — done (E-004)
8. Correlate producer ↔ consumer artefacts — done
9. Produce formal report with diagrams — done (`report/report.md`)
10. Validate `inf.bin` formula byte-exact against real sample — done (E-005)

## signoff
- ready_for_act: true
- notes: Static analysis only; no target interaction required or performed.

## deliverables
- `evidence/E-001.md`, `evidence/E-002.md`, `evidence/E-004.md`, `evidence/E-005.md`
- `report/report.md` (main deliverable, Vietnamese, with architecture/flow/state diagrams)
- `report/diagrams/*.svg|.pdf|.png`
- `work/delphi.py`, `work/pe_info.py`, `work/disasm_at.py`, `work/strx.py`, `work/grepstr.py`, `work/gen_diagrams.py`
- `work/make_infbin.py`, `work/miav_verify.py`, `work/verify_formula.py` (byte-exact `inf.bin` generator + MiAV verifier oracle)
