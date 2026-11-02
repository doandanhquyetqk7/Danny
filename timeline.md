# Timeline — MiAV / USB An Toàn analysis

## 2026-10-23 T01:30 — Ingest & unpack | E-001
| item | value |
|---|---|
| action | Unpacked both installers with innounp (read-only, no execution) |
| evidence_ids | E-001 |

## 2026-10-23 T02:10 — PE triage & Inno script extraction | E-001
| item | value |
|---|---|
| action | Architecture, toolchain, Authenticode status, service/registry/config defaults |
| evidence_ids | E-001 |

## 2026-10-23 T03:05 — MiAV policy engine location | E-002
| item | value |
|---|---|
| action | Xref to config.ini / usb_no_at located the decision function at 0x90ECE0 |
| evidence_ids | E-002 |

## 2026-10-23 T04:00 — Classification + lock mechanism | E-002
| item | value |
|---|---|
| action | Disassembled GetTypeUSB (0x914EA8), isUSBATT (0x914D40), isUSBCY (0x91468C), CBFS lock (0x917B58), alert dialog (0x90D560) |
| evidence_ids | E-002 |

## 2026-10-23 T05:20 — Producer side (VB6) reconstruction | E-004
| item | value |
|---|---|
| action | Extracted string table and API usage of USB_ATTT.exe; reconstructed format/label/marker/ACL pipeline |
| evidence_ids | E-004 |

## 2026-10-23 T06:10 — Correlation & reporting | E-001, E-002, E-004
| item | value |
|---|---|
| action | Built producer/consumer fingerprint matrix, wrote the final mechanism report and rendered 5 diagrams |
| evidence_ids | E-001, E-002, E-004 |
