# SafeCheck Pro (macOS) — OGF/Poseidon Quick Scan

> A bilingual (Arabic/English) macOS shell script to quickly triage OGF/Poseidon artifacts: checks Gatekeeper status, hunts local indicators, verifies DMG hashes against BrokenStones `badfiles.txt`, inspects mounted volumes, optionally runs a helper script, and compares active connections to IPs from community intel (rentry).

<p align="center">
  <img alt="macOS" src="https://img.shields.io/badge/macOS-12%2B-blue">
  <img alt="Shell" src="https://img.shields.io/badge/shell-bash-informational">
  <a href="#license"><img alt="License" src="https://img.shields.io/badge/license-MIT-green"></a>
</p>


## Features

- **Bilingual UX (Arabic/English)** – prompt at start.
- **Gatekeeper status** check.
- **Local artifacts sweep**:
  - `/tmp` for `run.sh` and `tnt*`
  - Spotlight & Application Support for `.dat.nosync*`
  - LaunchAgents/Daemons listing (light triage)
- **DMG hash check** – compares recursively found `*.dmg` under `Downloads/Desktop` against BrokenStones `badfiles.txt`.
- **OGF filename hunt** – searches for “Open Gatekeeper friendly” files (incl. mounted volumes under `/Volumes`).
- **Optional helper** – runs BrokenStones helper script inside `~/Downloads` (configurable).
- **Rentry IPs match** – fetches known IPs and compares with current `lsof` network connections.
- **Auto-quarantine** – moves suspicious hits to a timestamped folder.
- **Comprehensive log** – timestamped file under `~/Desktop/SafeCheck_Logs`.

> ⚠️ **Research tool**: Intended for triage and awareness. Not a replacement for EDR/AV or professional IR.

## Requirements

- macOS 12+ (should work on newer versions too)
- `bash`, `curl`, `md5` (or `md5sum`), `lsof`, `file`, `stat`
- Terminal permissions; for wider coverage you may grant **Full Disk Access** to your terminal app (System Settings → Privacy & Security).

## Quick Start

```bash
# Clone
git clone https://github.com/ikhd/safecheck-macos.git
cd safecheck-macos

# Make executable
chmod +x SafeCheck_Pro.sh

# Run
./SafeCheck_Pro.sh
```

<p align="center">
  <img src="Screenshot.png" alt="SafeCheck sample output" width="700">
</p>
