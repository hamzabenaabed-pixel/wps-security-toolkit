# WPS Security Toolkit

Professional offline-first toolkit for **authorized** WPS / Wi-Fi security testing.

> **Legal notice:** Use only on networks and devices you own or have explicit written permission to test. Unauthorized access to computer systems is illegal.

## Features

- Network scanner (`iw`) with WPS IE parsing, WPA3/SAE hints, vendor OUI map
- Offline WPS PIN intelligence (airgeddon known-PIN snapshot + algorithms)
- Target assessment (readiness score, recommended method, warnings)
- Direct WPS engine via `wpa_supplicant` (PIN / Pixie / PBC / smart)
- Auto-WPS with lock monitoring and attempt resume
- Handshake / PMKID helpers, Hashcat runner, recon, evil twin modules
- Thread-safe SQLite vault, HTML/JSON reports, system diagnostics

## Project layout

```
wps_toolkit_final/
├── main.py                 # Rich TUI dashboard
├── config.py               # Settings + paths
├── database.py             # Thread-safe SQLite layer
├── vulnwsc.txt             # Extra vulnerable model names
├── data/
│   ├── wps.db              # Created at runtime
│   └── wps_pin_database.json
├── modules/                # Feature modules
├── tools/
│   ├── build_pin_database.py
│   └── vendor/known_pins.db
├── tests/
│   └── test_core_offline.py
├── reports/                # HTML/JSON exports + DB backups
└── logs/
```

## Requirements

- Linux with wireless stack (`iw`, `ip`)
- Python 3.9+
- Prefer root for live scans / monitor mode
- Optional: `wpa_supplicant`, `pixiewps`, `hashcat`, `hostapd`, `dnsmasq`, aircrack-ng suite

Python packages (auto-installed by `main.py` if missing):

- `rich`
- `psutil`

## Quick start

```bash
cd wps_toolkit_final

# 1) Build offline PIN intelligence (once, or after updating vendor DB)
python3 tools/build_pin_database.py --merge-static

# 2) Offline self-test (no Wi-Fi needed)
python3 tests/test_core_offline.py

# 3) Launch dashboard (root recommended for live features)
sudo python3 main.py
```

### Menu map (high level)

| # | Module |
|---|--------|
| 1 | Network Scanner |
| 2 | Target Management |
| 4 | Attack Center (+ assessment) |
| 6 | Auto-WPS |
| 9 | Handshake Capture |
| 15 | Credentials Vault |
| 16 | Reports |
| 18 | **System Diagnostics** |
| A | Settings |

## PIN intelligence

The toolkit expects `data/wps_pin_database.json`.

Source snapshot: [airgeddon `known_pins.db`](https://github.com/v1s1t0r1sh3r3/airgeddon) (GPL-3.0).  
Bundled under `tools/vendor/known_pins.db` and converted offline:

```bash
python3 tools/build_pin_database.py --merge-static
```

You can also rebuild from Settings → option 6 inside the TUI.

## Smart probe + Vulnerability intelligence

### Smart probe (lockout-aware)
- Remembers per-IP attempts / lockouts in SQLite (`router_probe_state`)
- Brand policies (ZTE/Huawei/ISP CPE → max 3 tries, longer delay)
- Auto-blocks probing until `lockout_until`
- Menu **7 → 8** shows state and can clear local timer

### Vuln intel (reference only)
- Offline seed: `data/vuln_intel_seed.json`
- Optional NVD API keyword lookup (cached in `data/vuln_intel_cache.json`)
- Exploit-DB / NVD **search links only** — no exploit payloads downloaded or executed
- Menu **7 → 7** for manual lookup; Full audit attaches CVE refs automatically

## Router Web Audit (menu 7)

Safe, authorized **web management** audit — not a Wi-Fi cracker:

1. TCP probe of common admin ports
2. HTTP(S) fingerprint (brand / title / model hints)
3. Optional **Basic Auth** default-credential probe with strict verification
4. Manual confirmation before each network action
5. Results stored in `router_audits` (verified passwords only) + JSON under `reports/`

Moroccan ISP CPE signatures (IAM / Inwi / OrangeMA) are included conservatively.

Default web login ≠ Wi-Fi PSK. Only `status=success` is treated as verified.

## Safety rules (false-positive prevention)

- A WPS result is only stored as a credential when a **PSK is verified**
- PIN-only rows for WPS-like methods are **rejected** by `Database.add_credential`
- Reports separate **verified** credentials from incomplete / suspicious rows
- Target assessment prefers offline analysis before online attempts
- Diagnostics never send attack traffic

## Development rules used in this repo

1. Read existing code before changing it  
2. Prefer `.format()` over complex f-strings in new code  
3. Every `subprocess.run` uses `timeout`, `try/except`, `capture_output=True`, `text=True`  
4. Avoid `subprocess.Popen` unless streaming is required  
5. SQLite uses `threading.Lock()` + `check_same_thread=False`  
6. Schema created via `executescript()`  
7. Do not claim success without tests  

### Compile check

```bash
python3 - <<'PY'
import py_compile
from pathlib import Path
files = [path for path in Path('.').rglob('*.py') if '.git' not in path.parts]
for path in files:
    py_compile.compile(str(path), doraise=True)
print("py_compile project: PASS ({})".format(len(files)))
PY
git diff --check
```

## Attribution

- airgeddon known WPS PIN database — [v1s1t0r1sh3r3/airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) (GPL-3.0)
- Project authors / contributors as listed in Git history

## Disclaimer

This software is provided for educational and authorized security assessment purposes only. The authors assume no liability for misuse.


## New lab features (post-upgrade)

- Safety gates: signal / WPS lock / Pixie history (`modules/safety_gates.py`)
- Vendor playbooks (`modules/playbooks.py`)
- Offline ISP password candidates (`modules/isp_passwords.py`)
- Evidence locker + lab notes (`modules/evidence.py`)
- Candidate PIN vault (menu **19**)
- First-target wizard (menu **20**)
- See **LAB_GUIDE.md** for full test walkthrough


## Mega wordlist (1M, 2026)

```bash
python3 tools/build_mega_wordlist.py
# → data/wordlists/mega_1m_2026.txt
```

Also available from TUI menu **8 → 4**.

## Morocco mega wordlist 5M (2026)

Built from [MoroccanRockyou](https://github.com/ydy4/MoroccanRockyou) + local ISP/name/phone/2026 patterns.

```bash
python3 tools/build_mega_wordlist.py --count 5000000
```

File: `data/wordlists/mega_ma_5m_2026.txt`

Password length policy: **8–12 characters only**.

### Wordlist policy (current)
- Source only: [MoroccanRockyou](https://github.com/ydy4/MoroccanRockyou)
- Length: **8–12**
- **No random numeric spam** — deterministic expansions of source seeds only
- File: `data/wordlists/mega_ma_5m_2026.txt`

## Realistic wordlist 500k (recommended)

File: `data/wordlists/realistic_ma_500k_2026.txt`

- **500,000** unique passwords
- Length **8–12** with balanced distribution (not only length 8)
- Source-first: [MoroccanRockyou](https://github.com/ydy4/MoroccanRockyou) + ISP/names/cities/years
- No pure-random number spam

```bash
python3 tools/build_realistic_wordlist.py --count 500000
# TUI: menu 8 → 4
hashcat -m 22000 capture.hc22000 data/wordlists/realistic_ma_500k_2026.txt
```



## LAN MITM Lab (menu 13)

Replaces WPA2 Evil Twin entry in the main menu.

- ARP spoof (arpspoof if installed, else Python raw socket)
- Optional DNS spoof (Python UDP :53 + optional iptables redirect)
- **ALL targets** mode supported
- Stop restores ip_forward + best-effort ARP

Requires root and a connected LAN interface. Authorized lab only.
