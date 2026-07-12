# Lab Guide — How to test everything

**Legal:** Only networks/devices you own or have written authorization to test.

## 0) Setup

```bash
cd /home/user/wps_toolkit_final
python3 -m pip install -r requirements.txt --user
# system tools (Debian/Kali examples)
# sudo apt install iw wpasupplicant pixiewps reaver hcxdumptool hcxtools hashcat
python3 tests/test_core_offline.py
sudo python3 main.py
```

Confirm the main menu shows **19 Candidate PIN Vault** and **20 First-Target Wizard**.

## 1) System Diagnostics (menu 18)

1. Main menu → **18**
2. Check: root, interface, `iw`, `wpa_supplicant`, `pixiewps`, PIN DB prefixes
3. Export JSON if needed

**Pass:** PIN intelligence not empty; core tools present.

## 2) First-Target Wizard (menu 20)

1. **20** → scan → pick a network with best signal
2. Read playbook + recommended path + warnings
3. Optional: open assessment / handshake / attack center

**Pass:** You see playbook family (e.g. Ralink vs ISP ONT) and signal warnings if weak.

## 3) Scanner (menu 1)

1. Scan in managed mode
2. Confirm ESSID / BSSID / WPS / model columns
3. Prefer targets with RSSI **better than -80 dBm** for WPS

## 4) Auto Target Assessment (Attack Center → 7)

1. Menu **4** → **7**
2. Select target
3. Check: Pixie tier %, max online PINs, attack order, playbook notes

Examples from real lab runs:

- Ralink RT2860 → Pixie-friendly playbook
- HG6145F1 / Fibre_inwi → ISP ONT, Pixie discouraged, PMKID / ISP candidates

## 5) Safety gates (forced path)

Pick a target at about **-90 dBm** or a prior `pixie_not_vulnerable` BSSID:

1. Attack Center → Pixie
2. Expect **Safety gate** summary
3. Without typing `FORCE`, the action should cancel when blocked

**Pass:** You cannot casually spam Pixie on resistant or very weak targets.

## 6) Pixie Dust on Ralink (good lab case)

When you have a Ralink/RT2860-like AP and good signal:

1. Attack Center → **2 Pixie Dust**
2. Watch for M1…M4, field collection, pixiewps
3. Outcomes:
   - `success` + PSK → credentials vault
   - `pixie_pin_unverified` + PIN → stored in menu **19**
4. If unverified: menu **19** → verify PIN, or Attack Center → PIN with that PIN

**Known PIN from earlier lab work:** `65917763` on `08:5A:11:64:95:20` (verify when close).

## 7) Candidate PIN Vault (menu 19)

1. Open **19**
2. See offline Pixie PINs
3. Verify one online when signal is good

## 8) ISP ONT path (HG6145 / F680 class)

1. Assessment should say modern resistant / PMKID preferred
2. Offline ISP password candidates listed
3. Prefer: Handshake menu → PMKID / passive
4. Router Web Audit (menu **7**) for gateway only, max 3 defaults, wait on lockout

## 9) Router Web Audit (menu 7)

1. Set target IP (gateway)
2. Full audit with optional NVD online
3. Menu **8** probe state if lockout
4. Do not treat web login as Wi-Fi PSK

## 10) Handshake / PMKID (menu 9)

1. Menu **9 → 8** optional **WPS survey (wash)** if installed — updates lock/version in DB
2. **1 Capture PMKID** — shows playbook + signal gate + writes ISP candidate wordlist to `/tmp/wps_toolkit_isp_candidates.txt`
3. On success: `.hc22000` file + `hashcat -m 22000`
4. Passive handshake (2) with a client you own (no deauth)
5. Hashcat menu 10 — default wordlist may point to ISP candidates file if present

### Legacy section
## 10b) Handshake / PMKID details

1. Managed PMKID probe if WPA2
2. Passive wait if clients reconnect
3. Export for hashcat (mode **22000** is typical for modern WPA hashes)

## 11) Hashcat (menu 10)

1. Point at capture/hash file
2. Use a wordlist; you can seed it with offline ISP candidates from assessment notes

## 12) Evidence and lab notes

After attacks:

- `logs/evidence/ev_*.json` — structured evidence
- `reports/ev_*.md` — short lab note

## 13) Offline unit tests (no Wi-Fi)

```bash
python3 tests/test_core_offline.py
```

## 14) Troubleshooting

| Symptom | Fix |
|---------|-----|
| Stuck on Trying PIN | Use updated wpa_engine reader thread; restart from this folder |
| Not enough data 0/7 after PIN found | Fixed single-pass pixiewps; ensure latest attack.py |
| Always weak signal | Move closer; WPS blocked under about -88 dBm |
| Pixie on Inwi ONT | Expected fail; use PMKID / ISP wordlist |
| Menu missing 19/20 | Wrong directory or old copy |

## Quick decision card

1. Signal worse than -88 dBm → stop / move closer  
2. WPS locked → stop online WPS  
3. Family Ralink → Pixie then verify PIN  
4. Family HG6145 / F680 / ISP → no Pixie spam → PMKID + ISP candidates + careful web audit  
5. Known OUI PINs → limited PIN sweep  


## 15) Mega wordlist 1,000,000 (2026)

```bash
# CLI
python3 tools/build_mega_wordlist.py --count 1000000

# Or from TUI: menu 8 → 4 MEGA 1,000,000 list
```

Default file: `data/wordlists/mega_1m_2026.txt`

Crack example:
```bash
hashcat -m 22000 data/handshakes/pmkid_XXXX.hc22000 data/wordlists/mega_1m_2026.txt
```

## 16) Morocco mega wordlist 5,000,000 (2026)

Source seed: [MoroccanRockyou](https://github.com/ydy4/MoroccanRockyou)

```bash
python3 tools/build_mega_wordlist.py --count 5000000
# → data/wordlists/mega_ma_5m_2026.txt
```

TUI: menu **8 → 4**

```bash
hashcat -m 22000 capture.hc22000 data/wordlists/mega_ma_5m_2026.txt
```

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



## 17) LAN MITM Lab (menu 13)

Replaces former WPA2 Evil Twin menu slot.

1. Connect to your **lab** Wi-Fi/LAN
2. Main menu → **13 LAN MITM Lab**
3. Option **8** dependency hints (`dsniff`/`iptables`/`nmap`…)
4. **1** discover hosts
5. **4** optional DNS map (domain → IP / catch-all)
6. **2** ARP chosen targets, **3** ARP ALL targets, or **5** ARP+DNS
7. **7** STOP + cleanup (restores ip_forward / best-effort ARP)

Needs root. Private IPv4 only. Authorized networks only.
