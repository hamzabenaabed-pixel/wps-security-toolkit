#!/usr/bin/env python3
"""
Hashcat Runner v5 - Multi-threaded PMKID + Full Handshake Cracker
- Full handshake (WPA*02) مع HMAC-SHA1-128 فوق EAPOL frame
- PMKID cracking
- Multi-threading PBKDF2
"""

import os, re, time, hashlib, hmac as hmac_mod, threading, struct
from pathlib import Path
from datetime import datetime

HANDSHAKE_DIR = Path(__file__).parent.parent / "data" / "handshakes"
HANDSHAKE_DIR.mkdir(parents=True, exist_ok=True)


def detect_cpu_count():
    try:
        return max(1, (os.cpu_count() or 4) - 1)
    except Exception:
        return 4


def prf384(k, a, b):
    """PRF-384 for WPA2 PTK derivation (IEEE 802.11i)"""
    result = b""
    i = 0
    while len(result) < 48:
        msg = a.encode() + b"\x00" + b + struct.pack(">B", i)
        result += hmac_mod.new(k, msg, hashlib.sha1).digest()
        i += 1
    return result[:48]


def verify_eapol_mic(kck, eapol_hex, stored_mic_hex):
    """
    التحقق من MIC (hashcat -m 22000 طريقة)
    إطار EAPOL-Key كامل (مع 4 بايت EAPOL header):
      Bytes 0-3:   EAPOL header (version, type, length)
      Bytes 4:     Key Descriptor Type
      Bytes 5-6:   Key Info
      Bytes 7-8:   Key Length
      Bytes 9-16:  Key Replay Counter
      Bytes 17-48: Key Nonce
      Bytes 49-64: EAPOL-Key IV
      Bytes 65-72: Key RSC
      Bytes 73-80: Key ID / Reserved
      Bytes 81-96: Key MIC (16)    ← MIC هنا (الصحيح!)
      Bytes 97-98: Key Data Length
      Bytes 99+:   Key Data
    """
    frame = bytes.fromhex(eapol_hex)
    stored_mic = stored_mic_hex.upper()

    if len(frame) < 97:
        return False

    # Key Info (bytes 5-6) يجب أن يكون فيه MIC flag
    ki = struct.unpack(">H", frame[5:7])[0]
    if not (ki & 0x0100):
        return False  # هذا الإطار مش فيه MIC

    # MIC في bytes 81-96
    for mic_start in [81, 79, 83, 77, 85, 87]:
        mic_end = mic_start + 16
        if mic_end > len(frame):
            continue

        # حافظ على MIC لاستخراجها من الإطار
        mic_in_frame = frame[mic_start:mic_end].hex().upper()

        # صفر MIC bytes
        frame_list = bytearray(frame)
        for i in range(mic_start, mic_end):
            frame_list[i] = 0
        zeroed = bytes(frame_list)

        # HMAC-SHA1(KCK, zeroed_frame)[:16]
        computed = hmac_mod.new(kck, zeroed, hashlib.sha1).digest()[:16].hex().upper()

        if computed == stored_mic:
            return True

    return False


class HashcatRunner:
    def __init__(self):
        self.process = None
        self.output = []
        self.callback = None
        self.running = False
        self.threads = detect_cpu_count()

    def is_installed(self):
        import shutil
        return shutil.which("hashcat") is not None

    def list_captures(self):
        caps = []
        for f in sorted(HANDSHAKE_DIR.glob("*.hc22000"), key=os.path.getmtime, reverse=True):
            caps.append({"file": str(f), "name": f.name, "size": f.stat().st_size})
        return caps

    def crack(self, capture_file, wordlist, rules=None, callback=None):
        self.output = []
        self.callback = callback

        try:
            with open(wordlist, "r", errors="ignore") as f:
                total = sum(1 for line in f if line.strip())
        except Exception:
            total = 0

        self._log("Capture: " + os.path.basename(capture_file))
        self._log("Wordlist: " + os.path.basename(wordlist) + " (" + str(total) + " passwords, " + str(self.threads) + " threads)")

        # Try hashcat first
        if self.is_installed():
            self._log("\nTrying hashcat -m 22000...")
            import subprocess
            cmd = ["hashcat", "-m", "22000", "--force", capture_file, wordlist]
            if rules:
                cmd.extend(["-r", rules])
            try:
                self.process = subprocess.Popen(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, bufsize=1)
                no_devices = False
                for line in iter(self.process.stdout.readline, ""):
                    line = line.rstrip("\n")
                    self.output.append(line)
                    if self.callback:
                        self.callback(line)
                    if "No devices" in line:
                        no_devices = True
                self.process.wait()
                if not no_devices and self.process.returncode == 0:
                    result = self._parse_result()
                    if result["status"] == "cracked":
                        return result
                self._log("hashcat: no GPU/CPU support")
            except FileNotFoundError:
                self._log("hashcat not found")
            except KeyboardInterrupt:
                self.stop()
                return {"status": "stopped"}
            except Exception as e:
                self._log("hashcat error: " + str(e))

        self._log("\nRunning Python cracker (" + str(self.threads) + " threads)...")
        return self._python_crack(capture_file, wordlist)

    def _python_crack(self, capture_file, wordlist):
        try:
            with open(capture_file, "r") as f:
                content = f.read().strip()
        except Exception as e:
            return {"status": "error", "message": str(e)}

        first = content.split("\n")[0].strip()
        if first.startswith("PMKID:"):
            return self._crack_pmkid(first, wordlist)
        elif first.startswith("WPA*01*"):
            return self._crack_pmkid_standard(first, wordlist)
        elif first.startswith("WPA*02*"):
            return self._crack_handshake(first, wordlist)
        else:
            return {"status": "error", "message": "Unknown format"}

    def _crack_pmkid(self, content, wordlist):
        """كسر PMKID"""
        parts = content.split(":", 1)[1].strip().split("*")
        if len(parts) < 4:
            return {"status": "error", "message": "Invalid PMKID"}

        target = parts[0].upper()
        bssid = bytes.fromhex(parts[1])
        sta = bytes.fromhex(parts[2])
        essid = bytes.fromhex(parts[3])
        essid_str = essid.decode("utf-8", errors="replace")

        self._log("Target PMKID: " + target)
        self._log("ESSID: " + essid_str)

        return self._crack_passwords(wordlist, essid_str, {
            "type": "pmkid", "target": target, "bssid": bssid, "sta": sta, "essid": essid
        })

    def _crack_pmkid_standard(self, content, wordlist):
        """Crack a standard Hashcat WPA*01 PMKID line."""
        parts = content.split("*")
        if len(parts) < 6:
            return {"status": "error", "message": "Invalid WPA*01"}
        try:
            target = parts[2].upper()
            bssid = bytes.fromhex(parts[3])
            sta = bytes.fromhex(parts[4])
            essid = bytes.fromhex(parts[5])
        except ValueError as exc:
            return {"status": "error", "message": "Bad hex: " + str(exc)}

        essid_str = essid.decode("utf-8", errors="replace")
        self._log("Target PMKID: " + target)
        self._log("ESSID: " + essid_str)
        return self._crack_passwords(wordlist, essid_str, {
            "type": "pmkid",
            "target": target,
            "bssid": bssid,
            "sta": sta,
            "essid": essid,
        })

    def _crack_handshake(self, content, wordlist):
        """كسر full handshake باستخدام HMAC-SHA1-128 فوق EAPOL"""
        parts = content.split("*")
        if len(parts) < 9:
            return {"status": "error", "message": "Invalid WPA*02"}

        target_mic = parts[2].upper()
        bssid_hex = parts[3]
        sta_hex = parts[4]
        essid_hex = parts[5]
        anonce_hex = parts[6]

        # Standard hc22000: field 7=EAPOL, field 8=message-pair flags.
        # Legacy toolkit diagnostic: field 7=SNonce, field 8=EAPOL.
        if len(parts[7]) >= 190 and len(parts[8]) <= 2:
            eapol_hex = parts[7]
            snonce_hex = eapol_hex[34:98] if len(eapol_hex) >= 98 else ""
        else:
            snonce_hex = parts[7]
            eapol_hex = parts[8]

        try:
            bssid = bytes.fromhex(bssid_hex)
            sta = bytes.fromhex(sta_hex)
            essid = bytes.fromhex(essid_hex) if essid_hex else b""
            anonce = bytes.fromhex(anonce_hex)
            snonce = bytes.fromhex(snonce_hex)
        except ValueError as e:
            return {"status": "error", "message": "Bad hex: " + str(e)}

        essid_str = essid.decode("utf-8", errors="replace")
        self._log("Target MIC: " + target_mic)
        self._log("ESSID: " + (essid_str or "Unknown"))
        self._log("BSSID: " + bssid_hex)
        self._log("Full handshake - using PRF-384 + HMAC-SHA1-128")

        return self._crack_passwords_handshake(wordlist, {
            "target_mic": target_mic,
            "bssid": bssid,
            "sta": sta,
            "essid": essid,
            "anonce": anonce,
            "snonce": snonce,
            "eapol_hex": eapol_hex,
        })

    def _crack_passwords(self, wordlist, essid_str, params):
        """كسر PMKID"""
        passwords = []
        try:
            with open(wordlist, "r", errors="ignore") as f:
                for line in f:
                    pwd = line.strip()
                    if len(pwd) >= 8:
                        passwords.append(pwd)
        except Exception as e:
            return {"status": "error", "message": str(e)}

        total = len(passwords)
        self._log("Loaded " + str(total) + " passwords")

        if total == 0:
            return {"status": "exhausted"}

        self.running = True
        found = [None]
        tested = [0]
        lock = threading.Lock()
        counter = threading.Lock()
        start = time.time()
        essid = params["essid"]

        def worker(chunk):
            for pwd in chunk:
                if not self.running or found[0]:
                    return
                try:
                    pmk = hashlib.pbkdf2_hmac("sha1", pwd.encode(), essid, 4096, 32)
                    msg = b"PMK Name" + params["bssid"] + params["sta"]
                    pmkid = hmac_mod.new(pmk, msg, hashlib.sha1).digest()[:16].hex().upper()
                    if pmkid == params["target"]:
                        with lock:
                            found[0] = pwd
                        return
                except Exception:
                    pass
                with counter:
                    tested[0] += 1
                    if tested[0] % 1000 == 0:
                        elapsed = time.time() - start
                        speed = tested[0] / elapsed if elapsed > 0 else 0
                        self._log("  {n}/{t} ({spd}/s)".format(n=tested[0], t=total, spd=int(speed)))

        self._run_threads(passwords, worker)
        elapsed = time.time() - start
        self._log("\nTested: " + str(tested[0]) + " in " + str(int(elapsed)) + "s")

        if found[0]:
            self._log("\nKEY FOUND! [" + found[0] + "]")
            return {"status": "cracked", "password": found[0]}
        return {"status": "exhausted"}

    def _crack_passwords_handshake(self, wordlist, params):
        """كسر full handshake"""
        passwords = []
        try:
            with open(wordlist, "r", errors="ignore") as f:
                for line in f:
                    pwd = line.strip()
                    if len(pwd) >= 8:
                        passwords.append(pwd)
        except Exception as e:
            return {"status": "error", "message": str(e)}

        total = len(passwords)
        self._log("Loaded " + str(total) + " passwords")

        if total == 0:
            return {"status": "exhausted"}

        self.running = True
        found = [None]
        tested = [0]
        lock = threading.Lock()
        counter = threading.Lock()
        start = time.time()
        essid = params["essid"]
        bssid = params["bssid"]
        sta = params["sta"]
        anonce = params["anonce"]
        snonce = params["snonce"]
        target_mic = params["target_mic"]
        eapol_hex = params["eapol_hex"]

        def worker(chunk):
            for pwd in chunk:
                if not self.running or found[0]:
                    return
                try:
                    # 1. احسب PMK
                    pmk = hashlib.pbkdf2_hmac("sha1", pwd.encode(), essid, 4096, 32)

                    # 2. احسب PTK عبر PRF-384
                    b = min(bssid, sta) + max(bssid, sta) + min(anonce, snonce) + max(anonce, snonce)
                    ptk = prf384(pmk, "Pairwise key expansion", b)

                    # 3. KCK = أول 16 بايت من PTK
                    kck = ptk[:16]

                    # 4. تحقق من MIC فوق إطار EAPOL
                    if eapol_hex and len(eapol_hex) > 100:
                        if verify_eapol_mic(kck, eapol_hex, target_mic):
                            with lock:
                                found[0] = pwd
                            return
                    else:
                        # بدون EAPOL، قارن KCK مباشرة مع MIC (قد ينجح أحياناً)
                        if kck.hex().upper() == target_mic:
                            with lock:
                                found[0] = pwd
                            return
                except Exception:
                    pass
                with counter:
                    tested[0] += 1
                    if tested[0] % 500 == 0:
                        elapsed = time.time() - start
                        speed = tested[0] / elapsed if elapsed > 0 else 0
                        rem = (total - tested[0]) / speed if speed > 0 else 0
                        self._log("  {n}/{t} ({spd}/s) ETA: {eta}s".format(
                            n=tested[0], t=total, spd=int(speed), eta=int(rem)))

        self._run_threads(passwords, worker)
        elapsed = time.time() - start
        speed = tested[0] / elapsed if elapsed > 0 else 0
        self._log("\nTested: " + str(tested[0]) + " in " + str(int(elapsed)) + "s (" + str(int(speed)) + "/s)")

        if found[0]:
            self._log("\n" + "=" * 50)
            self._log("KEY FOUND! [" + found[0] + "]")
            self._log("=" * 50)
            return {"status": "cracked", "password": found[0]}
        return {"status": "exhausted"}

    def _run_threads(self, passwords, worker_func):
        """تشغيل threads للكسر المتوازي"""
        chunk_size = max(1, len(passwords) // self.threads)
        chunks = [passwords[i:i+chunk_size] for i in range(0, len(passwords), chunk_size)]

        threads = []
        for chunk in chunks:
            t = threading.Thread(target=worker_func, args=(chunk,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

    def stop(self):
        self.running = False
        if self.process:
            try:
                self.process.terminate()
                self.process.wait(timeout=5)
            except Exception:
                try:
                    self.process.kill()
                except Exception:
                    pass

    def _parse_result(self):
        for line in reversed(self.output):
            line = line.strip()
            if not line or line.startswith(" ") or line.startswith("["):
                continue
            skip = ["Started:", "Stopped:", "hashcat", "Session",
                    "Status:", "Progress:", "Speed:", "Time:", "Running:",
                    "Recovered", "Input:", "Hardware", "Initializing",
                    "No devices", "Approaching", "Cracked", "Exhausted"]
            if any(w in line for w in skip):
                continue
            if ":" in line:
                parts = line.rstrip().split(":")
                if len(parts) >= 2:
                    candidate = parts[-1].strip()
                    if len(candidate) >= 8 and not candidate.startswith("0x"):
                        return {"status": "cracked", "password": candidate}
        return {"status": "completed"}

    def _log(self, msg):
        self.output.append(msg)
        if self.callback:
            self.callback(msg)
