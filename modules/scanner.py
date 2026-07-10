#!/usr/bin/env python3
"""Network Scanner - iw dev scan with WPS detection"""

import re
import subprocess
import codecs
import time

def freq_to_ch(freq):
    try:
        f = int(freq)
    except (ValueError, TypeError):
        return 0
    if 2412 <= f <= 2484:
        return 14 if f == 2484 else (f - 2412) // 5 + 1
    elif 5170 <= f <= 5825:
        return (f - 5170) // 5 + 34
    elif 5955 <= f <= 7115:
        return (f - 5955) // 5 + 1
    return 0

def get_interface_mode(iface):
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                          capture_output=True, text=True, timeout=5)
        m = re.search(r"type\s+(\w+)", r.stdout)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"

def get_interfaces():
    ifaces = []
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        for m in re.finditer(r"Interface (\S+)", r.stdout):
            ifaces.append(m.group(1))
    except Exception:
        pass
    return ifaces

def scan_iw(iface, timeout=20):
    """Scan using iw dev scan - works in managed mode"""
    try:
        subprocess.run(["ip", "link", "set", iface, "up"],
                      capture_output=True, timeout=5)
    except Exception:
        pass
    time.sleep(1)

    try:
        r = subprocess.run(["iw", "dev", iface, "scan"],
                          capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    if r.returncode != 0:
        return []

    return parse_iw_output(r.stdout)

def parse_iw_output(output):
    networks = []
    current = None

    for line in output.split("\n"):
        line = line.strip().lstrip("\t")

        m = re.match(r"BSS ([0-9a-fA-F:]{17})", line)
        if m:
            if current and current.get("has_wps"):
                networks.append(current)
            current = {
                "bssid": m.group(1).upper(),
                "essid": "",
                "channel": 0,
                "frequency": 0,
                "rssi": 0,
                "has_wps": 0,
                "wps_locked": "Unknown",
                "wps_version": "1.0",
                "wps_device": "",
                "wps_model": "",
                "encryption": "Unknown",
                "cipher": "",
                "auth": "",
                "source": "iw",
            }
            continue

        if current is None:
            continue

        # SSID
        m2 = re.match(r"SSID: (.*)", line)
        if m2:
            try:
                current["essid"] = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["essid"] = m2.group(1)
            if not current["essid"].strip("\x00 "):
                current["essid"] = "Hidden"
            continue

        # Signal
        m2 = re.match(r"signal: ([+-]?[0-9.]+) dBm", line)
        if m2:
            current["rssi"] = int(float(m2.group(1)))
            continue

        # Frequency
        m2 = re.match(r"freq: (\d+)", line)
        if m2:
            current["frequency"] = int(m2.group(1))
            current["channel"] = freq_to_ch(current["frequency"])
            continue

        # Encryption: capability
        m2 = re.match(r"(capability): (.+)", line)
        if m2:
            current["encryption"] = "WEP" if "Privacy" in m2.group(2) else "Open"
            continue

        # RSN (WPA2)
        m2 = re.match(r"(RSN):\t", line)
        if m2:
            sec = current["encryption"]
            if sec == "WEP":
                current["encryption"] = "WPA2"
            elif sec == "WPA":
                current["encryption"] = "WPA/WPA2"
            continue

        # WPA
        m2 = re.match(r"(WPA):\t", line)
        if m2:
            sec = current["encryption"]
            if sec == "WEP":
                current["encryption"] = "WPA"
            elif sec == "WPA2":
                current["encryption"] = "WPA/WPA2"
            continue

        # Auth suites
        m2 = re.match(r" [*] Authentication suites: (.+)", line)
        if m2:
            a = m2.group(1).strip()
            if "PSK" in a and "SAE" in a:
                current["encryption"] = "WPA2/WPA3"
            elif "SAE" in a:
                current["encryption"] = "WPA3"
            continue

        # WPS Version
        m2 = re.match(r"WPS:\t [*] Version: ([0-9.]+)", line)
        if m2:
            current["has_wps"] = 1
            continue

        # WPS Version2
        m2 = re.match(r" [*] Version2: (.+)", line)
        if m2:
            if "2.0" in m2.group(1):
                current["wps_version"] = "2.0"
            continue

        # WPS Lock
        m2 = re.match(r" [*] AP setup locked: (0x[0-9a-fA-F]+)", line)
        if m2:
            current["wps_locked"] = "Yes" if int(m2.group(1), 16) else "No"
            continue

        # Model
        m2 = re.match(r" [*] Model: (.*)", line)
        if m2:
            try:
                current["wps_model"] = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["wps_model"] = m2.group(1)
            continue

        # Model Number
        m2 = re.match(r" [*] Model Number: (.*)", line)
        if m2:
            try:
                val = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                val = m2.group(1)
            current["wps_model"] = (current["wps_model"] + " " + val).strip()
            continue

        # Device Name
        m2 = re.match(r" [*] Device name: (.*)", line)
        if m2:
            try:
                current["wps_device"] = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["wps_device"] = m2.group(1)
            continue

    if current and current.get("has_wps"):
        networks.append(current)

    networks.sort(key=lambda x: x["rssi"], reverse=True)
    return networks
