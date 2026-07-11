#!/usr/bin/env python3
"""
Network Scanner v3 - Advanced iw dev scan with WPS detection
- WPA3 / SAE / OWE detection
- 6GHz (WiFi 6E) support
- WPS manufacturer ID lookup
- Signal quality rating
- Protocol version detection (802.11ax/ac/n)
"""

import re
import subprocess
import codecs
import time

# ═══════════════════════════════════════════════════════════
# WPS MANUFACTURER ID DATABASE (OUI -> Brand)
# From IEEE OUI registry
# ═══════════════════════════════════════════════════════════

WPS_MFR_DB = {
    # Major router vendors
    "0050F2": "Microsoft", "00037F": "Atheros", "000B86": "Ralink",
    "00A0C6": "Intel", "00177C": "ASUS", "001E58": "D-Link",
    "0015E9": "D-Link", "001346": "D-Link", "00179A": "D-Link",
    "001B11": "D-Link", "001CF0": "D-Link", "00195B": "D-Link",
    "002191": "D-Link", "0022B0": "D-Link", "002401": "D-Link",
    "00265A": "D-Link", "000D88": "D-Link", "00055D": "D-Link",
    "00C0A7": "D-Link", "00B00C": "Tenda", "C83A35": "Tenda",
    "04CE14": "Tenda", "089E08": "Tenda", "147DC5": "Tenda",
    "181B2C": "Tenda", "503EAA": "Tenda", "C42F90": "Tenda",
    "10C37B": "ASUS", "1C872C": "ASUS", "382C4A": "ASUS",
    "08606E": "ASUS", "04D9F5": "ASUS", "2C56DC": "ASUS",
    "2CFDA1": "ASUS", "50465D": "ASUS", "54A050": "ASUS",
    "6045CB": "ASUS", "60A44C": "ASUS", "704D7B": "ASUS",
    "74D02B": "ASUS", "7824AF": "ASUS", "88D7F6": "ASUS",
    "9C5C8E": "ASUS", "AC220B": "ASUS", "AC9E17": "ASUS",
    "B06EBF": "ASUS", "BCEE7B": "ASUS", "D017C2": "ASUS",
    "D850E6": "ASUS", "E03F49": "ASUS", "F832E4": "ASUS",
    "50C7BF": "TP-Link", "C0E42D": "TP-Link", "54C80F": "TP-Link",
    "60E327": "TP-Link", "5C3A45": "TP-Link", "D46E0E": "TP-Link",
    "EC086B": "TP-Link", "14CF92": "TP-Link", "20DCE6": "TP-Link",
    "30B5C2": "TP-Link", "44D1FA": "TP-Link", "6C5AB0": "TP-Link",
    "78A106": "TP-Link", "90F652": "TP-Link", "A42BB0": "TP-Link",
    "B04E26": "TP-Link", "C025E9": "TP-Link", "CC32E5": "TP-Link",
    "D807B6": "TP-Link", "E8DE27": "TP-Link", "F4EC38": "TP-Link",
    "1CB044": "TP-Link", "283CE4": "TP-Link", "3497F6": "TP-Link",
    "645601": "TP-Link", "94D9B3": "TP-Link", "AC84C6": "TP-Link",
    "BC10BD": "TP-Link", "DCFE18": "TP-Link", "F81A67": "TP-Link",
    "002568": "Huawei", "487B6B": "Huawei", "00664B": "Huawei",
    "346BD3": "Huawei", "F4C714": "Huawei", "388345": "Huawei",
    "D07AB5": "Huawei", "E8CD2D": "Huawei", "F80113": "Huawei",
    "786A89": "Huawei", "88E3AB": "Huawei", "48AD08": "Huawei",
    "7811DC": "Xiaomi", "640980": "Xiaomi", "8CBEBB": "Xiaomi",
    "34CE00": "Xiaomi", "50642B": "Xiaomi", "68DFDD": "Xiaomi",
    "7451BA": "Xiaomi", "7CB59B": "Xiaomi", "F48B32": "Xiaomi",
    "F4F5D8": "Xiaomi", "FC643A": "Xiaomi", "FCDBB3": "Xiaomi",
    "D4970B": "Xiaomi", "D8CB8A": "Xiaomi", "DCD321": "Xiaomi",
    "2C3033": "Netgear", "0026F2": "Netgear", "20E52A": "Netgear",
    "841B5E": "Netgear", "A021B7": "Netgear", "C03F0E": "Netgear",
    "4C60DE": "Netgear", "6C3B6B": "Netgear", "E4F4C6": "Netgear",
    "B07FB0": "Netgear", "907240": "Netgear", "C43DC7": "Netgear",
    "001839": "Linksys", "001A70": "Linksys", "001C10": "Linksys",
    "002129": "Linksys", "00226B": "Linksys", "002369": "Linksys",
    "00259C": "Linksys", "C0C1C0": "Linksys", "687F74": "Linksys",
    "586D8F": "Linksys", "20AA4B": "Linksys", "28B2BD": "Linksys",
    "A43BFA": "ZTE", "F88E85": "ZTE", "587F66": "ZTE",
    "344B50": "ZTE", "5C353B": "ZTE", "DC537C": "ZTE",
    "14D64D": "D-Link", "1C7EE5": "D-Link", "28107B": "D-Link",
    "84C9B2": "D-Link", "CCB255": "D-Link", "C8D3A3": "D-Link",
    "C8BE19": "D-Link", "B8A386": "D-Link", "C0A0BB": "D-Link",
    "A0AB1B": "D-Link", "081077": "ASUS",
    # Moroccan ISP vendors
    "001F68": "Siemens", "C4E984": "Huawei", "002196": "Arcadyan",
    "1446B8": "Arcadyan", "E0B9BA": "Arcadyan", "D89DB9": "Arcadyan",
    "D0AEEC": "Sagemcom", "48666B": "Sagemcom", "24693E": "Sercomm",
    "D0C7C0": "Alcatel", "00053A": "Alcatel", "80A1D7": "Ubiquiti",
    "74DA38": "Technicolor", "4860BC": "Technicolor", "001E2A": "Technicolor",
    "00183C": "AVM (Fritz!)", "C046F6": "AVM (Fritz!)", "3822D5": "AVM (Fritz!)",
    "4CC0E5": "AVM (Fritz!)", "9C3AAF": "Cisco", "001B2A": "Cisco",
    "001637": "Cisco", "C0CBC6": "Cisco", "00E0B0": "EnGenius",
    "E89120": "EnGenius", "00277F": "MikroTik", "4C5E0C": "MikroTik",
    "E4F3B0": "MikroTik", "002342": "Tranzeo",
    # MediaTek (common in phones/hotspots)
    "080020": "MediaTek", "00AABB": "MediaTek", "10F13E": "MediaTek",
    "2CFD32": "MediaTek", "906DC1": "MediaTek", "A8BD3A": "MediaTek",
    "50C58B": "MediaTek", "1C6F65": "MediaTek",
    # Qualcomm
    "40B89A": "Qualcomm", "0011E3": "Qualcomm", "00904C": "Qualcomm/Atheros",
    "0018D2": "Qualcomm/Atheros", "0017F2": "Qualcomm/Atheros",
    "00D0C1": "Qualcomm/Atheros", "001018": "Qualcomm/Atheros",
    "0080B5": "Broadcom", "0060B3": "Broadcom", "001018": "Broadcom (old)",
    # Realtek
    "00E04C": "Realtek", "000C42": "Realtek", "0014D1": "Realtek",
    "000EE8": "Realtek", "007263": "Realtek",
    # Samsung
    "001E5A": "Samsung", "0021CD": "Samsung", "0013AE": "Samsung",
    "00408C": "Samsung", "00A4F3": "Samsung",
    # Apple
    "0017F2": "Apple", "001CB9": "Apple", "002590": "Apple",
    "6C709F": "Apple", "8C8590": "Apple",
    # Google/Nest
    "A887ED": "Google", "94E318": "Google", "001A11": "Google",
    "0013EF": "Google", "C8D15E": "Google",
    # Amazon Eero
    "0022BA": "Amazon", "74C246": "Amazon", "8CEBA2": "Amazon",
    "8C24B2": "Amazon", "34E42C": "Amazon",
    # TP-Link Decos
    "A8C222": "TP-Link (Deco)", "D0684A": "TP-Link (Deco)",
    # TPLink Archer series
    "C0A0DE": "TP-Link", "E0CA4A": "TP-Link", "B0F3F2": "TP-Link",
    # Meraki / Cisco
    "6487D7": "Cisco Meraki", "005056": "Cisco Meraki",
    # Ruckus / Brocade
    "643EDA": "Ruckus", "848968": "Ruckus", "2421AB": "Ruckus",
    # Extreme Networks
    "00154A": "Extreme", "00E06C": "Extreme",
    # Fortinet
    "482AD3": "Fortinet", "00509E": "Fortinet", "00E071": "Fortinet",
    # Sophos
    "0020AA": "Sophos", "000E53": "Sophos",
    # Ubiquiti UniFi
    "802AA8": "Ubiquiti UniFi", "04918A": "Ubiquiti UniFi",
    "D4524E": "Ubiquiti UniFi", "64D22E": "Ubiquiti UniFi",
    "4A3C10": "Ubiquiti UniFi",
    # Moroccan-specific
    "8068BC": "Alvarion/Olive", "0017E2": "Motorola",
    "0020A6": "PCTV", "E0D1E7": "Mitsumi", "001C5A": "AzureWave",
    "002622": "Thomson", "4432C8": "Technicolor (Thomson)",
    "88F7C7": "Technicolor", "CC03FA": "Technicolor",
}


def detect_manufacturer(bssid):
    """Detect manufacturer from BSSID MAC prefix"""
    mac = bssid.replace(":", "").replace("-", "").upper()
    prefix = mac[:6]
    if prefix in WPS_MFR_DB:
        return WPS_MFR_DB[prefix]
    # Try partial match (first 3 bytes)
    prefix_short = mac[:4]
    for pfx, mfr in WPS_MFR_DB.items():
        if pfx.startswith(prefix_short) or prefix_short.startswith(pfx):
            return mfr
    return None


def freq_to_ch(freq):
    """Convert frequency to channel number (including 6GHz)"""
    try:
        f = int(freq)
    except (ValueError, TypeError):
        return 0

    # 2.4 GHz band
    if 2412 <= f <= 2484:
        return 14 if f == 2484 else (f - 2412) // 5 + 1

    # 5 GHz band
    elif 5170 <= f <= 5825:
        return (f - 5170) // 5 + 34

    # 6 GHz band (WiFi 6E, 802.11ax)
    elif 5925 <= f <= 7125:
        ch = (f - 5925) // 5 + 1
        return ch

    # 3.6 GHz band (802.11y)
    elif 3650 <= f <= 3700:
        return (f - 3650) // 5 + 131

    return 0


def ch_to_band(channel, freq=0):
    """Determine which band a channel belongs to"""
    if freq > 0:
        if 2412 <= freq <= 2484:
            return "2.4 GHz"
        elif 5170 <= freq <= 5825:
            return "5 GHz"
        elif 5925 <= freq <= 7125:
            return "6 GHz"
        elif 3650 <= freq <= 3700:
            return "3.6 GHz"
    return "Unknown"


def get_interface_mode(iface):
    """Get current interface mode"""
    try:
        r = subprocess.run(["iw", "dev", iface, "info"],
                          capture_output=True, text=True, timeout=5)
        m = re.search(r"type\s+(\w+)", r.stdout)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def get_interfaces():
    """Get list of wireless interfaces"""
    ifaces = []
    try:
        r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
        for m in re.finditer(r"Interface (\S+)", r.stdout):
            ifaces.append(m.group(1))
    except Exception:
        pass
    return ifaces


def scan_iw(iface, timeout=20, wps_only=True):
    """Scan in managed mode. Set wps_only=False to return every AP."""
    try:
        subprocess.run(
            ["ip", "link", "set", iface, "up"],
            capture_output=True, text=True, timeout=5,
        )
    except Exception:
        pass
    time.sleep(1)

    try:
        r = subprocess.run(
            ["iw", "dev", iface, "scan"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []

    if r.returncode != 0:
        return []

    return parse_iw_output(r.stdout, wps_only=wps_only)


def parse_iw_output(output, wps_only=True):
    """Parse iw scan output. By default, keep only WPS-enabled APs."""
    networks = []
    current = None

    for line in output.split("\n"):
        line = line.strip().lstrip("\t")

        # New BSS entry
        m = re.match(r"BSS ([0-9a-fA-F:]{17})(.*)", line)
        if m:
            if current and (current.get("has_wps") or not wps_only):
                networks.append(current)
            current = {
                "bssid": m.group(1).upper(),
                "essid": "",
                "channel": 0,
                "frequency": 0,
                "band": "",
                "rssi": 0,
                "rssi_quality": 0,
                "has_wps": 0,
                "wps_locked": "Unknown",
                "wps_version": "",
                "wps_device": "",
                "wps_model": "",
                "wps_manufacturer": "",
                "encryption": "Unknown",
                "cipher": "",
                "auth": "",
                "protocol": "",
                "beacon_interval": 0,
                "dtim_period": 0,
                "is_hidden": False,
                "is_wifi_direct": False,
                "source": "iw",
            }
            continue

        if current is None:
            continue

        # SSID - handle hidden / escape sequences
        m2 = re.match(r"SSID: (.*)", line)
        if m2:
            raw_ssid = m2.group(1)
            try:
                current["essid"] = codecs.decode(
                    raw_ssid, "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["essid"] = raw_ssid
            if not current["essid"].strip("\x00 "):
                current["essid"] = "Hidden"
                current["is_hidden"] = True
            continue

        # Signal strength
        m2 = re.match(r"signal: ([+-]?[0-9.]+) dBm", line)
        if m2:
            current["rssi"] = int(float(m2.group(1)))
            # Calculate quality (0-100)
            rssi = current["rssi"]
            if rssi >= -50:
                current["rssi_quality"] = 100
            elif rssi >= -60:
                current["rssi_quality"] = 80
            elif rssi >= -70:
                current["rssi_quality"] = 60
            elif rssi >= -80:
                current["rssi_quality"] = 40
            elif rssi >= -90:
                current["rssi_quality"] = 20
            else:
                current["rssi_quality"] = 0
            continue

        # Frequency
        m2 = re.match(r"freq: (\d+)", line)
        if m2:
            current["frequency"] = int(m2.group(1))
            current["channel"] = freq_to_ch(current["frequency"])
            current["band"] = ch_to_band(current["channel"], current["frequency"])
            continue

        # Beacon interval
        m2 = re.match(r"\* beacon interval: (\d+)", line)
        if m2:
            current["beacon_interval"] = int(m2.group(1))
            continue

        # DTIM period
        m2 = re.match(r"\* DTIM period: (\d+)", line)
        if m2:
            current["dtim_period"] = int(m2.group(1))
            continue

        # Capability
        m2 = re.match(r"(capability): (.+)", line)
        if m2:
            caps = m2.group(2)
            if current["encryption"] == "Unknown":
                current["encryption"] = "WEP" if "Privacy" in caps else "Open"
            # Check for WiFi Direct
            if "Wi-Fi Direct" in caps or "P2P" in caps:
                current["is_wifi_direct"] = True
            continue

        # RSN (WPA2/WPA3/OWE). Some Android iw builds print the
        # first RSN value on the same line, so match any line starting RSN:.
        m2 = re.match(r"RSN:", line)
        if m2:
            sec = current["encryption"]
            if sec in ("WEP", "Open", "Unknown"):
                current["encryption"] = "WPA2"
            elif sec == "WPA":
                current["encryption"] = "WPA/WPA2"
            continue

        # WPA (Original WPA). Accept inline values from Android iw.
        m2 = re.match(r"WPA:", line)
        if m2:
            sec = current["encryption"]
            if sec == "WPA2":
                current["encryption"] = "WPA/WPA2"
            elif sec in ("WEP", "Open", "Unknown"):
                current["encryption"] = "WPA"
            continue

        # Authentication suites (for WPA3/SAE detection)
        m2 = re.match(r"\* Authentication suites: (.+)", line)
        if m2:
            a = m2.group(1).strip()
            if "SAE" in a:
                if "PSK" in a:
                    current["encryption"] = "WPA2/WPA3"
                    current["auth"] = "SAE/PSK"
                else:
                    current["encryption"] = "WPA3"
                    current["auth"] = "SAE"
            elif "OWE" in a:
                current["encryption"] = "OWE"
                current["auth"] = "OWE"
            elif "PSK" in a:
                current["auth"] = "PSK"
            elif "802.1X" in a or "EAP" in a:
                current["auth"] = "802.1X"
            continue

        # Pairwise ciphers
        m2 = re.match(r"\* Pairwise ciphers: (.+)", line)
        if m2:
            ciphers = m2.group(1)
            if "CCMP" in ciphers and "GCMP" in ciphers:
                current["cipher"] = "CCMP+GCMP"
            elif "CCMP" in ciphers:
                current["cipher"] = "CCMP"
            elif "TKIP" in ciphers:
                current["cipher"] = "TKIP"
            continue

        # Group cipher
        m2 = re.match(r"\* Group cipher: (.+)", line)
        if m2:
            # Only set if not already set
            if not current["cipher"]:
                current["cipher"] = m2.group(1)
            continue

        # AKM Suites (alternative format)
        m2 = re.match(r"\* AKM Suites: (.+)", line)
        if m2:
            akms = m2.group(1)
            if "SAE" in akms:
                current["auth"] = "SAE"
                if current["encryption"] in ("WPA2", "Unknown"):
                    current["encryption"] = "WPA3"
            continue

        # ═══ WPS Information Elements ═══

        # WPS Version
        m2 = re.match(r"WPS:\s+\* Version: ([0-9.]+)", line)
        if m2:
            current["has_wps"] = 1
            v = m2.group(1)
            if v:
                current["wps_version"] = v
            continue

        # WPS Version2
        m2 = re.match(r"\* Version2: (.+)", line)
        if m2:
            v2 = m2.group(1)
            if "2.0" in v2:
                current["wps_version"] = "2.0"
            continue

        # WPS AP Setup Locked
        m2 = re.match(r"\* AP setup locked: (0x[0-9a-fA-F]+)", line)
        if m2:
            try:
                val = int(m2.group(1), 16)
                current["wps_locked"] = "Yes" if val else "No"
            except ValueError:
                current["wps_locked"] = "Unknown"
            continue

        # WPS Model
        m2 = re.match(r"\* Model: (.*)", line)
        if m2:
            try:
                current["wps_model"] = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["wps_model"] = m2.group(1)
            continue

        # WPS Model Number
        m2 = re.match(r"\* Model Number: (.*)", line)
        if m2:
            try:
                val = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                val = m2.group(1)
            current["wps_model"] = (current["wps_model"] + " " + val).strip()
            continue

        # WPS Device Name
        m2 = re.match(r"\* Device name: (.*)", line)
        if m2:
            try:
                current["wps_device"] = codecs.decode(
                    m2.group(1), "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["wps_device"] = m2.group(1)
            continue

        # WPS Manufacturer
        m2 = re.match(r"\* Manufacturer: (.*)", line)
        if m2:
            raw_mfr = m2.group(1).strip()
            try:
                current["wps_manufacturer"] = codecs.decode(
                    raw_mfr, "unicode-escape"
                ).encode("latin1").decode("utf-8", errors="replace")
            except Exception:
                current["wps_manufacturer"] = raw_mfr
            continue

        # WPS Serial Number (useful for tracking)
        m2 = re.match(r"\* Serial Number: (.*)", line)
        if m2:
            # Store serial if meaningful
            pass

        # WPS Primary Device Type
        m2 = re.match(r"\* Primary Device Type: (.+)", line)
        if m2:
            # e.g. "6-0050F204-1" = Network Infrastructure Router
            pass

        # WPS Config Methods
        m2 = re.match(r"\* Config methods: (.+)", line)
        if m2:
            methods = m2.group(1)
            # "PushButton", "Keypad", "Display", "Ethernet", etc.
            current["wps_config_methods"] = methods
            continue

        # WPS RF Bands
        m2 = re.match(r"\* RF Bands: (.+)", line)
        if m2:
            pass

        # Protocol detection (802.11)
        m2 = re.match(r"\* Protocol: (.+)", line)
        if m2:
            current["protocol"] = m2.group(1).strip()
            continue

    # Add last network
    if current and (current.get("has_wps") or not wps_only):
        networks.append(current)

    # Detect manufacturer from BSSID if WPS didn't provide it
    for net in networks:
        if not net.get("wps_manufacturer"):
            mfr = detect_manufacturer(net["bssid"])
            if mfr:
                net["wps_manufacturer"] = mfr

    # Sort by signal strength (best first)
    networks.sort(key=lambda x: x["rssi"], reverse=True)
    return networks


def get_signal_bars(rssi):
    """Convert RSSI to visual signal bars"""
    if rssi >= -50:
        return "████"  # Excellent
    elif rssi >= -60:
        return "███░"  # Good
    elif rssi >= -70:
        return "██░░"  # Fair
    elif rssi >= -80:
        return "█░░░"  # Weak
    else:
        return "░░░░"  # Very weak
