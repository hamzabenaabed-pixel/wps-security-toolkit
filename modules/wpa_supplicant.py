#!/usr/bin/env python3
"""
wpa_supplicant Manager Module v2
Complete management of wpa_supplicant via wpa_cli
Works on managed mode - no monitor mode needed
"""

import os
import subprocess
import re
import time
import threading
from pathlib import Path


class WpaSupplicant:
    """Complete wpa_supplicant manager via wpa_cli"""

    def __init__(self, iface="wlan1"):
        self.iface = iface
        self.ctrl_dir = f"/var/run/wpa_supplicant/{iface}"

    def _cli(self, cmd, timeout=5):
        """Run wpa_cli command"""
        try:
            full = ["wpa_cli", "-i", self.iface] + (cmd if isinstance(cmd, list) else [cmd])
            r = subprocess.run(full, capture_output=True, text=True, timeout=timeout)
            return r.stdout.strip(), r.returncode
        except subprocess.TimeoutExpired:
            return "TIMEOUT", -1
        except FileNotFoundError:
            return "wpa_cli not found", -1
        except Exception as e:
            return str(e), -1

    # ═══════════════════════════════════════════
    # STATUS & INFO
    # ═══════════════════════════════════════════

    def is_running(self):
        """Check if wpa_supplicant is running on this interface"""
        out, rc = self._cli("status")
        return rc == 0 and "wpa_state" in out

    def status(self):
        """Get full connection status"""
        info = {
            "running": False, "state": "INACTIVE",
            "ssid": "", "bssid": "", "ip": "",
            "freq": "", "key_mgmt": "", "mac": "",
            "pairwise_cipher": "", "group_cipher": "",
            "wpa_state": "", "uuid": "",
        }
        out, rc = self._cli("status")
        if rc == 0 and "wpa_state" in out:
            info["running"] = True
            for line in out.split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    mapping = {
                        "wpa_state": "state", "ssid": "ssid",
                        "bssid": "bssid", "ip_address": "ip",
                        "freq": "freq", "key_mgmt": "key_mgmt",
                        "address": "mac", "pairwise_cipher": "pairwise_cipher",
                        "group_cipher": "group_cipher", "uuid": "uuid",
                    }
                    key = mapping.get(k, k)
                    info[key] = v
        return info

    def signal_poll(self):
        """Get signal strength information"""
        out, rc = self._cli("SIGNAL_POLL")
        info = {}
        if rc == 0:
            for line in out.split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip()
        return info

    def ping(self):
        """Test wpa_cli connection"""
        out, rc = self._cli("PING")
        return rc == 0 and "PONG" in out

    def driver_info(self):
        """Get driver capabilities"""
        out, rc = self._cli("DRIVER")
        return out

    def mib(self):
        """Get MIB (Management Information Base) counters"""
        out, rc = self._cli("MIB")
        info = {}
        if rc == 0:
            for line in out.split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip()
        return info

    # ═══════════════════════════════════════════
    # SCANNING
    # ═══════════════════════════════════════════

    def scan(self):
        """Trigger a scan"""
        out, rc = self._cli("scan")
        return rc == 0 and "OK" in out

    def scan_results(self):
        """Get scan results as list of dicts"""
        # Trigger scan first
        self.scan()
        time.sleep(3)

        networks = []
        out, rc = self._cli("scan_results")
        if rc != 0:
            return networks

        for line in out.split("\n"):
            if line.startswith("bssid") or not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) < 5:
                continue

            bssid = parts[0].strip().upper()
            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
                continue

            freq = parts[1].strip()
            signal = parts[2].strip()
            flags = parts[3].strip()
            ssid = parts[4].strip() if len(parts) > 4 else ""

            # Parse flags
            enc = "Open"
            cipher = ""
            auth = ""
            has_wps = 0
            wps_version = ""

            if "[WPA-PSK" in flags:
                enc = "WPA"
                auth = "PSK"
            if "[WPA2-PSK" in flags:
                enc = "WPA2"
                auth = "PSK"
            if "[WPA3-SAE" in flags:
                enc = "WPA3"
                auth = "SAE"
            if "CCMP" in flags:
                cipher = "CCMP"
            elif "TKIP" in flags:
                cipher = "TKIP"
            if "[WPS]" in flags:
                has_wps = 1
                wps_version = "1.0"  # Default, detailed version from iw scan

            # Convert frequency to channel
            channel = 0
            try:
                f = int(freq)
                if 2412 <= f <= 2484:
                    channel = 14 if f == 2484 else (f - 2412) // 5 + 1
                elif 5170 <= f <= 5825:
                    channel = (f - 5170) // 5 + 34
            except (ValueError, TypeError):
                pass

            net = {
                "bssid": bssid,
                "essid": ssid if ssid and not ssid.startswith("\\x") else "Hidden",
                "channel": channel,
                "frequency": int(freq) if freq.isdigit() else 0,
                "rssi": int(signal) if signal.lstrip("-").isdigit() else 0,
                "has_wps": has_wps,
                "wps_locked": "Unknown",
                "wps_version": wps_version,
                "wps_device": "",
                "wps_model": "",
                "encryption": enc,
                "cipher": cipher,
                "auth": auth,
                "source": "wpa_cli",
            }
            networks.append(net)

        networks.sort(key=lambda x: x["rssi"], reverse=True)
        return networks

    def bss_info(self, index=0):
        """Get detailed BSS information"""
        out, rc = self._cli(["BSS", str(index)])
        info = {}
        if rc == 0:
            for line in out.split("\n"):
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip()
        return info

    def bss_flush(self):
        """Clear BSS cache"""
        out, rc = self._cli("BSS_FLUSH")
        return rc == 0

    # ═══════════════════════════════════════════
    # NETWORK MANAGEMENT
    # ═══════════════════════════════════════════

    def add_network(self):
        """Add a new empty network, returns network ID"""
        out, rc = self._cli("add_network")
        if rc == 0 and out.strip().isdigit():
            return int(out.strip())
        return None

    def remove_network(self, net_id):
        """Remove network by ID or 'all'"""
        out, rc = self._cli(["remove_network", str(net_id)])
        return rc == 0

    def list_networks(self):
        """List all saved networks"""
        out, rc = self._cli("list_networks")
        networks = []
        if rc == 0:
            for line in out.split("\n")[1:]:  # Skip header
                parts = line.split("\t")
                if len(parts) >= 2:
                    networks.append({
                        "id": parts[0],
                        "ssid": parts[1],
                        "bssid": parts[2] if len(parts) > 2 else "any",
                        "flags": parts[3] if len(parts) > 3 else "",
                    })
        return networks

    def set_network(self, net_id, key, value):
        """Set network parameter"""
        out, rc = self._cli(["set_network", str(net_id), key, value])
        return rc == 0 and "OK" in out

    def get_network(self, net_id, key):
        """Get network parameter"""
        out, rc = self._cli(["get_network", str(net_id), key])
        if rc == 0:
            return out.strip().strip('"')
        return None

    def select_network(self, net_id):
        """Select and connect to network"""
        out, rc = self._cli(["select_network", str(net_id)])
        return rc == 0

    def enable_network(self, net_id):
        """Enable network"""
        out, rc = self._cli(["enable_network", str(net_id)])
        return rc == 0

    def disable_network(self, net_id):
        """Disable network"""
        out, rc = self._cli(["disable_network", str(net_id)])
        return rc == 0

    def save_config(self):
        """Save current config to file"""
        out, rc = self._cli("save_config")
        return rc == 0

    # ═══════════════════════════════════════════
    # CONNECTION
    # ═══════════════════════════════════════════

    def connect(self, ssid, psk=None, key_mgmt=None, hidden=False):
        """Connect to a network"""
        net_id = self.add_network()
        if net_id is None:
            return False, "Failed to add network"

        # Set SSID
        if not self.set_network(net_id, "ssid", f'"{ssid}"'):
            return False, "Failed to set SSID"

        # Set hidden network flag
        if hidden:
            self.set_network(net_id, "scan_ssid", "1")

        # Set authentication
        if key_mgmt:
            self.set_network(net_id, "key_mgmt", key_mgmt)
        elif psk:
            if len(psk) >= 8:
                self.set_network(net_id, "psk", f'"{psk}"')
                self.set_network(net_id, "key_mgmt", "WPA-PSK")
            else:
                # WEP or other
                self.set_network(net_id, "key_mgmt", "NONE")
                self.set_network(net_id, "wep_key0", f'"{psk}"')
        else:
            # Open network
            self.set_network(net_id, "key_mgmt", "NONE")

        # Connect
        self.select_network(net_id)
        self.enable_network(net_id)
        self.save_config()

        # Wait for connection
        for _ in range(15):
            time.sleep(1)
            st = self.status()
            if st.get("state") == "COMPLETED":
                return True, f"Connected to {ssid}"

        return False, "Connection timeout"

    def connect_eap(self, ssid, identity, password, eap="PEAP"):
        """Connect to enterprise (EAP) network"""
        net_id = self.add_network()
        if net_id is None:
            return False, "Failed to add network"

        self.set_network(net_id, "ssid", f'"{ssid}"')
        self.set_network(net_id, "key_mgmt", "WPA-EAP")
        self.set_network(net_id, "eap", eap)
        self.set_network(net_id, "identity", f'"{identity}"')
        self.set_network(net_id, "password", f'"{password}"')

        self.select_network(net_id)
        self.enable_network(net_id)
        self.save_config()

        for _ in range(20):
            time.sleep(1)
            st = self.status()
            if st.get("state") == "COMPLETED":
                return True, f"Connected to {ssid}"

        return False, "Connection timeout"

    def connect_open(self, ssid, hidden=False):
        """Connect to open network"""
        return self.connect(ssid, psk=None, hidden=hidden)

    def connect_wep(self, ssid, key):
        """Connect to WEP network"""
        net_id = self.add_network()
        if net_id is None:
            return False, "Failed"

        self.set_network(net_id, "ssid", f'"{ssid}"')
        self.set_network(net_id, "key_mgmt", "NONE")
        self.set_network(net_id, "wep_key0", f'"{key}"')

        self.select_network(net_id)
        self.enable_network(net_id)
        self.save_config()

        for _ in range(10):
            time.sleep(1)
            st = self.status()
            if st.get("state") == "COMPLETED":
                return True, f"Connected to {ssid}"
        return False, "Failed"

    def disconnect(self):
        """Disconnect from current network"""
        out, rc = self._cli("disconnect")
        return rc == 0

    def reconnect(self):
        """Reconnect to current network"""
        out, rc = self._cli("reconnect")
        return rc == 0

    def reassociate(self):
        """Reassociate with current AP"""
        out, rc = self._cli("reassociate")
        return rc == 0

    # ═══════════════════════════════════════════
    # WPS OPERATIONS
    # ═══════════════════════════════════════════

    def wps_pin(self, bssid=None, pin=None):
        """Start WPS PIN session"""
        if bssid and pin:
            out, rc = self._cli(["WPS_PIN", bssid, pin])
        elif bssid:
            out, rc = self._cli(["WPS_PIN", bssid])
        else:
            out, rc = self._cli("WPS_PIN any")
        return rc == 0, out

    def wps_pbc(self, bssid=None):
        """Start WPS Push Button session"""
        if bssid:
            out, rc = self._cli(["WPS_PBC", bssid])
        else:
            out, rc = self._cli("WPS_PBC")
        return rc == 0, out

    def wps_cancel(self):
        """Cancel WPS operation"""
        out, rc = self._cli("WPS_CANCEL")
        return rc == 0

    def wps_reg(self, bssid, pin):
        """Start WPS Registrar session (used by ose.py)"""
        out, rc = self._cli(["WPS_REG", bssid, pin])
        return rc == 0, out

    # ═══════════════════════════════════════════
    # SECURITY
    # ═══════════════════════════════════════════

    def preauthenticate(self, bssid):
        """Initiate PMKSA preauthentication"""
        out, rc = self._cli(["PREAUTH", bssid])
        return rc == 0

    def tdls_discover(self, addr):
        """TDLS peer discovery"""
        out, rc = self._cli(["TDLS_DISCOVER", addr])
        return rc == 0

    def tdls_setup(self, addr):
        """TDLS setup"""
        out, rc = self._cli(["TDLS_SETUP", addr])
        return rc == 0

    def tdls_teardown(self, addr):
        """TDLS teardown"""
        out, rc = self._cli(["TDLS_TEARDOWN", addr])
        return rc == 0

    def tdls_status(self, addr):
        """TDLS status"""
        out, rc = self._cli(["TDLS_STATUS", addr])
        return out

    # ═══════════════════════════════════════════
    # CONTROL INTERFACE
    # ═══════════════════════════════════════════

    def attach(self):
        """Subscribe to wpa_supplicant events"""
        out, rc = self._cli("ATTACH")
        return rc == 0

    def detach(self):
        """Unsubscribe from events"""
        out, rc = self._cli("DETACH")
        return rc == 0

    def set_level(self, level):
        """Set event verbosity (0=minimal, 1=normal, 2=verbose)"""
        out, rc = self._cli(["LEVEL", str(level)])
        return rc == 0

    def reconfigure(self):
        """Reload configuration"""
        out, rc = self._cli("RECONFIGURE")
        return rc == 0

    def relog(self):
        """Reopen log files"""
        out, rc = self._cli("RELOG")
        return rc == 0

    def set_global(self, var, value):
        """Set global variable"""
        out, rc = self._cli(["SET", var, value])
        return rc == 0

    def get_global(self, var):
        """Get global variable"""
        out, rc = self._cli(["GET", var])
        return out if rc == 0 else None

    # ═══════════════════════════════════════════
    # PROCESS MANAGEMENT
    # ═══════════════════════════════════════════

    def start(self, conf_path=None):
        """Start wpa_supplicant process"""
        if self.is_running():
            return True

        if not conf_path:
            candidates = [
                f"/etc/wpa_supplicant/wpa_supplicant-{self.iface}.conf",
                "/etc/wpa_supplicant/wpa_supplicant.conf",
                f"/tmp/wpa_supplicant_{self.iface}.conf",
            ]
            for c in candidates:
                if os.path.exists(c):
                    conf_path = c
                    break

        if not conf_path:
            conf_path = f"/tmp/wpa_supplicant_{self.iface}.conf"
            with open(conf_path, "w") as f:
                f.write(f"ctrl_interface=/var/run/wpa_supplicant\n")
                f.write("update_config=1\ncountry=LB\n")

        try:
            subprocess.run(["ip", "link", "set", self.iface, "up"],
                          capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(1)

        # Kill existing on this interface
        try:
            subprocess.run(["wpa_cli", "-i", self.iface, "terminate"],
                          capture_output=True, timeout=3)
            time.sleep(1)
        except Exception:
            pass

        try:
            subprocess.Popen(
                ["wpa_supplicant", "-B", "-i", self.iface,
                 "-c", conf_path, "-D", "nl80211,wext"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        except Exception:
            return False

        for _ in range(8):
            time.sleep(1)
            if self.is_running():
                return True
        return False

    def stop(self):
        """Stop wpa_supplicant"""
        out, rc = self._cli("terminate")
        return rc == 0

    def restart(self, conf_path=None):
        """Restart wpa_supplicant"""
        self.stop()
        time.sleep(2)
        return self.start(conf_path)

    # ═══════════════════════════════════════════
    # CONVENIENCE METHODS
    # ═══════════════════════════════════════════

    def get_saved_passwords(self):
        """Extract saved passwords from config"""
        passwords = []
        nets = self.list_networks()
        for net in nets:
            nid = net["id"]
            psk = self.get_network(nid, "psk")
            key_mgmt = self.get_network(nid, "key_mgmt")
            if psk and psk != "FAILED":
                passwords.append({
                    "id": nid,
                    "ssid": net["ssid"],
                    "key_mgmt": key_mgmt,
                    "psk": psk.strip('"'),
                })
        return passwords

    def forget_network(self, ssid_or_id):
        """Remove a saved network by SSID or ID"""
        nets = self.list_networks()
        for net in nets:
            if net["id"] == str(ssid_or_id) or net["ssid"] == ssid_or_id:
                self.remove_network(net["id"])
                self.save_config()
                return True
        return False

    def is_connected(self):
        """Check if currently connected"""
        st = self.status()
        return st.get("state") == "COMPLETED"

    def get_ip(self):
        """Get current IP address"""
        st = self.status()
        return st.get("ip", "")

    def get_connected_ssid(self):
        """Get current connected SSID"""
        st = self.status()
        return st.get("ssid", "")

    def get_connected_bssid(self):
        """Get current AP BSSID"""
        st = self.status()
        return st.get("bssid", "")

    def wait_for_connection(self, timeout=30):
        """Wait until connected"""
        for _ in range(timeout):
            if self.is_connected():
                return True
            time.sleep(1)
        return False

    def scan_and_display(self):
        """Scan and return formatted results"""
        nets = self.scan_results()
        return nets

    def connect_hidden(self, ssid, psk=None):
        """Connect to hidden network"""
        return self.connect(ssid, psk, hidden=True)

    def roaming_scan(self):
        """Perform scan for roaming (find better APs)"""
        out, rc = self._cli("SCAN")
        time.sleep(2)
        out2, rc2 = self._cli("SCAN_RESULTS")
        return out2 if rc2 == 0 else ""

    def get_bssid_list(self):
        """Get list of known BSSIDs"""
        out, rc = self._cli("BSS_RANGE")
        return out

    def set_ap_scan(self, mode):
        """Set AP scan mode (0=auto, 1=wpa_supplicant, 2=hostapd)"""
        out, rc = self._cli(["AP_SCAN", str(mode)])
        return rc == 0

    def get_capability(self, what="eap"):
        """Get driver capability"""
        out, rc = self._cli(["GET_CAPABILITY", what])
        return out if rc == 0 else ""

    def note(self, net_id, text):
        """Add note to network (stores in extra_data field)"""
        # wpa_supplicant doesn't have native notes,
        # but we can store in our DB
        pass
