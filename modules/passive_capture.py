#!/usr/bin/env python3
"""
Passive WPA Handshake Capture

Captures a real, authorized client handshake from a fixed channel without
packet injection. Designed for Qualcomm QCACLD monitor mode on Android.
Only use on networks and client devices you own or are authorized to test.
"""

import json
import os
import re
import shutil
import subprocess
import time
from datetime import datetime
from pathlib import Path

from modules.monitor_mode import (
    disable_monitor,
    enable_monitor,
    get_mode,
    set_channel,
)


CAPTURE_DIR = Path(__file__).parent.parent / "data" / "handshakes"
CAPTURE_DIR.mkdir(parents=True, exist_ok=True)


class PassiveHandshakeCapture:
    """Fixed-channel passive EAPOL capture and hc22000 conversion."""

    def __init__(self, interface="wlan0", tools=None):
        self.interface = interface
        self.callback = None
        self.output = []
        supplied = tools or {}
        self.tools = {
            "timeout": supplied.get("timeout") or shutil.which("timeout"),
            "tcpdump": supplied.get("tcpdump") or shutil.which("tcpdump"),
            "tshark": supplied.get("tshark") or shutil.which("tshark"),
            "hcxpcapngtool": supplied.get("hcxpcapngtool") or shutil.which("hcxpcapngtool"),
            "hcxhashtool": supplied.get("hcxhashtool") or shutil.which("hcxhashtool"),
        }

    def _log(self, message):
        self.output.append(message)
        if self.callback:
            self.callback(message)

    def _run(self, command, timeout):
        """Run every subprocess with capture, text mode, timeout and handling."""
        try:
            return subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes):
                stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes):
                stderr = stderr.decode(errors="replace")
            return subprocess.CompletedProcess(
                command,
                124,
                stdout=stdout,
                stderr=stderr,
            )
        except (FileNotFoundError, PermissionError, OSError) as exc:
            self._log("[!] Command failed: {err}".format(err=exc))
            return None
        except Exception as exc:
            self._log("[!] Command error: {err}".format(err=exc))
            return None

    @staticmethod
    def _normalize_bssid(bssid):
        value = (bssid or "").strip().upper()
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", value):
            return None
        return value

    def _missing_tools(self):
        required = ["timeout", "tcpdump", "tshark", "hcxpcapngtool", "hcxhashtool"]
        return [name for name in required if not self.tools.get(name)]

    def _capture_packets(self, pcap_path, duration):
        """Run tcpdump and return detailed capture diagnostics."""
        timeout_bin = self.tools["timeout"]
        tcpdump = self.tools["tcpdump"]
        command = [
            timeout_bin,
            "--foreground",
            "--signal=INT",
            "--kill-after=3",
            str(duration),
            tcpdump,
            "-i",
            self.interface,
            "-s",
            "0",
            "-B",
            "4096",
            "-U",
            "-Z",
            "root",
            "-w",
            str(pcap_path),
        ]
        self._log("[*] Passive capture started for {seconds}s".format(seconds=duration))
        self._log("[*] Capture interface: {iface}".format(iface=self.interface))
        result = self._run(command, timeout=duration + 8)

        diagnostics = {
            "ok": False,
            "exists": pcap_path.exists(),
            "size": 0,
            "returncode": None,
        }
        if result:
            diagnostics["returncode"] = result.returncode
            self._log("[*] tcpdump return code: {code}".format(
                code=result.returncode
            ))
            if result.stdout.strip():
                for line in result.stdout.splitlines():
                    if line.strip():
                        self._log("[tcpdump] " + line.strip())
            if result.stderr.strip():
                for line in result.stderr.splitlines():
                    if line.strip():
                        self._log("[tcpdump] " + line.strip())
        else:
            self._log("[!] tcpdump did not start")

        diagnostics["exists"] = pcap_path.exists()
        if diagnostics["exists"]:
            try:
                diagnostics["size"] = pcap_path.stat().st_size
            except OSError:
                diagnostics["size"] = 0
            self._log("[*] Capture file size: {size} bytes".format(
                size=diagnostics["size"]
            ))

        diagnostics["ok"] = bool(
            diagnostics["exists"] and diagnostics["size"] > 24
        )
        if diagnostics["exists"] and diagnostics["size"] == 24:
            self._log("[!] PCAP header exists, but the interface received zero frames")
        elif not diagnostics["exists"]:
            self._log("[!] tcpdump did not create the PCAP file")
        return diagnostics

    def _count_target_eapol(self, pcap_path, bssid):
        display_filter = "eapol && wlan.addr == {bssid}".format(
            bssid=bssid.lower()
        )
        command = [
            self.tools["tshark"],
            "-r",
            str(pcap_path),
            "-Y",
            display_filter,
            "-T",
            "fields",
            "-e",
            "frame.number",
        ]
        result = self._run(command, timeout=30)
        if not result:
            return 0
        return len([line for line in result.stdout.splitlines() if line.strip()])

    def _convert_capture(self, pcap_path, output_path):
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        command = [
            self.tools["hcxpcapngtool"],
            "-o",
            str(output_path),
            str(pcap_path),
        ]
        result = self._run(command, timeout=60)
        return bool(
            result
            and output_path.exists()
            and output_path.stat().st_size > 0
        )

    def _authorized_only(self, input_path, output_path):
        try:
            output_path.unlink(missing_ok=True)
        except OSError:
            pass
        command = [
            self.tools["hcxhashtool"],
            "-i",
            str(input_path),
            "-o",
            str(output_path),
            "--authorized",
        ]
        result = self._run(command, timeout=30)
        return bool(
            result
            and output_path.exists()
            and output_path.stat().st_size > 0
        )

    @staticmethod
    def _target_wpa02_lines(input_path, bssid):
        if not input_path.exists():
            return []
        target = bssid.replace(":", "").upper()
        found = []
        seen = set()
        try:
            with open(input_path, "r", errors="ignore") as handle:
                for raw_line in handle:
                    line = raw_line.strip()
                    if not line.startswith("WPA*02*"):
                        continue
                    parts = line.split("*")
                    if len(parts) < 9 or parts[3].upper() != target:
                        continue
                    if line not in seen:
                        seen.add(line)
                        found.append(line)
        except OSError:
            return []
        return found

    @staticmethod
    def _write_lines(output_path, lines):
        try:
            with open(output_path, "w") as handle:
                for line in lines:
                    handle.write(line + "\n")
            return True
        except OSError:
            return False

    def capture(self, bssid, essid, channel, width=0, duration=60, restore=True):
        """Capture and validate an authorized WPA*02 handshake."""
        result = {
            "status": "failed",
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "eapol_frames": 0,
            "hashes": 0,
            "files": [],
            "output": "",
        }

        normalized = self._normalize_bssid(bssid)
        if not normalized:
            result["status"] = "invalid_bssid"
            return result
        bssid = normalized
        result["bssid"] = bssid

        try:
            channel = int(channel)
            width = int(width)
            duration = max(10, min(int(duration), 600))
        except (TypeError, ValueError):
            result["status"] = "invalid_parameters"
            return result

        missing = self._missing_tools()
        if missing:
            result["status"] = "missing_tools"
            result["missing"] = missing
            self._log("[!] Missing tools: " + ", ".join(missing))
            result["output"] = "\n".join(self.output)
            return result

        if os.geteuid() != 0:
            result["status"] = "root_required"
            self._log("[!] Passive capture requires root")
            result["output"] = "\n".join(self.output)
            return result

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        short_bssid = bssid.replace(":", "")
        pcap_path = CAPTURE_DIR / "passive_{bssid}_{ts}.pcap".format(
            bssid=short_bssid,
            ts=timestamp,
        )
        all_hashes = CAPTURE_DIR / ".all_{bssid}_{ts}.hc22000".format(
            bssid=short_bssid,
            ts=timestamp,
        )
        authorized_hashes = CAPTURE_DIR / ".authorized_{bssid}_{ts}.hc22000".format(
            bssid=short_bssid,
            ts=timestamp,
        )
        target_hash = CAPTURE_DIR / "hs_real_{bssid}_{ts}.hc22000".format(
            bssid=short_bssid,
            ts=timestamp,
        )
        metadata_path = CAPTURE_DIR / "passive_{bssid}_{ts}.json".format(
            bssid=short_bssid,
            ts=timestamp,
        )
        log_path = CAPTURE_DIR / "passive_{bssid}_{ts}.log".format(
            bssid=short_bssid,
            ts=timestamp,
        )

        monitor_was_enabled = get_mode(self.interface) == "monitor"

        try:
            if not monitor_was_enabled:
                self._log("[*] Enabling monitor mode on {iface}".format(
                    iface=self.interface
                ))
                monitor_iface = enable_monitor(self.interface)
                if not monitor_iface:
                    result["status"] = "monitor_failed"
                    return result
                self.interface = monitor_iface

            if not set_channel(self.interface, channel, width):
                result["status"] = "channel_failed"
                self._log("[!] Could not set channel {channel}".format(
                    channel=channel
                ))
                return result

            self._log("[+] Monitor interface: {iface}".format(iface=self.interface))
            self._log("[+] Fixed channel: {channel}, width code: {width}".format(
                channel=channel,
                width=width,
            ))

            # QCACLD applies setMonChan asynchronously. Give firmware time
            # to finish switching before opening the packet socket.
            time.sleep(3)
            capture_details = self._capture_packets(pcap_path, duration)
            result["capture_size"] = capture_details["size"]
            result["tcpdump_returncode"] = capture_details["returncode"]
            if capture_details["exists"]:
                result["files"].append(str(pcap_path))
            if not capture_details["ok"]:
                result["status"] = "no_packets"
                self._log("[!] No 802.11 frames were saved")
                return result

            eapol_count = self._count_target_eapol(pcap_path, bssid)
            result["eapol_frames"] = eapol_count
            self._log("[*] Target EAPOL frames: {count}".format(count=eapol_count))

            if eapol_count == 0:
                result["status"] = "no_eapol"
                self._log("[!] No target EAPOL frames. Reconnect an authorized client and retry")
                return result

            if not self._convert_capture(pcap_path, all_hashes):
                result["status"] = "conversion_failed"
                self._log("[!] hcxpcapngtool did not produce hashes")
                return result

            all_target_lines = self._target_wpa02_lines(all_hashes, bssid)
            self._authorized_only(all_hashes, authorized_hashes)
            authorized_lines = self._target_wpa02_lines(authorized_hashes, bssid)

            if authorized_lines:
                if not self._write_lines(target_hash, authorized_lines):
                    result["status"] = "save_failed"
                    return result
                result["hashes"] = len(authorized_lines)
                result["files"].append(str(target_hash))
                result["status"] = "handshake_captured"
                self._log("[+] Real authorized handshake captured")
                self._log("[+] Hashes: {count}".format(count=len(authorized_lines)))
            elif all_target_lines:
                result["status"] = "challenge_only"
                self._log("[!] Only challenge M1/M2 found; no authorized M2/M3 pair")
                self._log("[!] Reconnect a client that knows the real network password")
            else:
                result["status"] = "no_target_hash"
                self._log("[!] EAPOL was seen but no target WPA*02 hash was produced")

        except KeyboardInterrupt:
            result["status"] = "stopped"
            self._log("[!] Capture stopped by user")
        except Exception as exc:
            result["status"] = "error"
            result["message"] = str(exc)
            self._log("[!] Passive capture error: {err}".format(err=exc))
        finally:
            for temporary in (all_hashes, authorized_hashes):
                try:
                    temporary.unlink(missing_ok=True)
                except OSError:
                    pass

            if restore:
                self._log("[*] Restoring managed mode and Android Wi-Fi")
                if not disable_monitor(self.interface):
                    self._log("[!] Automatic Wi-Fi restore reported a failure")

            metadata = {
                "status": result["status"],
                "bssid": bssid,
                "essid": essid,
                "channel": channel,
                "width": width,
                "duration": duration,
                "eapol_frames": result["eapol_frames"],
                "hashes": result["hashes"],
                "capture_size": result.get("capture_size", 0),
                "tcpdump_returncode": result.get("tcpdump_returncode"),
                "capture_file": str(pcap_path) if pcap_path.exists() else None,
                "hash_file": str(target_hash) if target_hash.exists() else None,
                "timestamp": timestamp,
            }
            try:
                with open(metadata_path, "w") as handle:
                    json.dump(metadata, handle, indent=2)
                result["files"].append(str(metadata_path))
            except OSError:
                pass

            try:
                with open(log_path, "w") as handle:
                    handle.write("\n".join(self.output) + "\n")
                result["files"].append(str(log_path))
            except OSError:
                pass

            result["output"] = "\n".join(self.output)

        return result
