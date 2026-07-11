#!/usr/bin/env python3
"""
Monitor Mode Manager v2

Supports two backends:
- Qualcomm Android QCACLD/ICNSS via /sys/module/wlan/parameters/con_mode
- Standard Linux mac80211 via airmon-ng / nl80211
"""

import os
import re
import shutil
import subprocess
import time
from pathlib import Path


CON_MODE_PATH = Path("/sys/module/wlan/parameters/con_mode")
SYSTEM_SVC = Path("/system/bin/svc")


def _run(command, timeout=10):
    """Run a command with the subprocess safety rules used by the toolkit."""
    try:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, PermissionError, OSError):
        return None
    except Exception:
        return None


def _tool(name):
    """Return an executable path when available."""
    return shutil.which(name) or name


def _physical_iface(iface):
    """QCACLD monitor mode is exposed on the physical wlan0 interface."""
    if CON_MODE_PATH.exists() and Path("/sys/class/net/wlan0").exists():
        return "wlan0"
    return iface


def is_qualcomm_monitor():
    """Return True when the Android QCACLD con_mode switch is present."""
    return CON_MODE_PATH.exists()


def _set_android_wifi(enabled):
    """Enable or disable Android Wi-Fi service when /system/bin/svc is visible."""
    svc = str(SYSTEM_SVC) if SYSTEM_SVC.exists() else shutil.which("svc")
    if not svc:
        return False
    action = "enable" if enabled else "disable"
    result = _run([svc, "wifi", action], timeout=10)
    return bool(result and result.returncode == 0)


def _write_con_mode(value):
    """Write QCACLD connection mode. Requires toolkit to run as root."""
    try:
        with open(CON_MODE_PATH, "w") as handle:
            handle.write(str(value))
        return True
    except (OSError, PermissionError):
        return False


def get_mode(iface):
    target = _physical_iface(iface)
    result = _run([_tool("iw"), "dev", target, "info"], timeout=5)
    if not result:
        return "unknown"
    match = re.search(r"type\s+(\w+)", result.stdout)
    return match.group(1) if match else "unknown"


def enable_monitor(iface):
    """Enable monitor mode and return the actual monitor interface."""
    target = _physical_iface(iface)

    # Qualcomm Android must not use airmon-ng. It creates an unsuitable
    # virtual interface and channel/FCS errors on QCACLD/ICNSS drivers.
    if is_qualcomm_monitor():
        _set_android_wifi(False)
        time.sleep(3)

        down = _run([_tool("ip"), "link", "set", target, "down"], timeout=5)
        if not down or down.returncode != 0:
            return None

        if not _write_con_mode(4):
            return None
        time.sleep(2)

        up = _run([_tool("ip"), "link", "set", target, "up"], timeout=5)
        if not up or up.returncode != 0:
            _write_con_mode(0)
            return None

        time.sleep(2)
        if get_mode(target) == "monitor":
            return target

        _write_con_mode(0)
        return None

    # Standard mac80211 path.
    _run([_tool("airmon-ng"), "check", "kill"], timeout=15)
    time.sleep(1)

    result = _run([_tool("airmon-ng"), "start", target], timeout=15)
    if result:
        output = result.stdout + result.stderr
        monitors = re.findall(r"([A-Za-z0-9_.-]+mon[A-Za-z0-9_.-]*)", output)
        if monitors:
            return monitors[0]

    down = _run([_tool("ip"), "link", "set", target, "down"], timeout=5)
    changed = _run(
        [_tool("iw"), "dev", target, "set", "type", "monitor"],
        timeout=5,
    )
    up = _run([_tool("ip"), "link", "set", target, "up"], timeout=5)
    if not down or not changed or not up:
        return None
    if down.returncode != 0 or changed.returncode != 0 or up.returncode != 0:
        return None

    time.sleep(1)
    return target if get_mode(target) == "monitor" else None


def disable_monitor(iface):
    """Restore managed mode and Android Wi-Fi service."""
    target = _physical_iface(iface)

    if is_qualcomm_monitor():
        _run([_tool("ip"), "link", "set", target, "down"], timeout=5)
        restored = _write_con_mode(0)
        time.sleep(2)
        up = _run([_tool("ip"), "link", "set", target, "up"], timeout=5)
        _set_android_wifi(True)
        time.sleep(2)
        return bool(restored and up and up.returncode == 0)

    _run([_tool("airmon-ng"), "stop", target], timeout=15)
    time.sleep(1)
    _run([_tool("ip"), "link", "set", target, "down"], timeout=5)
    changed = _run(
        [_tool("iw"), "dev", target, "set", "type", "managed"],
        timeout=5,
    )
    up = _run([_tool("ip"), "link", "set", target, "up"], timeout=5)
    return bool(changed and up and changed.returncode == 0 and up.returncode == 0)


def kill_processes():
    result = _run([_tool("airmon-ng"), "check", "kill"], timeout=15)
    return result.stdout if result else ""


def set_channel(iface, channel, width=0):
    """
    Set monitor channel.

    Qualcomm width values: 0=20 MHz, 1=40 MHz, 2=80 MHz.
    The function tries the QCACLD private ioctl first, then nl80211.
    """
    target = _physical_iface(iface)
    try:
        channel_num = int(channel)
        width_num = int(width)
    except (TypeError, ValueError):
        return False

    if is_qualcomm_monitor():
        iwpriv = shutil.which("iwpriv")
        if iwpriv:
            result = _run(
                [iwpriv, target, "setMonChan", str(channel_num), str(width_num)],
                timeout=8,
            )
            if result and result.returncode == 0:
                return True

    width_name = {0: "HT20", 1: "HT40+", 2: "80MHz"}.get(width_num, "HT20")
    command = [_tool("iw"), "dev", target, "set", "channel", str(channel_num)]
    if width_num in (0, 1):
        command.append(width_name)
    result = _run(command, timeout=8)
    return bool(result and result.returncode == 0)


def iface_up(iface):
    target = _physical_iface(iface)
    result = _run([_tool("ip"), "link", "set", target, "up"], timeout=5)
    return bool(result and result.returncode == 0)


def iface_down(iface):
    target = _physical_iface(iface)
    result = _run([_tool("ip"), "link", "set", target, "down"], timeout=5)
    return bool(result and result.returncode == 0)


def get_iw_dev():
    result = _run([_tool("iw"), "dev"], timeout=5)
    if not result:
        return "Error"
    return result.stdout + result.stderr
