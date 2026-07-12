#!/usr/bin/env python3
"""Configuration management for WPS Toolkit"""

import json
from pathlib import Path

APP_DIR = Path(__file__).parent
DB_PATH = APP_DIR / "data" / "wps.db"
CFG_PATH = APP_DIR / "data" / "config.json"
REPORTS_DIR = APP_DIR / "reports"
LOGS_DIR = APP_DIR / "logs"

for d in [APP_DIR / "data", REPORTS_DIR, LOGS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

DEFAULTS = {
    "interface": "wlan0",
    "scan_timeout": 20,
    "auto_backup": True,
    "dont_touch_settings": True,
    "restore_processes": True,
    "verbose": False,
    "min_rssi_online": -85,
    "lab_mode": False,
    "require_force_phrase": True,
}

class Config:
    def __init__(self):
        self.data = DEFAULTS.copy()
        if CFG_PATH.exists():
            try:
                with open(CFG_PATH) as f:
                    self.data.update(json.load(f))
            except Exception:
                pass

    def save(self):
        with open(CFG_PATH, "w") as f:
            json.dump(self.data, f, indent=2)

    def get(self, key, default=None):
        return self.data.get(key, default if default is not None else DEFAULTS.get(key))

    def set(self, key, value):
        self.data[key] = value
        self.save()
