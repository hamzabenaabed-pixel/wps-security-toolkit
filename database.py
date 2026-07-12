#!/usr/bin/env python3
"""Thread-safe SQLite database for WPS Toolkit"""

import json
import sqlite3
import threading
import shutil
from datetime import datetime
from config import DB_PATH

WPS_PIN_DB_PATH = DB_PATH.parent / "wps_pin_database.json"

class Database:
    SCHEMA = """
    CREATE TABLE IF NOT EXISTS networks(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT UNIQUE NOT NULL,
        essid TEXT,
        channel INTEGER DEFAULT 0,
        frequency INTEGER DEFAULT 0,
        rssi INTEGER DEFAULT 0,
        has_wps INTEGER DEFAULT 0,
        wps_locked TEXT DEFAULT 'Unknown',
        wps_version TEXT,
        wps_device TEXT,
        wps_model TEXT,
        encryption TEXT,
        cipher TEXT,
        auth TEXT,
        first_seen TEXT DEFAULT (datetime('now','localtime')),
        last_seen TEXT DEFAULT (datetime('now','localtime')),
        scan_count INTEGER DEFAULT 1,
        scan_source TEXT,
        notes TEXT,
        is_target INTEGER DEFAULT 0,
        status TEXT DEFAULT 'new'
    );
    CREATE TABLE IF NOT EXISTS sessions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT,
        essid TEXT,
        attack_type TEXT,
        start_time TEXT DEFAULT (datetime('now','localtime')),
        end_time TEXT,
        status TEXT DEFAULT 'running',
        pin_found TEXT,
        psk_found TEXT,
        attempts INTEGER DEFAULT 0,
        log_path TEXT
    );
    CREATE TABLE IF NOT EXISTS credentials(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT,
        essid TEXT,
        pin TEXT,
        psk TEXT,
        method TEXT,
        captured_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS activity_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT DEFAULT (datetime('now','localtime')),
        event_type TEXT,
        category TEXT,
        message TEXT,
        severity TEXT DEFAULT 'info'
    );
    CREATE TABLE IF NOT EXISTS scan_history(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_time TEXT DEFAULT (datetime('now','localtime')),
        interface TEXT,
        method TEXT,
        duration INTEGER,
        found INTEGER DEFAULT 0,
        new_count INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS intelligence_meta(
        key TEXT PRIMARY KEY,
        value TEXT,
        updated_at TEXT DEFAULT (datetime('now','localtime'))
    );
    CREATE TABLE IF NOT EXISTS wps_pin_database(
        prefix TEXT NOT NULL,
        pin TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence INTEGER DEFAULT 80,
        version TEXT,
        PRIMARY KEY(prefix,pin,source)
    );
    CREATE INDEX IF NOT EXISTS idx_wps_pin_prefix
        ON wps_pin_database(prefix);
    CREATE TABLE IF NOT EXISTS target_assessments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        essid TEXT,
        assessed_at TEXT DEFAULT (datetime('now','localtime')),
        channel INTEGER DEFAULT 0,
        rssi INTEGER DEFAULT 0,
        encryption TEXT,
        has_wps INTEGER DEFAULT 0,
        wps_locked TEXT,
        manufacturer TEXT,
        model TEXT,
        known_pin_count INTEGER DEFAULT 0,
        best_pin TEXT,
        pixie_candidate INTEGER DEFAULT 0,
        pmkid_candidate INTEGER DEFAULT 0,
        passive_candidate INTEGER DEFAULT 0,
        readiness_score INTEGER DEFAULT 0,
        recommended_method TEXT,
        warnings TEXT,
        intelligence_version TEXT,
        report_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_assessment_bssid_time
        ON target_assessments(bssid,assessed_at DESC);
    CREATE TABLE IF NOT EXISTS wps_pin_attempts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        pin TEXT NOT NULL,
        attempted_at TEXT DEFAULT (datetime('now','localtime')),
        status TEXT,
        response TEXT,
        duration REAL DEFAULT 0,
        session_id INTEGER,
        UNIQUE(bssid,pin)
    );
    CREATE INDEX IF NOT EXISTS idx_wps_attempt_bssid
        ON wps_pin_attempts(bssid,attempted_at DESC);
    CREATE TABLE IF NOT EXISTS router_audits(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target_ip TEXT NOT NULL,
        started_at TEXT DEFAULT (datetime('now','localtime')),
        finished_at TEXT,
        brand TEXT,
        confidence INTEGER DEFAULT 0,
        title TEXT,
        open_ports TEXT,
        auth_status TEXT,
        username TEXT,
        password TEXT,
        auth_method TEXT,
        summary TEXT,
        warnings TEXT,
        report_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_router_audits_ip_time
        ON router_audits(target_ip, started_at DESC);
    CREATE TABLE IF NOT EXISTS router_probe_state(
        target_ip TEXT PRIMARY KEY,
        brand TEXT,
        window_started_at TEXT,
        attempts_in_window INTEGER DEFAULT 0,
        total_attempts INTEGER DEFAULT 0,
        last_attempt_at TEXT,
        last_auth_status TEXT,
        last_detail TEXT,
        lockout_until TEXT,
        lockout_count INTEGER DEFAULT 0,
        last_lockout_at TEXT,
        verified_at TEXT,
        updated_at TEXT DEFAULT (datetime('now','localtime')),
        extra_json TEXT
    );
    CREATE TABLE IF NOT EXISTS vuln_lookups(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        queried_at TEXT DEFAULT (datetime('now','localtime')),
        vendor TEXT,
        model TEXT,
        title TEXT,
        online INTEGER DEFAULT 0,
        match_count INTEGER DEFAULT 0,
        report_json TEXT
    );

    CREATE TABLE IF NOT EXISTS candidate_pins(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT NOT NULL,
        essid TEXT,
        pin TEXT NOT NULL,
        source TEXT,
        status TEXT DEFAULT 'unverified',
        confidence INTEGER DEFAULT 50,
        notes TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime')),
        verified_at TEXT,
        psk TEXT,
        UNIQUE(bssid,pin)
    );
    CREATE INDEX IF NOT EXISTS idx_candidate_pins_bssid
        ON candidate_pins(bssid, created_at DESC);
    CREATE TABLE IF NOT EXISTS evidence_index(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        bssid TEXT,
        essid TEXT,
        action TEXT,
        status TEXT,
        path TEXT,
        created_at TEXT DEFAULT (datetime('now','localtime'))
    );
    """

    def __init__(self):
        self.conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            cur = self.conn.cursor()
            cur.executescript(self.SCHEMA)
            self.conn.commit()
        self.sync_wps_intelligence()

    def execute(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            self.conn.commit()
            return cur

    def fetch_one(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur.fetchone()

    def fetch_all(self, query, params=()):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute(query, params)
            return cur.fetchall()

    # ── Networks ──
    def add_network(self, net):
        existing = self.fetch_one("SELECT id FROM networks WHERE bssid=?", (net["bssid"],))
        if existing:
            self.execute(
                """UPDATE networks SET essid=?,channel=?,frequency=?,rssi=?,
                   has_wps=?,wps_locked=?,wps_version=?,wps_device=?,wps_model=?,
                   encryption=?,cipher=?,auth=?,last_seen=datetime('now','localtime'),
                   scan_count=scan_count+1,scan_source=? WHERE bssid=?""",
                (net.get("essid"),net.get("channel"),net.get("frequency"),
                 net.get("rssi"),net.get("has_wps",0),net.get("wps_locked","Unknown"),
                 net.get("wps_version"),net.get("wps_device"),net.get("wps_model"),
                 net.get("encryption"),net.get("cipher"),net.get("auth"),
                 net.get("source",""),net["bssid"]))
            return existing["id"]
        cur = self.execute(
            """INSERT INTO networks(bssid,essid,channel,frequency,rssi,has_wps,
               wps_locked,wps_version,wps_device,wps_model,encryption,cipher,auth,scan_source)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (net["bssid"],net.get("essid"),net.get("channel"),net.get("frequency"),
             net.get("rssi"),net.get("has_wps",0),net.get("wps_locked","Unknown"),
             net.get("wps_version"),net.get("wps_device"),net.get("wps_model"),
             net.get("encryption"),net.get("cipher"),net.get("auth"),net.get("source","")))
        return cur.lastrowid

    def get_all_networks(self):
        return self.fetch_all("SELECT * FROM networks ORDER BY last_seen DESC")

    def get_network(self, bssid):
        return self.fetch_one("SELECT * FROM networks WHERE bssid=?", (bssid,))

    def get_targets(self):
        return self.fetch_all("SELECT * FROM networks WHERE is_target=1 ORDER BY last_seen DESC")

    def set_target(self, nid, val=True):
        self.execute("UPDATE networks SET is_target=? WHERE id=?", (1 if val else 0, nid))

    def search_networks(self, q):
        pattern = "%{q}%".format(q=q)
        return self.fetch_all(
            "SELECT * FROM networks WHERE essid LIKE ? OR bssid LIKE ? OR notes LIKE ?",
            (pattern, pattern, pattern),
        )

    def get_activity_summary(self, limit=20):
        """Recent activity for dashboard / reports."""
        return self.fetch_all(
            """SELECT timestamp, event_type, category, message, severity
               FROM activity_log ORDER BY timestamp DESC, id DESC LIMIT ?""",
            (int(limit),),
        )

    def get_stats(self):
        s = {}
        s["total"] = self.fetch_one("SELECT COUNT(*) c FROM networks")["c"]
        s["wps"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1")["c"]
        s["wps_open"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1 AND wps_locked='No'")["c"]
        s["wps_locked"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE has_wps=1 AND wps_locked='Yes'")["c"]
        s["targets"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE is_target=1")["c"]
        s["compromised"] = self.fetch_one("SELECT COUNT(*) c FROM networks WHERE status='compromised'")["c"]
        return s

    # ── Sessions ──
    def create_session(self, bssid, essid, attack_type):
        cur = self.execute("INSERT INTO sessions(bssid,essid,attack_type) VALUES(?,?,?)",
                          (bssid,essid,attack_type))
        return cur.lastrowid

    def update_session(self, sid, **kwargs):
        """Update session fields. Only allow known column names."""
        allowed = {
            "bssid", "essid", "attack_type", "start_time", "end_time",
            "status", "pin_found", "psk_found", "attempts", "log_path",
        }
        clean = {k: v for k, v in kwargs.items() if k in allowed}
        if not clean:
            return
        sets = ",".join("{col}=?".format(col=k) for k in clean)
        query = "UPDATE sessions SET {sets} WHERE id=?".format(sets=sets)
        self.execute(query, (*clean.values(), sid))

    def get_sessions(self, limit=50):
        return self.fetch_all("SELECT * FROM sessions ORDER BY start_time DESC LIMIT ?",(limit,))

    def get_active_sessions(self):
        return self.fetch_all("SELECT * FROM sessions WHERE status='running'")

    # ── Credentials ──
    def add_credential(self, bssid, essid, pin, psk, method):
        """
        Store a credential row.

        Safety: WPS-style methods require a non-empty PSK to be treated as a
        real success. PIN-only inserts are rejected for those methods so the
        vault does not accumulate misleading false positives.
        """
        pin_text = (pin or "").strip() or None
        psk_text = (psk or "").strip() or None
        method_text = (method or "").strip() or "unknown"
        method_upper = method_text.upper()

        wps_like = any(
            token in method_upper
            for token in (
                "WPS", "PIXIE", "SMART ATTACK", "AUTO-WPS", "PIN (",
                "SUGGESTED PIN", "BEST-PIN", "PBC",
            )
        )
        if wps_like and not psk_text:
            self.log(
                "credential_rejected",
                "security",
                "Rejected PIN-only credential for {bssid} method={method}".format(
                    bssid=bssid or "?",
                    method=method_text,
                ),
                severity="warn",
            )
            return None

        cur = self.execute(
            "INSERT INTO credentials(bssid,essid,pin,psk,method) VALUES(?,?,?,?,?)",
            (bssid, essid, pin_text, psk_text, method_text),
        )
        if psk_text and bssid:
            try:
                self.execute(
                    "UPDATE networks SET status='compromised' WHERE bssid=?",
                    (bssid,),
                )
            except Exception:
                pass
        return cur.lastrowid

    def get_credentials(self):
        return self.fetch_all("SELECT * FROM credentials ORDER BY captured_at DESC")

    def get_suspicious_wps_credentials(self):
        """Find legacy WPS credentials that contain a PIN but no PSK."""
        return self.fetch_all(
            """SELECT * FROM credentials
               WHERE COALESCE(pin,'') != ''
               AND COALESCE(psk,'') = ''
               AND (
                   method LIKE 'Smart Attack%'
                   OR method LIKE 'Pixie Dust%'
                   OR method LIKE 'Direct WPS%'
                   OR method LIKE 'Auto-WPS%'
                   OR method LIKE 'Suggested PIN Sweep%'
                   OR method LIKE 'Smart Best-PIN Test%'
                   OR method LIKE 'PIN (%'
               )
               ORDER BY captured_at DESC"""
        )

    def delete_credentials(self, credential_ids):
        """Delete selected credential rows by id."""
        ids = [int(value) for value in credential_ids]
        if not ids:
            return 0
        placeholders = ",".join("?" for _ in ids)
        query = "DELETE FROM credentials WHERE id IN ({items})".format(
            items=placeholders
        )
        cur = self.execute(query, tuple(ids))
        return cur.rowcount

    # ── Activity Log ──
    def log(self, event_type, category, message, severity="info"):
        self.execute("INSERT INTO activity_log(event_type,category,message,severity) VALUES(?,?,?,?)",
                    (event_type,category,message,severity))

    def get_log(self, limit=50):
        return self.fetch_all("SELECT * FROM activity_log ORDER BY timestamp DESC LIMIT ?",(limit,))

    # ── Scan History ──
    def add_scan_record(self, iface, method, duration, found, new):
        self.execute("INSERT INTO scan_history(interface,method,duration,found,new_count) VALUES(?,?,?,?,?)",
                    (iface,method,duration,found,new))

    # ── WPS Intelligence ──
    def sync_wps_intelligence(self):
        """Import the bundled versioned OUI/PIN snapshot into SQLite."""
        try:
            with open(WPS_PIN_DB_PATH, "r") as handle:
                payload = json.load(handle)
        except (OSError, ValueError, TypeError):
            return {"status": "unavailable", "prefixes": 0, "pins": 0}

        version = str(payload.get("database_version", "unknown"))
        generated_at = str(payload.get("generated_at", ""))
        source_data = payload.get("source", {})
        source_name = str(source_data.get("name", "bundled_wps_db"))
        source_url = str(source_data.get("url", ""))
        source_sha256 = str(source_data.get("sha256", ""))
        source_license = str(source_data.get("license", ""))
        source_attribution = str(source_data.get("attribution", ""))
        prefixes = payload.get("prefixes", {})
        rows = []
        if isinstance(prefixes, dict):
            for prefix, pins in prefixes.items():
                clean_prefix = str(prefix).replace(":", "").upper()[:6]
                if len(clean_prefix) != 6:
                    continue
                for index, pin in enumerate(pins if isinstance(pins, list) else []):
                    pin_text = str(pin)
                    if not pin_text.isdigit() or len(pin_text) != 8:
                        continue
                    confidence = max(70, 90 - index)
                    rows.append((clean_prefix, pin_text, source_name, confidence, version))

        with self.lock:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT value FROM intelligence_meta WHERE key='wps_database_version'"
            )
            current = cur.fetchone()
            cur.execute("SELECT COUNT(*) c FROM wps_pin_database")
            current_count = cur.fetchone()["c"]
            if current and current["value"] == version and current_count == len(rows):
                return {
                    "status": "current",
                    "version": version,
                    "prefixes": len(prefixes),
                    "pins": len(rows),
                }

            cur.execute("DELETE FROM wps_pin_database")
            cur.executemany(
                """INSERT OR REPLACE INTO wps_pin_database
                   (prefix,pin,source,confidence,version) VALUES(?,?,?,?,?)""",
                rows,
            )
            metadata = {
                "wps_database_version": version,
                "wps_database_source": source_name,
                "wps_database_source_url": source_url,
                "wps_database_source_sha256": source_sha256,
                "wps_database_license": source_license,
                "wps_database_attribution": source_attribution,
                "wps_database_generated_at": generated_at,
                "wps_database_prefixes": str(len(prefixes)),
                "wps_database_pins": str(len(rows)),
            }
            for key, value in metadata.items():
                cur.execute(
                    """INSERT OR REPLACE INTO intelligence_meta(key,value,updated_at)
                       VALUES(?,?,datetime('now','localtime'))""",
                    (key, value),
                )
            self.conn.commit()

        return {
            "status": "updated",
            "version": version,
            "prefixes": len(prefixes),
            "pins": len(rows),
        }

    def get_intelligence_stats(self):
        with self.lock:
            cur = self.conn.cursor()
            cur.execute("SELECT key,value FROM intelligence_meta")
            metadata = {row["key"]: row["value"] for row in cur.fetchall()}
            cur.execute("SELECT COUNT(DISTINCT prefix) c FROM wps_pin_database")
            prefix_count = cur.fetchone()["c"]
            cur.execute("SELECT COUNT(*) c FROM wps_pin_database")
            pin_count = cur.fetchone()["c"]
        return {
            "version": metadata.get("wps_database_version", "unavailable"),
            "source": metadata.get("wps_database_source", ""),
            "source_url": metadata.get("wps_database_source_url", ""),
            "source_sha256": metadata.get("wps_database_source_sha256", ""),
            "license": metadata.get("wps_database_license", ""),
            "attribution": metadata.get("wps_database_attribution", ""),
            "generated_at": metadata.get("wps_database_generated_at", ""),
            "prefixes": prefix_count,
            "pins": pin_count,
        }

    def get_known_wps_pins(self, bssid, limit=16):
        prefix = (bssid or "").replace(":", "").replace("-", "").upper()[:6]
        return self.fetch_all(
            """SELECT pin,source,confidence,version FROM wps_pin_database
               WHERE prefix=? ORDER BY confidence DESC,pin LIMIT ?""",
            (prefix, int(limit)),
        )

    # ── Target Assessments ──
    def save_assessment(self, report):
        warnings = report.get("warnings", [])
        warnings_text = json.dumps(warnings, ensure_ascii=False)
        report_text = json.dumps(report, ensure_ascii=False, sort_keys=True)
        cur = self.execute(
            """INSERT INTO target_assessments(
               bssid,essid,channel,rssi,encryption,has_wps,wps_locked,
               manufacturer,model,known_pin_count,best_pin,pixie_candidate,
               pmkid_candidate,passive_candidate,readiness_score,
               recommended_method,warnings,intelligence_version,report_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report.get("bssid"), report.get("essid"), report.get("channel", 0),
                report.get("rssi", 0), report.get("encryption", ""),
                1 if report.get("has_wps") else 0, report.get("wps_locked", "Unknown"),
                report.get("manufacturer", "Unknown"), report.get("model", ""),
                report.get("known_pin_count", 0), report.get("best_pin", ""),
                1 if report.get("pixie_candidate") else 0,
                1 if report.get("pmkid_candidate") else 0,
                1 if report.get("passive_candidate") else 0,
                report.get("readiness_score", 0),
                report.get("recommended_method", ""), warnings_text,
                report.get("intelligence_version", ""), report_text,
            ),
        )
        return cur.lastrowid

    def get_latest_assessment(self, bssid):
        return self.fetch_one(
            """SELECT * FROM target_assessments WHERE bssid=?
               ORDER BY assessed_at DESC,id DESC LIMIT 1""",
            (bssid,),
        )

    # ── WPS Attempt Resume State ──
    def record_wps_attempt(self, bssid, pin, status, response="", duration=0, session_id=None):
        self.execute(
            """INSERT OR REPLACE INTO wps_pin_attempts
               (bssid,pin,attempted_at,status,response,duration,session_id)
               VALUES(?,?,datetime('now','localtime'),?,?,?,?)""",
            (bssid, pin, status, response, float(duration), session_id),
        )

    def get_attempted_wps_pins(self, bssid):
        rows = self.fetch_all(
            "SELECT pin FROM wps_pin_attempts WHERE bssid=? ORDER BY attempted_at",
            (bssid,),
        )
        return {row["pin"] for row in rows}

    def get_wps_attempt_progress(self, bssid):
        total = self.fetch_one(
            "SELECT COUNT(*) c FROM wps_pin_attempts WHERE bssid=?",
            (bssid,),
        )["c"]
        latest = self.fetch_one(
            """SELECT pin,status,attempted_at FROM wps_pin_attempts
               WHERE bssid=? ORDER BY attempted_at DESC,id DESC LIMIT 1""",
            (bssid,),
        )
        return {"attempted": total, "latest": dict(latest) if latest else None}

    # ── Router web audits ──
    def save_router_audit(self, report):
        """Persist a router web-audit report. Only store verified auth secrets."""
        if not isinstance(report, dict):
            return None

        fingerprint = report.get("fingerprint") or {}
        creds = report.get("credentials") or []
        verified = [c for c in creds if c.get("status") == "success"]
        chosen = verified[0] if verified else {}

        # Never persist unverified passwords
        username = chosen.get("username") if chosen else None
        password = chosen.get("password") if chosen else None
        auth_method = chosen.get("method") if chosen else None
        auth_status = report.get("auth_status") or (
            "success" if verified else "unknown"
        )

        open_ports = report.get("open_ports") or []
        warnings = report.get("warnings") or []
        cur = self.execute(
            """INSERT INTO router_audits(
               target_ip,started_at,finished_at,brand,confidence,title,
               open_ports,auth_status,username,password,auth_method,
               summary,warnings,report_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                report.get("ip"),
                report.get("started_at"),
                report.get("finished_at"),
                fingerprint.get("brand"),
                int(fingerprint.get("confidence") or 0),
                fingerprint.get("title"),
                json.dumps(open_ports, ensure_ascii=False),
                auth_status,
                username,
                password,
                auth_method,
                report.get("summary"),
                json.dumps(warnings, ensure_ascii=False),
                json.dumps(report, ensure_ascii=False, default=str),
            ),
        )
        self.log(
            "router_audit",
            "router",
            "Audit {ip} brand={brand} auth={auth}".format(
                ip=report.get("ip"),
                brand=fingerprint.get("brand"),
                auth=auth_status,
            ),
        )
        return cur.lastrowid

    def get_router_audits(self, limit=50):
        return self.fetch_all(
            """SELECT id,target_ip,started_at,brand,confidence,auth_status,
                      username,summary,title
               FROM router_audits
               ORDER BY started_at DESC,id DESC LIMIT ?""",
            (int(limit),),
        )

    def get_router_audit(self, audit_id):
        return self.fetch_one(
            "SELECT * FROM router_audits WHERE id=?",
            (int(audit_id),),
        )

    def get_probe_state(self, target_ip):
        return self.fetch_one(
            "SELECT * FROM router_probe_state WHERE target_ip=?",
            (str(target_ip or "").strip(),),
        )

    def upsert_probe_state(self, target_ip, state):
        """Insert/update smart probe state for one target IP."""
        target_ip = str(target_ip or "").strip()
        if not target_ip:
            return None
        extra = {
            k: v for k, v in (state or {}).items()
            if k not in {
                "target_ip", "brand", "window_started_at", "attempts_in_window",
                "total_attempts", "last_attempt_at", "last_auth_status",
                "last_detail", "lockout_until", "lockout_count",
                "last_lockout_at", "verified_at", "updated_at", "extra_json",
            }
        }
        return self.execute(
            """INSERT INTO router_probe_state(
               target_ip,brand,window_started_at,attempts_in_window,total_attempts,
               last_attempt_at,last_auth_status,last_detail,lockout_until,
               lockout_count,last_lockout_at,verified_at,updated_at,extra_json
               ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,datetime('now','localtime'),?)
               ON CONFLICT(target_ip) DO UPDATE SET
                 brand=excluded.brand,
                 window_started_at=excluded.window_started_at,
                 attempts_in_window=excluded.attempts_in_window,
                 total_attempts=excluded.total_attempts,
                 last_attempt_at=excluded.last_attempt_at,
                 last_auth_status=excluded.last_auth_status,
                 last_detail=excluded.last_detail,
                 lockout_until=excluded.lockout_until,
                 lockout_count=excluded.lockout_count,
                 last_lockout_at=excluded.last_lockout_at,
                 verified_at=excluded.verified_at,
                 updated_at=datetime('now','localtime'),
                 extra_json=excluded.extra_json
            """,
            (
                target_ip,
                state.get("brand"),
                state.get("window_started_at"),
                int(state.get("attempts_in_window") or 0),
                int(state.get("total_attempts") or 0),
                state.get("last_attempt_at"),
                state.get("last_auth_status"),
                state.get("last_detail"),
                state.get("lockout_until"),
                int(state.get("lockout_count") or 0),
                state.get("last_lockout_at"),
                state.get("verified_at"),
                json.dumps(extra, ensure_ascii=False, default=str) if extra else None,
            ),
        )

    def clear_probe_lockout(self, target_ip):
        self.execute(
            """UPDATE router_probe_state
               SET lockout_until=NULL, updated_at=datetime('now','localtime')
               WHERE target_ip=?""",
            (str(target_ip or "").strip(),),
        )

    def save_vuln_lookup(self, report):
        query = (report or {}).get("query") or {}
        offline = (report or {}).get("offline") or {}
        cur = self.execute(
            """INSERT INTO vuln_lookups(vendor,model,title,online,match_count,report_json)
               VALUES(?,?,?,?,?,?)""",
            (
                query.get("vendor"),
                query.get("model"),
                query.get("title"),
                1 if query.get("online") else 0,
                int(offline.get("match_count") or len((report or {}).get("cves") or [])),
                json.dumps(report, ensure_ascii=False, default=str),
            ),
        )
        return cur.lastrowid

    def get_vuln_lookups(self, limit=30):
        return self.fetch_all(
            """SELECT id,queried_at,vendor,model,title,online,match_count
               FROM vuln_lookups ORDER BY queried_at DESC,id DESC LIMIT ?""",
            (int(limit),),
        )

    # ── Maintenance ──
    
    # ── Candidate PINs (Pixie offline hits, etc.) ──
    def save_candidate_pin(self, bssid, pin, essid="", source="pixie", confidence=70, notes="", status="unverified"):
        pin = (pin or "").strip()
        bssid = (bssid or "").upper()
        if not pin or not bssid:
            return None
        cur = self.execute(
            """INSERT INTO candidate_pins(bssid,essid,pin,source,status,confidence,notes)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(bssid,pin) DO UPDATE SET
                 essid=excluded.essid,
                 source=excluded.source,
                 status=excluded.status,
                 confidence=excluded.confidence,
                 notes=excluded.notes
            """,
            (bssid, essid, pin, source, status, int(confidence), notes),
        )
        self.log("candidate_pin", "wps", "Saved candidate PIN for {b} from {s}".format(b=bssid, s=source))
        return cur.lastrowid

    def get_candidate_pins(self, bssid=None, limit=50):
        if bssid:
            return self.fetch_all(
                """SELECT * FROM candidate_pins WHERE bssid=?
                   ORDER BY created_at DESC LIMIT ?""",
                (str(bssid).upper(), int(limit)),
            )
        return self.fetch_all(
            "SELECT * FROM candidate_pins ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        )

    def mark_candidate_verified(self, bssid, pin, psk):
        self.execute(
            """UPDATE candidate_pins
               SET status='verified', psk=?, verified_at=datetime('now','localtime')
               WHERE bssid=? AND pin=?""",
            (psk, str(bssid).upper(), str(pin)),
        )

    def save_evidence_index(self, bssid, essid, action, status, path):
        return self.execute(
            """INSERT INTO evidence_index(bssid,essid,action,status,path)
               VALUES(?,?,?,?,?)""",
            (bssid, essid, action, status, path),
        ).lastrowid

    def backup(self):
        fname = "bk_{ts}.db".format(ts=datetime.now().strftime("%Y%m%d_%H%M%S"))
        dest = DB_PATH.parent.parent / "reports" / fname
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Prefer a consistent SQLite snapshot when possible
        try:
            with self.lock:
                backup_conn = sqlite3.connect(str(dest))
                try:
                    self.conn.backup(backup_conn)
                finally:
                    backup_conn.close()
        except Exception:
            shutil.copy2(DB_PATH, dest)
        return str(dest)

    def close(self):
        with self.lock:
            self.conn.close()
