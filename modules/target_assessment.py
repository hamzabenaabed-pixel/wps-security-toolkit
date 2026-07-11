#!/usr/bin/env python3
"""
Offline-first target assessment and method planner.

This module does not transmit attack traffic. It combines scan information,
versioned WPS PIN intelligence, device limitations, and capture feasibility to
recommend the least intrusive authorized test path.
"""

from modules.wps_pins import (
    detect_manufacturer,
    get_database_pins,
    get_pin_database_info,
    is_vulnerable_model,
    suggest_pins,
)


def _field(network, key, default=None):
    try:
        value = network[key]
    except (KeyError, IndexError, TypeError):
        return default
    return default if value is None else value


class TargetAssessor:
    """Build a repeatable assessment report for one scanned access point."""

    def __init__(self, internal_monitor=True, internal_injection=False):
        self.internal_monitor = bool(internal_monitor)
        self.internal_injection = bool(internal_injection)

    @staticmethod
    def _signal_grade(rssi):
        if rssi == 0:
            return "unknown"
        if rssi >= -60:
            return "excellent"
        if rssi >= -70:
            return "good"
        if rssi >= -80:
            return "fair"
        if rssi >= -85:
            return "weak"
        return "very_weak"

    def assess(self, network):
        bssid = str(_field(network, "bssid", "")).upper()
        essid = str(_field(network, "essid", "Hidden"))
        encryption = str(_field(network, "encryption", "Unknown"))
        encryption_upper = encryption.upper()
        wps_locked = str(_field(network, "wps_locked", "Unknown"))
        raw_wps = _field(network, "has_wps", 0)
        if isinstance(raw_wps, str):
            has_wps = raw_wps.strip().lower() in ("1", "yes", "true", "on")
        else:
            has_wps = bool(raw_wps)
        model = str(_field(network, "wps_model", "") or "")
        device = str(_field(network, "wps_device", "") or "")

        try:
            channel = int(_field(network, "channel", 0) or 0)
        except (TypeError, ValueError):
            channel = 0
        try:
            rssi = int(_field(network, "rssi", 0) or 0)
        except (TypeError, ValueError):
            rssi = 0

        manufacturer, algorithm, algorithm_confidence = detect_manufacturer(bssid)
        manufacturer = manufacturer or "Unknown"
        vulnerable_model, vulnerable_match = is_vulnerable_model(model, device)
        database_pins = get_database_pins(bssid, limit=16)
        suggestions = suggest_pins(bssid, str(_field(network, "wps_version", "")), wps_locked)
        database_info = get_pin_database_info()

        is_wpa2 = "WPA2" in encryption_upper or "WPA/WPA2" in encryption_upper
        is_wpa3_only = "WPA3" in encryption_upper and "WPA2" not in encryption_upper
        is_open_or_wep = encryption_upper in ("OPEN", "WEP")
        wps_available = has_wps and wps_locked.lower() != "yes"

        warnings = []
        if rssi == 0:
            warnings.append("Signal level is unavailable; run a fresh scan before testing")
        elif rssi <= -85:
            warnings.append("Signal is too weak for reliable WPS/EAPOL exchanges")
        elif rssi <= -80:
            warnings.append("Signal is weak; move closer before online testing")
        if wps_locked.lower() == "yes":
            warnings.append("WPS is locked; do not start online PIN attempts")
        if not has_wps:
            warnings.append("WPS was not detected in the latest scan")
        if is_open_or_wep:
            warnings.append("PMKID and WPA EAPOL handshakes do not apply to Open/WEP")
        if is_wpa3_only:
            warnings.append("WPA3-only target is not compatible with PMKID/WPA2 cracking")
        if essid.lower() == "hidden":
            warnings.append("Hidden ESSID requires the exact network name")
        if not self.internal_injection:
            warnings.append("Internal QCACLD interface is receive-only; injection methods are unavailable")

        score = 10
        if rssi == 0:
            score += 0
        elif rssi >= -60:
            score += 30
        elif rssi >= -70:
            score += 24
        elif rssi >= -80:
            score += 16
        elif rssi >= -85:
            score += 8

        if is_wpa2:
            score += 15
        elif is_wpa3_only:
            score += 5
        elif is_open_or_wep:
            score -= 10

        if wps_available:
            score += 20
        elif has_wps:
            score -= 5
        if database_pins:
            score += 15
        if vulnerable_model:
            score += 10
        score = max(0, min(100, score))

        pmkid_candidate = bool(is_wpa2)
        passive_candidate = bool(is_wpa2 and self.internal_monitor)
        pixie_candidate = bool(wps_available)

        attack_order = []
        if wps_available and database_pins:
            attack_order.append("known_pin_sweep")
        if wps_available:
            attack_order.append("pixie_probe")
            attack_order.append("calculated_pin_sweep")
        if pmkid_candidate:
            attack_order.append("managed_pmkid_probe")
        if passive_candidate:
            attack_order.append("passive_handshake_wait")
        if not self.internal_injection:
            attack_order.append("external_adapter_if_active_capture_required")

        if wps_available and database_pins:
            recommended = "Suggested PIN Sweep (versioned known-default database)"
        elif wps_available and vulnerable_model:
            recommended = "Pixie Dust probe, then calculated PIN sweep"
        elif wps_available:
            recommended = "Calculated PIN sweep, then one Pixie Dust probe"
        elif pmkid_candidate:
            recommended = "Managed PMKID probe; passive handshake if a client reconnects"
        elif passive_candidate:
            recommended = "Passive handshake wait"
        else:
            recommended = "No compatible internal Wi-Fi method"

        top_candidates = []
        for suggestion in suggestions[:12]:
            top_candidates.append({
                "pin": suggestion.get("pin", ""),
                "method": suggestion.get("method", ""),
                "confidence": suggestion.get("confidence", 0),
                "priority": suggestion.get("priority", 99),
            })

        return {
            "bssid": bssid,
            "essid": essid,
            "channel": channel,
            "rssi": rssi,
            "signal_grade": self._signal_grade(rssi),
            "encryption": encryption,
            "has_wps": has_wps,
            "wps_locked": wps_locked,
            "manufacturer": manufacturer,
            "algorithm": algorithm or "generic",
            "algorithm_confidence": algorithm_confidence,
            "model": model,
            "device": device,
            "vulnerable_model": vulnerable_model,
            "vulnerable_match": vulnerable_match,
            "known_pin_count": len(database_pins),
            "best_pin": top_candidates[0]["pin"] if top_candidates else "",
            "pin_candidates": top_candidates,
            "pixie_candidate": pixie_candidate,
            "pmkid_candidate": pmkid_candidate,
            "passive_candidate": passive_candidate,
            "internal_monitor": self.internal_monitor,
            "internal_injection": self.internal_injection,
            "readiness_score": score,
            "recommended_method": recommended,
            "attack_order": attack_order,
            "warnings": warnings,
            "intelligence_version": database_info.get("database_version", "unavailable"),
            "intelligence_prefixes": database_info.get("prefix_count", 0),
            "intelligence_pins": database_info.get("pin_count", 0),
        }
