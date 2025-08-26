import os
from typing import Dict, Any, List

from androguard.core.bytecodes.apk import APK

# Define risky permissions and weights for rule-based scoring
DANGEROUS_PERMISSIONS_WEIGHTS = {
    "android.permission.SEND_SMS": 25,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.WRITE_SMS": 20,
    "android.permission.READ_CONTACTS": 20,
    "android.permission.WRITE_CONTACTS": 20,
    "android.permission.READ_CALL_LOG": 15,
    "android.permission.WRITE_CALL_LOG": 15,
    "android.permission.CALL_PHONE": 15,
    "android.permission.RECORD_AUDIO": 30,
    "android.permission.CAMERA": 25,
    "android.permission.READ_PHONE_STATE": 15,
    "android.permission.PROCESS_OUTGOING_CALLS": 15,
    "android.permission.ACCESS_FINE_LOCATION": 15,
    "android.permission.ACCESS_COARSE_LOCATION": 10,
    "android.permission.READ_EXTERNAL_STORAGE": 10,
    "android.permission.WRITE_EXTERNAL_STORAGE": 10,
    "android.permission.REQUEST_INSTALL_PACKAGES": 25,
    "android.permission.SYSTEM_ALERT_WINDOW": 30,
}


CLASSIFICATION_THRESHOLDS = {
    "Clean": (0, 29),
    "Suspicious": (30, 59),
    "Malicious": (60, 1000),
}


def classify_score(score: int) -> str:
    for label, (low, high) in CLASSIFICATION_THRESHOLDS.items():
        if low <= score <= high:
            return label
    return "Clean"


def analyze_apk(apk_path: str) -> Dict[str, Any]:
    """Perform static analysis on APK and compute risk score."""
    if not os.path.exists(apk_path):
        raise FileNotFoundError("APK file not found")

    apk = APK(apk_path)
    permissions: List[str] = sorted(apk.get_permissions())

    score_breakdown: List[Dict[str, Any]] = []
    total_score = 0
    for perm in permissions:
        if perm in DANGEROUS_PERMISSIONS_WEIGHTS:
            weight = DANGEROUS_PERMISSIONS_WEIGHTS[perm]
            total_score += weight
            score_breakdown.append({
                "label": perm,
                "weight": weight,
                "reason": "Permission considered high risk"
            })

    # Bonus rules for certain combinations
    combination_rules = [
        ({"android.permission.CAMERA", "android.permission.RECORD_AUDIO"}, 10, "May enable stealth recording"),
        ({"android.permission.SEND_SMS", "android.permission.READ_CONTACTS"}, 10, "Could exfiltrate contacts via SMS"),
        ({"android.permission.SYSTEM_ALERT_WINDOW"}, 10, "Can draw over apps; used in phishing overlays"),
    ]

    perm_set = set(permissions)
    for req_perms, bonus, reason in combination_rules:
        if req_perms.issubset(perm_set):
            total_score += bonus
            score_breakdown.append({
                "label": "+".join(sorted(req_perms)),
                "weight": bonus,
                "reason": reason
            })

    classification = classify_score(total_score)

    info = {
        "app_name": apk.get_app_name() or "Unknown",
        "package_name": apk.get_package() or "Unknown",
        "version_name": apk.get_androidversion_name() or "Unknown",
        "version_code": apk.get_androidversion_code() or "Unknown",
        "permissions": permissions,
        "risk_score": total_score,
        "classification": classification,
        "score_breakdown": score_breakdown,
    }

    return info
