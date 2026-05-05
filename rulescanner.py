"""
Rules Scanner - محرك توقيعات مرن
يبحث داخل الملفات عن نصوص وأنماط هيكس طبقاً لقواعد معرفة.
Read-only & safe.
"""
import os
import re
from pathlib import Path

# ---------- قاعدة بيانات القواعد (يمكن التوسع فيها) ----------
RULES = [
    # ---- قواعد عامة للملفات التنفيذية ----
    {
        "name": "MZ header with suspicious string",
        "description": "ملف PE يحتوي نصوص hack/inject",
        "severity": "High",
        "score": 80,
        "extensions": [".exe", ".dll"],
        "strings": ["cheat", "hacktool", "inject", "stealer"],
        "hex_patterns": [],
        "min_size": 1024
    },
    # ---- قواعد ماينكرافت JAR ----
    {
        "name": "JAR with cheat class names",
        "description": "ملف JAR يحتوي حزم hack/cheat",
        "severity": "High",
        "score": 75,
        "extensions": [".jar"],
        "strings": [
            "KillAura", "FlyHack", "SpeedHack", "ChestStealer",
            "XRay", "Freecam", "AutoClicker", "Aimbot",
            "net/minecraft/client/hack", "cheat/", "hack/client"
        ],
        "hex_patterns": [],
        "min_size": 100
    },
    {
        "name": "JAR with inject agent mainfest",
        "description": "MANIFEST.MF يشير إلى Agent-Class",
        "severity": "Medium",
        "score": 55,
        "extensions": [".jar"],
        "strings": ["Agent-Class:", "Launcher-Agent-Class:"],
        "hex_patterns": [],
        "min_size": 500
    },
    {
        "name": "JAR with embedded DLL",
        "description": "يحتوي JAR على مكتبة DLL",
        "severity": "Medium",
        "score": 40,
        "extensions": [".jar"],
        "strings": [],
        "hex_patterns": ["4D5A9000"],  # MZ signature
        "min_size": 1000
    },
    # ---- قواعد DLL injection ----
    {
        "name": "Known cheat DLL strings",
        "description": "مكتبة DLL تحتوي نصوص أدوات غش معروفة",
        "severity": "High",
        "score": 85,
        "extensions": [".dll"],
        "strings": ["Vape", "Sigma", "Wurst", "Meteor", "Raven", "cheatengine"],
        "hex_patterns": [],
        "min_size": 1024
    },
    # ---- قواعد ملفات التكوين ----
    {
        "name": "Suspicious config file",
        "description": "ملف إعدادات لأداة غش",
        "severity": "Medium",
        "score": 50,
        "extensions": [".txt", ".cfg", ".ini", ".json", ".yml"],
        "strings": ["killaura", "flyhack", "xray", "autoclicker", "cheat", "vape", "sigma"],
        "hex_patterns": [],
        "min_size": 10
    }
]

def match_rule_on_file(file_path, rule):
    """يفحص ملفاً واحداً تجاه قاعدة واحدة فقط، يُرجع (score, reasons) إذا انطبقت."""
    if not os.path.isfile(file_path):
        return 0, []
    
    ext = Path(file_path).suffix.lower()
    if rule.get("extensions") and ext not in rule["extensions"]:
        return 0, []
    
    # التحقق من الحجم الأدنى
    min_size = rule.get("min_size", 0)
    try:
        if os.path.getsize(file_path) < min_size:
            return 0, []
    except OSError:
        return 0, []
    
    reasons = []
    score = rule.get("score", 0)
    
    try:
        with open(file_path, "rb") as f:
            content = f.read()
    except Exception:
        return 0, []
    
    # البحث عن نصوص (strings)
    for s in rule.get("strings", []):
        # بحث بسيط كـ bytes
        if s.encode('utf-8', errors='ignore') in content:
            reasons.append(f"يحتوي النص: {s}")
            break  # نص واحد يكفي
    
    # البحث عن أنماط هيكس (hex patterns)
    for h in rule.get("hex_patterns", []):
        try:
            pattern = bytes.fromhex(h)
            if pattern in content:
                reasons.append(f"يحتوي نمط هيكس: {h}")
                break
        except Exception:
            pass
    
    if reasons:
        return score, reasons
    return 0, []

def scan_with_rules(file_path, rules=None):
    """
    تطبيق جميع القواعد على ملف واحد.
    يرجع (score, reasons) المجمعة من كل قاعدة مطابقة.
    """
    if rules is None:
        rules = RULES
    total_score = 0
    all_reasons = []
    for rule in rules:
        sc, res = match_rule_on_file(file_path, rule)
        if res:
            total_score += sc
            all_reasons.extend(res)
    if total_score > 0:
        return min(total_score, 100), all_reasons
    return 0, []