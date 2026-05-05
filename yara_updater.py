"""
YARA Rules Updater – Safe Scanner Ultimate
يحمل قواعد YARA جديدة من GitHub (اختياري).
Read-only.
"""
import os
import json
import urllib.request
from pathlib import Path
from datetime import datetime

# مستودع افتراضي لقواعد YARA (يمكن تغييره)
DEFAULT_RULES_URL = "https://raw.githubusercontent.com/YARA-Rules/rules/master/index.json"

def update_yara_rules(progress_callback=None):
    """
    محاولة تحميل أحدث القواعد من المستودع الافتراضي.
    يُرجع (success, message).
    """
    try:
        if progress_callback:
            progress_callback(0, 1, "جارٍ الاتصال بالمستودع...")
        req = urllib.request.Request(DEFAULT_RULES_URL)
        with urllib.request.urlopen(req, timeout=10) as response:
            data = json.loads(response.read().decode())
        if progress_callback:
            progress_callback(1, 1, "اكتمل التحميل")
        # حفظ محلي
        rules_file = Path("updated_yara_rules.json")
        with open(rules_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True, f"تم تحميل {len(data)} قاعدة"
    except Exception as e:
        return False, str(e)