"""
Obfuscation Detector – Safe Scanner Ultimate
يكشف تمويه ملفات JAR والسلاسل المشفرة.
Read-only.
"""
import zipfile
import re
from pathlib import Path

# ---------- مؤشرات التمويه ----------
OBFUSCATION_INDICATORS = {
    "Allatori": ["a.class", "Allatori", "ALLATORI"],
    "ZKM": ["ZKM", "zelix", "Zelix KlassMaster"],
    "Stringer": ["Stringer", "stringer"],
    "DashO": ["DashO", "dasho"],
    "ProGuard": ["proguard"],
    "Paramorphism": ["paramorphism"],
}

# نمط Base64 طويل (مشفر عادة)
BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/=]{50,}')
# نمط XOR بسيط (سلاسل غير طبيعية فيها أحرف عشوائية)
XOR_PATTERN = re.compile(r'[\x00-\x08\x0e-\x1f\x80-\xff]{10,}')

def detect_obfuscation(jar_path):
    """
    فحص JAR لاكتشاف أدوات التمويه والسلاسل المشفرة.
    يُرجع (reasons, score).
    """
    if not zipfile.is_zipfile(jar_path):
        return ["ليس ملف JAR صالحاً"], 0

    reasons = []
    score = 0
    found_obfuscator = None

    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            entries = zf.namelist()

            # 1. البحث عن ملفات تدل على أداة التمويه
            for obf_name, indicators in OBFUSCATION_INDICATORS.items():
                for entry in entries:
                    for ind in indicators:
                        if ind.lower() in entry.lower():
                            reasons.append(f"تم العثور على أداة تمويه: {obf_name}")
                            score += 70
                            found_obfuscator = obf_name
                            break
                    if found_obfuscator:
                        break
                if found_obfuscator:
                    break

            # 2. البحث عن أسماء كلاسات عشوائية (حرف واحد أو اثنين)
            short_names = [e for e in entries if e.endswith('.class') and len(Path(e).stem) <= 2]
            if len(short_names) > 5:
                reasons.append(f"أسماء كلاسات قصيرة جداً ({len(short_names)} كلاس) – مؤشر تمويه")
                score += 50

            # 3. فحص محتوى MANIFEST
            try:
                manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                if "Obfuscated" in manifest or "obfuscated" in manifest:
                    reasons.append("MANIFEST يشير إلى تمويه")
                    score += 30
                if "Allatori" in manifest or "ZKM" in manifest:
                    reasons.append(f"MANIFEST يحتوي إشارة إلى {found_obfuscator or 'مموه'}")
                    score += 40
            except:
                pass

            # 4. قراءة بعض الكلاسات والبحث عن سلاسل Base64 طويلة أو XOR
            base64_count = 0
            xor_count = 0
            for entry in entries[:20]:  # أول 20 كلاس فقط للسرعة
                if entry.endswith('.class'):
                    try:
                        data = zf.read(entry)
                        try:
                            text = data.decode('utf-8', errors='ignore')
                        except:
                            text = data.decode('latin-1', errors='ignore')
                        if BASE64_PATTERN.search(text):
                            base64_count += 1
                        if XOR_PATTERN.search(text):
                            xor_count += 1
                    except:
                        continue

            if base64_count > 3:
                reasons.append("وجود سلاسل Base64 طويلة (مؤشر تشفير)")
                score += 40
            if xor_count > 3:
                reasons.append("وجود سلاسل XOR/مشوشة")
                score += 45

    except Exception as e:
        reasons.append(f"خطأ في فتح JAR: {e}")
        score += 10

    if not reasons:
        reasons.append("لم يُكتشف تمويه واضح")
        score = 0
    return reasons, min(score, 100)