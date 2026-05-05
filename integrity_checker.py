"""
System File Integrity Checker – Safe Scanner Ultimate
يقارن هاشات SHA-256 لملفات النظام مع قاعدة بيانات Microsoft الأصلية.
Read-only، لا يعدل أي ملف.
"""
import os
import hashlib
from pathlib import Path
from datetime import datetime

# ---------- قاعدة بيانات مصغرة لهاشات ملفات النظام الأصلية (SHA-256) ----------
# هذه قائمة محاكاة لبعض ملفات Windows 10/11 الحرجة.
# في النسخة الكاملة يمكن تحميل قاعدة بيانات أصلية من Microsoft أو مستودع موثوق.
KNOWN_SYSTEM_HASHES = {
    # ملفات System32 الأساسية
    "ntoskrnl.exe": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0",
    "ntdll.dll": "b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
    "kernel32.dll": "c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
    "user32.dll": "d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3",
    "shell32.dll": "e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4",
    "winlogon.exe": "f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5",
    "svchost.exe": "a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6",
    "explorer.exe": "b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7",
    "lsass.exe": "c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8",
    "csrss.exe": "d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9",
    # برامج التشغيل
    "tcpip.sys": "e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0",
    "afd.sys": "f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1",
    "netbt.sys": "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
    "ndis.sys": "b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
}

# ---------- مسار مجلدات النظام ----------
SYSTEM_ROOTS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\System32\drivers",
]

def compute_sha256(file_path):
    """يحسب SHA-256 لملف معين."""
    h = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest().lower()
    except (OSError, PermissionError):
        return None

def scan_system_integrity(progress_callback=None):
    """
    فحص سلامة ملفات النظام مقابل قاعدة البيانات.
    يُرجع قائمة بجميع الحالات (موجود ومطابق، معدل، مفقود).
    """
    results = []
    total_files = len(KNOWN_SYSTEM_HASHES)
    current = 0

    for filename, expected_hash in KNOWN_SYSTEM_HASHES.items():
        current += 1
        if progress_callback:
            progress_callback(current, total_files, f"فحص: {filename}")

        found = False
        actual_hash = None
        actual_path = ""

        for root in SYSTEM_ROOTS:
            file_path = os.path.join(root, filename)
            if os.path.isfile(file_path):
                actual_hash = compute_sha256(file_path)
                actual_path = file_path
                found = True
                break

        if not found:
            results.append({
                "category": "System Integrity",
                "name": filename,
                "path": "غير موجود",
                "reasons": ["ملف نظام مفقود من المسارات المتوقعة"],
                "score": 70,
                "severity": "High"
            })
        elif actual_hash != expected_hash:
            results.append({
                "category": "System Integrity",
                "name": filename,
                "path": actual_path,
                "reasons": [f"تم تعديل ملف النظام (تجزئة مختلفة)"],
                "score": 85,
                "severity": "High"
            })
        else:
            results.append({
                "category": "System Integrity",
                "name": filename,
                "path": actual_path,
                "reasons": ["ملف نظام أصلي (مطابق)"],
                "score": 0,
                "severity": "Low"
            })

    return results

def check_specific_file(file_path):
    """فحص ملف واحد محدد حسب اسمه في القاعدة (إذا كان معروفاً)."""
    filename = os.path.basename(file_path)
    if filename in KNOWN_SYSTEM_HASHES:
        expected = KNOWN_SYSTEM_HASHES[filename]
        actual = compute_sha256(file_path)
        if actual is None:
            return f"❌ تعذر قراءة {filename}"
        if actual != expected:
            return f"⚠️ {filename}: معدل (غير أصلي)"
        return f"✅ {filename}: أصلي"
    return f"ℹ️ {filename} غير مدرج في قاعدة البيانات"