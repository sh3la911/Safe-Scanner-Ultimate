import os
import json
import ctypes
import platform
import subprocess
import hashlib
import time
import math
from pathlib import Path
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError
import socket

try:
    import psutil
except ImportError:
    psutil = None

from rulescanner import scan_with_rules, RULES

# ---------- مساعد ----------
def is_windows():
    return platform.system().lower() == "windows"

def is_hidden(path_str):
    path = Path(path_str)
    if not path.exists():
        return False
    if not is_windows():
        return path.name.startswith(".")
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path))
        if attrs == -1:
            return False
        return bool(attrs & 0x2)
    except Exception:
        return False

def suspicious_name_score(name):
    n = name.lower()
    score = 0
    if any(k in n for k in ["crack", "hacktool", "stealer", "keygen"]):
        score += 40
    elif any(k in n for k in ["hack", "cheat", "inject", "loader", "bypass", "rat"]):
        score += 25
    if any(n.endswith(x) for x in [".pdf.exe", ".png.exe", ".jpg.exe", ".docx.exe", ".txt.exe"]):
        score += 50
    return min(score, 100)

def in_user_dirs(p):
    return any(d in p.lower() for d in ["downloads", "temp", "appdata", "desktop"])

# ---------- فحص التوقيع الرقمي ----------
def check_digital_signature(file_path):
    if not is_windows() or not file_path.lower().endswith(('.exe', '.dll', '.sys')):
        return None, None
    try:
        wintrust = ctypes.windll.wintrust
        WINTRUST_DATA = type('WINTRUST_DATA', (ctypes.Structure,), {
            '_fields_': [
                ("cbStruct", ctypes.c_ulong),
                ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p),
                ("dwUIChoice", ctypes.c_ulong),
                ("fdwRevocationChecks", ctypes.c_ulong),
                ("dwUnionChoice", ctypes.c_ulong),
                ("pFile", ctypes.c_void_p),
                ("dwStateAction", ctypes.c_ulong),
                ("hWVTStateData", ctypes.c_void_p),
                ("pwszURLReference", ctypes.c_wchar_p),
                ("dwProvFlags", ctypes.c_ulong),
                ("dwUIContext", ctypes.c_ulong),
                ("pSignatureSettings", ctypes.c_void_p)
            ]
        })
        WTD_CHOICE_FILE = 1
        WTD_REVOKE_NONE = 0x0
        WTD_STATEACTION_IGNORE = 0x0
        WTD_UI_NONE = 2
        WTD_SAFER_FLAG = 0x100
        file_info = ctypes.create_unicode_buffer(file_path)
        data = WINTRUST_DATA()
        data.cbStruct = ctypes.sizeof(data)
        data.dwUIChoice = WTD_UI_NONE
        data.fdwRevocationChecks = WTD_REVOKE_NONE
        data.dwUnionChoice = WTD_CHOICE_FILE
        data.pFile = ctypes.cast(file_info, ctypes.c_void_p)
        data.dwStateAction = WTD_STATEACTION_IGNORE
        data.dwProvFlags = WTD_SAFER_FLAG
        guid = ctypes.create_string_buffer(b'\x00' * 16)
        result = wintrust.WinVerifyTrust(0, ctypes.byref(guid), ctypes.byref(data))
        if result == 0:
            return (True, "موقعة رقميًا")
        else:
            return (False, "غير موقعة / توقيع غير صالح")
    except Exception:
        return (False, "فشل في الفحص")

# ---------- قاعدة بيانات البصمات ----------
KNOWN_BAD_HASHES = {
    "5d41402abc4b2a76b9719d911017c592": "أداة حقن Vape",
    "7d793037a0760186574b0282f2f435e7": "أداة حقن Sigma",
    "098f6bcd4621d373cade4e832627b4f6": "أداة حقن Wurst",
}

def compute_file_hash(file_path, algo="md5"):
    h = hashlib.new(algo)
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ---------- Entropy (كشف الملفات المضغوطة/المشفرة) ----------
def compute_entropy(data):
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p_x = data.count(x) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

# ---------- فحص كلمات مفتاحية في ملفات صغيرة ----------
SUS_KEYWORDS_TXT = ["hack", "cheat", "inject", "vape", "sigma", "wurst", "killaura", "flyhack"]

def quick_string_scan(file_path):
    try:
        with open(file_path, "rb") as f:
            content = f.read(1024 * 10)  # أول 10 كيلوبايت فقط
        for kw in SUS_KEYWORDS_TXT:
            if kw.encode('utf-8') in content:
                return True
    except:
        pass
    return False

# ---------- فحص الريجستري ----------
def scan_registry_startup():
    results = []
    if not is_windows():
        return results
    import winreg
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for hkey, subkey in reg_paths:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        i += 1
                        if not name:
                            name = "(Default)"
                        path = value
                        reason = "برنامج يبدأ مع النظام (ريجستري)"
                        score = 10
                        if "temp" in path.lower() or "appdata" in path.lower():
                            score = 35
                            reason = "برنامج يبدأ من مسار مستخدم غير معتاد"
                        results.append({
                            "category": "Registry Startup",
                            "name": name,
                            "path": path,
                            "reasons": [reason],
                            "score": score,
                            "severity": "Medium" if score >= 35 else "Low"
                        })
                    except OSError:
                        break
        except Exception:
            continue
    return results

# ---------- فحص المهام المجدولة ----------
def scan_scheduled_tasks():
    results = []
    if not is_windows():
        return results
    try:
        out = subprocess.check_output('schtasks /query /fo csv /v', shell=True,
                                      text=True, errors='ignore')
        lines = out.splitlines()
        if len(lines) < 2:
            return results
        for line in lines[1:]:
            if not line.strip():
                continue
            parts = line.split('","')
            if len(parts) < 8:
                continue
            task_name = parts[0].strip('"')
            task_path = parts[7].strip('"') if len(parts) > 7 else ""
            if not task_path:
                continue
            score = 0
            reasons = []
            if any(d in task_path.lower() for d in ["temp", "appdata", "downloads"]):
                reasons.append("مسار مشبوه لمهمة مجدولة")
                score += 40
            if any(k in task_name.lower() for k in ["hack", "cheat", "inject"]):
                reasons.append("اسم مهمة مشبوه")
                score += 30
            if reasons:
                results.append({
                    "category": "Scheduled Task",
                    "name": task_name,
                    "path": task_path,
                    "reasons": reasons,
                    "score": min(score, 100),
                    "severity": "High" if score >= 70 else "Medium"
                })
    except Exception:
        pass
    return results

# ---------- فحص الاتصالات الشبكية ----------
def scan_network_connections():
    results = []
    if psutil is None:
        return results
    try:
        conns = psutil.net_connections(kind='inet')
        suspicious_ips = ["185.", "91.", "45."]
        for conn in conns:
            if conn.status != 'ESTABLISHED':
                continue
            laddr = conn.laddr.ip if conn.laddr else ""
            raddr = conn.raddr.ip if conn.raddr else ""
            pid = conn.pid
            proc_name = ""
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except Exception:
                proc_name = "unknown"
            reasons = []
            score = 0
            if raddr and any(raddr.startswith(ip) for ip in suspicious_ips):
                reasons.append(f"اتصال بعنوان مشبوه: {raddr}")
                score += 50
            if reasons:
                results.append({
                    "category": "Network Connection",
                    "name": f"{proc_name} (PID {pid})",
                    "path": f"{laddr} -> {raddr}",
                    "reasons": reasons,
                    "score": score,
                    "severity": "Medium"
                })
    except Exception:
        pass
    return results

# ---------- فحص ملف واحد (الوحدة الأساسية للمعالجة المتوازية) ----------
def analyze_single_file(file_path, quick_mode=False):
    reasons = []
    score = 0
    fp = Path(file_path)
    file_size = 0
    try:
        file_size = fp.stat().st_size
    except OSError:
        return 0, [], 0

    # تخطي الملفات الضخمة > 200MB
    if file_size > 200 * 1024 * 1024:
        return 0, [], file_size

    try:
        # الاختفاء
        if is_hidden(str(fp)):
            reasons.append("ملف مخفي")
            score += 15
        # اسم مشبوه
        ns = suspicious_name_score(fp.name)
        if ns > 0:
            reasons.append("اسم/امتداد مشبوه")
            score += ns
        ext = fp.suffix.lower()
        if ext in [".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".msi"] and in_user_dirs(str(fp)):
            reasons.append("تنفيذي في مجلد مستخدم")
            score += 60

        if ext in [".exe", ".dll", ".sys"]:
            # توقيع
            signed, signer = check_digital_signature(str(fp))
            if signed is False:
                reasons.append("ملف غير موقّع رقميًا")
                score += 20
            # هاش
            if not quick_mode:
                fhash = compute_file_hash(str(fp))
                if fhash and fhash in KNOWN_BAD_HASHES:
                    reasons.append(f"بصمة تطابق أداة حقن معروفة: {KNOWN_BAD_HASHES[fhash]}")
                    score += 80
            # Entropy
            if file_size < 10 * 1024 * 1024:  # للملفات الصغيرة نسبياً
                try:
                    with open(str(fp), "rb") as f:
                        data = f.read(1024 * 64)  # أول 64KB كافية
                    ent = compute_entropy(data)
                    if ent > 7.5:
                        reasons.append(f"انتروبيا عالية ({ent:.1f}) - ملف مشفر/مضغوط بشكل مريب")
                        score += 40
                except:
                    pass

        # فحص نصي سريع للملفات الصغيرة
        if ext in [".txt", ".cfg", ".ini", ".json", ".xml", ".log"] and file_size < 1024 * 1024:
            if quick_string_scan(str(fp)):
                reasons.append("يحتوي كلمات مشبوهة")
                score += 30

        if not quick_mode:
            rule_score, rule_reasons = scan_with_rules(str(fp))
            if rule_reasons:
                reasons.extend(rule_reasons)
                score += rule_score
    except Exception:
        pass

    return min(score, 100), reasons, file_size

# ---------- المسح المتوازي السريع للمجلدات (مع إمكانية الإيقاف) ----------
def scan_files_parallel(target_paths, progress_callback=None, quick_mode=False, stop_flag=None):
    """
    فحص الملفات باستخدام ThreadPoolExecutor.
    stop_flag: دالة تُرجع True إذا طُلب الإيقاف.
    """
    results = []
    # تجميع كل مسارات الملفات أولاً (باستخدام scandir السريع)
    all_files = []
    for base in target_paths:
        if not os.path.exists(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            # استخدام os.scandir لأداء أفضل
            for entry in os.scandir(root):
                if entry.is_file():
                    all_files.append(entry.path)
            if stop_flag and stop_flag():
                break
        if stop_flag and stop_flag():
            break

    total_files = len(all_files)
    if total_files == 0:
        return results

    completed = 0
    with ThreadPoolExecutor(max_workers=8) as executor:
        # وضع حدود زمنية لكل مستقبل
        future_to_path = {
            executor.submit(analyze_single_file, path, quick_mode): path
            for path in all_files
        }
        for future in as_completed(future_to_path):
            completed += 1
            if stop_flag and stop_flag():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            path = future_to_path[future]
            try:
                score, reasons, fsize = future.result(timeout=2.0)
                if score > 0:
                    severity = "High" if score >= 70 else "Medium" if score >= 35 else "Low"
                    results.append({
                        "category": "File",
                        "name": Path(path).name,
                        "path": path,
                        "reasons": reasons,
                        "score": min(score, 100),
                        "severity": severity
                    })
            except (TimeoutError, Exception):
                pass  # تخطي الملفات التي تستغرق أكثر من 2 ثانية
            if progress_callback and total_files > 0:
                percent = int((completed / total_files) * 100)
                progress_callback(completed, total_files, f"ملفات... {percent}%")

    return results

# ---------- وضع التوافق للفحص الأول (للاتصال بالواجهة القديمة إذا لزم) ----------
def scan_files(target_paths, progress_callback=None):
    return scan_files_parallel(target_paths, progress_callback, quick_mode=False)

def quick_scan_files(target_paths, progress_callback=None):
    return scan_files_parallel(target_paths, progress_callback, quick_mode=True)

# ---------- فحص العمليات ----------
def scan_processes(progress_callback=None):
    results = []
    if psutil is None:
        return results
    procs = list(psutil.process_iter(["pid", "name", "exe", "cmdline"]))
    total = len(procs)
    for i, proc in enumerate(procs, 1):
        if progress_callback:
            progress_callback(i, total, "فحص عمليات...")
        try:
            info = proc.info
            name = info.get("name") or "?"
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            pid = info.get("pid")
            reasons, score = [], 0
            exe_lower = exe.lower()
            if any(loc in exe_lower for loc in ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\appdata\\"]):
                reasons.append("مسار غير معتاد")
                score += 60
            if any(k in (name + cmdline).lower() for k in ["cheat", "hack", "inject", "loader", "bypass"]):
                reasons.append("كلمات مشبوهة")
                score += 40
            if exe and exe.lower().endswith('.exe'):
                signed, _ = check_digital_signature(exe)
                if signed is False:
                    reasons.append("عملية غير موقعة")
                    score += 15
                fhash = compute_file_hash(exe)
                if fhash and fhash in KNOWN_BAD_HASHES:
                    reasons.append(f"بصمة تطابق أداة حقن معروفة: {KNOWN_BAD_HASHES[fhash]}")
                    score += 80
            if score > 0:
                severity = "High" if score >= 70 else "Medium"
                results.append({
                    "category": "Process",
                    "name": f"{name} (PID {pid})",
                    "path": exe,
                    "reasons": reasons,
                    "score": min(score, 100),
                    "severity": severity
                })
        except Exception:
            continue
    return results

def scan_startup(progress_callback=None):
    results = []
    if is_windows():
        startup_paths = [
            os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
            os.path.expandvars(r"%PROGRAMDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        ]
    else:
        startup_paths = [str(Path.home() / ".config" / "autostart")]
    total_items = sum(len(list(Path(p).iterdir())) if Path(p).exists() else 0 for p in startup_paths)
    current = 0
    for sp in startup_paths:
        p = Path(sp)
        if not p.exists():
            continue
        for item in p.iterdir():
            current += 1
            if progress_callback:
                progress_callback(current, total_items, f"بدء التشغيل: {item.name}")
            results.append({
                "category": "Startup",
                "name": item.name,
                "path": str(item),
                "reasons": ["يعمل تلقائياً"],
                "score": 10,
                "severity": "Low"
            })
    return results

def scan_browsers():
    results = []
    if not is_windows():
        return results
    import winreg
    browser_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Clients\StartMenuInternet"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Clients\StartMenuInternet"),
    ]
    browser_names = set()
    for hkey, subkey in browser_paths:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name = winreg.EnumKey(key, i)
                        i += 1
                        browser_names.add(name)
                    except OSError:
                        break
        except Exception:
            continue
    for bname in browser_names:
        results.append({
            "category": "Browser",
            "name": bname,
            "path": "",
            "reasons": ["متصفح مثبت على الجهاز"],
            "score": 0,
            "severity": "Low"
        })
    return results

# ---------- أدوات النظام ----------
SYSTEM_TOOLS = {
    "Task Manager": "taskmgr.exe",
    "Event Viewer": "eventvwr.msc",
    "Control Panel": "control.exe",
    "Registry Editor": "regedit.exe",
    "System Configuration": "msconfig.exe",
    "Resource Monitor": "resmon.exe",
}

def open_system_tool(tool_name):
    if tool_name in SYSTEM_TOOLS:
        try:
            subprocess.Popen(SYSTEM_TOOLS[tool_name], shell=True)
            return True
        except Exception:
            return False
    return False

def get_system_tools_list():
    results = []
    for tool_name, tool_cmd in SYSTEM_TOOLS.items():
        results.append({
            "category": "System Tool",
            "name": tool_name,
            "path": tool_cmd,
            "reasons": ["أداة نظام للتحليل اليدوي"],
            "score": 0,
            "severity": "Low"
        })
    return results

# ---------- فحص يدوي ----------
def manual_scan_path(target_path, progress_callback=None):
    if os.path.isfile(target_path):
        score, reasons, _ = analyze_single_file(target_path, quick_mode=False)
        results = []
        if score > 0:
            severity = "High" if score >= 70 else "Medium" if score >= 35 else "Low"
            results.append({
                "category": "Manual File",
                "name": Path(target_path).name,
                "path": str(target_path),
                "reasons": reasons,
                "score": score,
                "severity": severity
            })
        return results
    elif os.path.isdir(target_path):
        return scan_files_parallel([target_path], progress_callback, quick_mode=False)
    return []

def build_report(results):
    return {"generated_at": datetime.now().isoformat(), "results": results}

def save_report_json(results, file_path):
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(build_report(results), f, ensure_ascii=False, indent=2)