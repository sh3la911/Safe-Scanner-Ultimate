"""
Minecraft Security Scanner - Ultimate Edition
الآن مع دمج محرك القواعد (Rules Scanner) على جميع المودات والملفات.
Read-only, safe, deep heuristic analysis.
"""
import os
import zipfile
import ctypes
import json
import subprocess
from pathlib import Path
from datetime import datetime
from ctypes import wintypes

try:
    import psutil
except ImportError:
    psutil = None

from rulescanner import scan_with_rules

# ---------- مساعد ----------
def is_hidden_windows(path_str):
    try:
        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(path_str))
        if attrs == -1:
            return False
        return bool(attrs & 0x2)
    except Exception:
        return False

def get_minecraft_dirs():
    home = Path.home()
    dirs = []
    official = home / "AppData" / "Roaming" / ".minecraft"
    if official.exists():
        dirs.append(("Official", official))
    tlauncher = home / "AppData" / "Roaming" / ".tlauncher"
    if tlauncher.exists():
        dirs.append(("TLauncher", tlauncher))
    lunar = home / ".lunarclient"
    if lunar.exists():
        dirs.append(("Lunar Client", lunar))
    badlion = home / "AppData" / "Roaming" / "Badlion Client"
    if badlion.exists():
        dirs.append(("Badlion Client", badlion))
    feather = home / "AppData" / "Roaming" / "Feather"
    if feather.exists():
        dirs.append(("Feather Client", feather))
    curse = home / "curseforge" / "minecraft" / "Instances"
    if curse.exists():
        dirs.append(("CurseForge", curse))
    modpacks = home / "AppData" / "Roaming" / "modpacks"
    if modpacks.exists():
        dirs.append(("ModPacks", modpacks))
    return dirs

INJECTOR_NAMES = [
    "vape", "sigma", "wurst", "meteor", "raven", "rise", "tenacity",
    "novoline", "flux", "azura", "cracked vape", "vape lite", "vape v4",
    "sigma 5", "wurst+", "wurst plus", "meteor client", "raven b+",
    "rise client", "tenacity client", "novoline client", "flux b13",
    "azura client", "injector", "ghost client", "ghost hack",
    "autoclicker", "auto clicker", "macro tool", "autohotkey",
    "pulover's macro creator", "killaura", "xray", "freecam",
    "esp hack", "tracers", "aimbot", "reach hack"
]

MACRO_TOOLS = [
    "autohotkey.exe", "autohotkey", "pulover's macro creator.exe",
    "macro creator.exe", "auto clicker.exe", "autoclicker.exe",
    "opus auto clicker.exe", "speed auto clicker.exe"
]

# ---------- 1. فتح JAR وتحليل (مع القواعد) ----------
def deep_scan_jar(jar_path):
    reasons, score = [], 0
    jar_name = Path(jar_path).name.lower()
    try:
        with zipfile.ZipFile(jar_path, 'r') as zf:
            entries = zf.namelist()
            high_kw = ["hack", "cheat", "xray", "killaura", "esp", "freecam", "autoclicker",
                       "inject", "crack", "stealer", "keygen", "aimbot", "reach"]
            med_kw = ["fly", "speed", "nofall", "macro", "scaffold", "tracers"]
            found_high = False
            found_med = False
            for entry in entries:
                el = entry.lower()
                if any(k in el for k in high_kw):
                    if not found_high:
                        reasons.append("حزمة هاك خطيرة بالداخل")
                        found_high = True
                        score += 50
                elif any(k in el for k in med_kw):
                    if not found_med:
                        reasons.append("حزمة مشبوهة متوسطة")
                        found_med = True
                        score += 30
            try:
                manifest = zf.read("META-INF/MANIFEST.MF").decode("utf-8", errors="ignore")
                if "Main-Class:" in manifest and any(k in manifest.lower() for k in ["hack", "cheat", "inject"]):
                    reasons.append("MANIFEST.MF يشير إلى Main-Class مشبوهة")
                    score += 40
                if "Agent-Class:" in manifest or "Launcher-Agent-Class:" in manifest:
                    reasons.append("يحتمل أن يكون Ghost Client (Agent-Class موجود)")
                    score += 55
            except:
                pass
            if any(e.endswith('.dll') for e in entries):
                reasons.append("يحتوي على مكتبة DLL (محتمل حقن)")
                score += 35
    except:
        reasons.append("ملف JAR تالف / لا يفتح")
        score += 10

    for injector in INJECTOR_NAMES:
        if injector in jar_name:
            reasons.append(f"اسم ملف يشير إلى injector معروف: {injector}")
            score += 70
            break

    # تطبيق محرك القواعد على ملف JAR
    rule_score, rule_reasons = scan_with_rules(jar_path)
    if rule_reasons:
        reasons.extend(rule_reasons)
        score += rule_score

    return reasons, min(score, 100)

# ---------- 2. فحص المودات ----------
def scan_jar_mods(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    if not minecraft_dirs:
        return results

    mod_dirs = []
    for launcher_name, base in minecraft_dirs:
        mod_dir = base / "mods"
        if mod_dir.exists():
            mod_dirs.append((launcher_name, mod_dir))
        versions_dir = base / "versions"
        if versions_dir.exists():
            for ver in versions_dir.iterdir():
                if ver.is_dir():
                    for jar in ver.glob("*.jar"):
                        mod_dirs.append((f"Version-{ver.name}", ver))

    total_mods = sum(len(list(md.glob("*.jar"))) for _, md in mod_dirs)
    current = 0
    for launcher_name, md in mod_dirs:
        for jar in md.glob("*.jar"):
            current += 1
            if progress_callback:
                progress_callback(current, total_mods, f"فحص: {jar.name}")
            reasons, score = deep_scan_jar(str(jar))
            if score > 0:
                severity = "High" if score >= 70 else "Medium" if score >= 35 else "Low"
                results.append({
                    "category": "Minecraft Mod",
                    "name": jar.name,
                    "path": str(jar),
                    "reasons": reasons,
                    "score": score,
                    "severity": severity
                })
    return results

# ---------- 3. فحص عمليات ماينكرافت ----------
def scan_minecraft_processes(progress_callback=None):
    results = []
    if psutil is None:
        return results

    mc_exes = ["javaw.exe", "java.exe", "minecraft launcher.exe",
               "lunar client.exe", "badlion client.exe", "tlauncher.exe",
               "feather client.exe", "multimc.exe", "prism.exe"]
    mc_procs = []
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if any(mc in name for mc in mc_exes):
                mc_procs.append(proc)
        except:
            continue

    total = len(mc_procs)
    for i, proc in enumerate(mc_procs, 1):
        if progress_callback:
            progress_callback(i, total, "فحص عمليات ماينكرافت...")
        try:
            info = proc.info
            exe = info.get("exe") or ""
            cmdline = " ".join(info.get("cmdline") or [])
            pid = info.get("pid")
            reasons, score = [], 0

            sus_args = [
                "-javaagent", "-agentpath", "-Xbootclasspath/a:",
                "-Dfml.ignoreInvalidMinecraftCertificates=true",
                "-Dfml.ignorePatchDiscrepancies=true"
            ]
            for arg in sus_args:
                if arg.lower() in cmdline.lower():
                    reasons.append(f"وسيط حقن: {arg}")
                    score += 60

            proc_name = info.get("name", "").lower()
            for injector in INJECTOR_NAMES:
                if injector in proc_name:
                    reasons.append(f"اسم عملية يشير إلى injector: {injector}")
                    score += 70
                    break

            for mt in MACRO_TOOLS:
                if mt in proc_name:
                    reasons.append(f"أداة ماكرو / auto-clicker مشبوهة: {mt}")
                    score += 50
                    break

            if score > 0:
                severity = "High" if score >= 70 else "Medium"
                results.append({
                    "category": "Minecraft Process",
                    "name": f"{info.get('name', '?')} (PID {pid})",
                    "path": exe,
                    "reasons": reasons,
                    "score": min(score, 100),
                    "severity": severity
                })
        except:
            continue
    return results

# ---------- 4. فحص اللانشرات ----------
def scan_launchers(progress_callback=None):
    results = []
    known = {
        "Lunar Client": ["lunarclient", "lunar client"],
        "Badlion Client": ["badlion", "badlion client"],
        "Feather Client": ["feather", "feather client"],
        "TLauncher": ["tlauncher"],
        "CurseForge": ["curseforge"],
        "MultiMC": ["multimc"],
        "Prism Launcher": ["prism", "prism launcher"],
        "ATLauncher": ["atlauncher"],
        "SKlauncher": ["sklauncher"]
    }
    home = Path.home()
    search_roots = [
        home / "AppData" / "Local" / "Programs",
        home / "AppData" / "Roaming",
        home / "AppData" / "Local",
        Path("C:/Program Files"),
        Path("C:/Program Files (x86)"),
        home / ".lunarclient",
        home / ".feather"
    ]

    total = len(search_roots)
    for i, root in enumerate(search_roots, 1):
        if progress_callback:
            progress_callback(i, total, f"بحث عن لانشرات: {root.name}")
        if not root.exists():
            continue
        try:
            for item in root.rglob("*.exe"):
                name_lower = item.name.lower()
                for launcher, aliases in known.items():
                    for alias in aliases:
                        if alias in name_lower:
                            results.append({
                                "category": "Minecraft Launcher",
                                "name": launcher,
                                "path": str(item),
                                "reasons": ["لانشر ماينكرافت مثبت"],
                                "score": 5,
                                "severity": "Low"
                            })
                            break
                if len(results) >= 15:
                    break
        except:
            continue
    return results

# ---------- 5. فحص اللقطات ----------
def scan_screenshots(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        ss_dir = base / "screenshots"
        if not ss_dir.exists():
            continue
        images = list(ss_dir.glob("*.png")) + list(ss_dir.glob("*.jpg"))
        total = len(images)
        current = 0
        for img in images:
            current += 1
            if progress_callback:
                progress_callback(current, total, f"لقطات: {img.name}")
            if any(k in img.name.lower() for k in INJECTOR_NAMES):
                results.append({
                    "category": "Screenshot Evidence",
                    "name": img.name,
                    "path": str(img),
                    "reasons": ["لقطة شاشة باسم هاك/انجكتور"],
                    "score": 25,
                    "severity": "Low"
                })
    return results

# ---------- 6. فحص ملفات الإعدادات ----------
def scan_configs(progress_callback=None):
    results = []
    sus_files = ["hacks.txt", "cheat_config.txt", "xray.txt", "autoclicker.cfg",
                 "vape.ini", "sigma.json", "wurst.json", "meteor.json"]
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        config_dir = base / "config"
        if not config_dir.exists():
            continue
        total = len(sus_files)
        for i, fname in enumerate(sus_files, 1):
            if progress_callback:
                progress_callback(i, total, f"إعدادات: {fname}")
            target = config_dir / fname
            if target.exists():
                results.append({
                    "category": "Suspicious Config",
                    "name": fname,
                    "path": str(target),
                    "reasons": ["ملف إعدادات هاك/انجكتور معروف"],
                    "score": 50,
                    "severity": "Medium"
                })
    return results

# ---------- 7. فحص حزم الموارد ----------
def scan_resource_packs(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        rp_dir = base / "resourcepacks"
        if not rp_dir.exists():
            continue
        files = list(rp_dir.glob("*.zip")) + list(rp_dir.glob("*.jar"))
        total = len(files)
        current = 0
        for rp in files:
            current += 1
            if progress_callback:
                progress_callback(current, total, f"حزم موارد: {rp.name}")
            try:
                with zipfile.ZipFile(rp, 'r') as zf:
                    entries = zf.namelist()
                    for entry in entries:
                        if entry.endswith('.class') or entry.endswith('.dex'):
                            results.append({
                                "category": "Suspicious Resource Pack",
                                "name": rp.name,
                                "path": str(rp),
                                "reasons": [f"يحتوي على كود قابل للتنفيذ: {entry}"],
                                "score": 60,
                                "severity": "High"
                            })
                            break
            except:
                pass
    return results

# ---------- 8. فتح سجل الأوامر وسجلات التشغيل ----------
def scan_command_history(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        cmdfile = base / "commandhistory.txt"
        if cmdfile.exists():
            try:
                with open(cmdfile, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().lower()
                sus_commands = [".bind", ".help hack", ".help cheat", ".inject", ".ghost"]
                found = [cmd for cmd in sus_commands if cmd in content]
                if found:
                    results.append({
                        "category": "Command History",
                        "name": "commandhistory.txt",
                        "path": str(cmdfile),
                        "reasons": [f"سجل أوامر مشبوه: {', '.join(found)}"],
                        "score": 40,
                        "severity": "Medium"
                    })
            except:
                pass
        logfile = base / "logs" / "latest.log"
        if logfile.exists():
            try:
                with open(logfile, "r", encoding="utf-8", errors="ignore") as f:
                    logcontent = f.read().lower()
                log_reasons = []
                if "javaagent" in logcontent:
                    log_reasons.append("وجود javaagent في سجل التشغيل")
                if "ignoring invalid minecraft certificate" in logcontent:
                    log_reasons.append("تجاهل شهادة أمان (مؤشر Ghost)")
                if log_reasons:
                    results.append({
                        "category": "Log Evidence",
                        "name": "latest.log",
                        "path": str(logfile),
                        "reasons": log_reasons,
                        "score": 45,
                        "severity": "Medium"
                    })
            except:
                pass
    return results

# ---------- 9. كشف ملفات DLL/EXE داخل مجلدات ماينكرافت ----------
def scan_suspicious_native_files(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        for pattern in ["*.dll", "*.exe"]:
            for file in base.glob(pattern):
                # تطبيق محرك القواعد على هذا الملف
                rule_score, rule_reasons = scan_with_rules(str(file))
                if rule_reasons:
                    results.append({
                        "category": "Suspicious Native File",
                        "name": file.name,
                        "path": str(file),
                        "reasons": ["مكتبة أصلية أو برنامج تنفيذي داخل مجلد ماينكرافت"] + rule_reasons,
                        "score": min(80 + rule_score, 100),
                        "severity": "High"
                    })
                else:
                    results.append({
                        "category": "Suspicious Native File",
                        "name": file.name,
                        "path": str(file),
                        "reasons": ["مكتبة أصلية أو برنامج تنفيذي داخل مجلد ماينكرافت"],
                        "score": 80,
                        "severity": "High"
                    })
    return results

# ---------- 10. فحص إعدادات البروكسي/VPN ----------
def scan_proxy_settings():
    results = []
    try:
        out = subprocess.check_output('netsh winhttp show proxy', shell=True,
                                      text=True, errors='ignore')
        if "Proxy Server(s)" in out and "Direct access" not in out:
            results.append({
                "category": "Proxy Setting",
                "name": "System Proxy",
                "path": "",
                "reasons": ["النظام يستخدم بروكسي (قد يكون لإخفاء النشاط)"],
                "score": 10,
                "severity": "Low"
            })
    except:
        pass
    return results

# ---------- 11. فحص أدلة محذوفة ----------
def scan_deleted_evidence(progress_callback=None):
    results = []
    recycle = Path("C:/$Recycle.Bin")
    prefetch = Path("C:/Windows/Prefetch")
    targets = []
    if recycle.exists():
        targets.append(("Recycle Bin", recycle))
    if prefetch.exists():
        targets.append(("Prefetch", prefetch))

    total_files = sum(len(list(p.glob("**/*"))) for _, p in targets) if targets else 0
    current = 0
    for category, path in targets:
        for item in path.glob("**/*"):
            current += 1
            if progress_callback:
                progress_callback(current, total_files, f"{category}: {item.name}")
            if not item.is_file():
                continue
            try:
                name_lower = item.name.lower()
                if any(k in name_lower for k in INJECTOR_NAMES):
                    results.append({
                        "category": "Deleted Evidence",
                        "name": item.name,
                        "path": str(item),
                        "reasons": ["دليل محذوف لملف هاك/انجكتور"],
                        "score": 30,
                        "severity": "Low"
                    })
            except:
                continue
    return results

# ---------- 12. فحص حسابات Alt ----------
def scan_alt_accounts(progress_callback=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    for launcher_name, base in minecraft_dirs:
        for acc_file in ["accounts.json", "launcher_accounts.json", "accounts.dat"]:
            target = base / acc_file
            if target.exists() and target.stat().st_size > 0:
                try:
                    with open(target, "r", encoding="utf-8", errors="ignore") as f:
                        data = json.load(f)
                    if isinstance(data, list):
                        count = len(data)
                    elif isinstance(data, dict):
                        count = len(data.get("accounts", []))
                    else:
                        count = 1
                    if count > 1:
                        results.append({
                            "category": "Alt Accounts",
                            "name": f"{launcher_name} - {acc_file}",
                            "path": str(target),
                            "reasons": [f"يحتوي على {count} حساب (تنبيه أمان)"],
                            "score": 15,
                            "severity": "Low"
                        })
                except:
                    pass
    return results


# ========== 🧠 التحليل الحي للذاكرة ==========
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_READABLE = (0x02 | 0x04 | 0x08 | 0x20 | 0x40)

SUSPICIOUS_MEMORY_STRINGS = [
    "KillAura", "Killaura", "killaura",
    "FlyHack", "flyhack", "Fly",
    "SpeedHack", "speedhack",
    "AutoClicker", "autoclicker",
    "ChestStealer", "cheststealer",
    "XRay", "xray",
    "Freecam", "freecam",
    "Inject", "inject",
    "Vape", "vape",
    "Sigma", "sigma",
    "Wurst", "wurst",
    "Meteor", "meteor",
    "Raven", "raven",
    "Tenacity", "tenacity"
]

def read_process_memory(pid, address, size):
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h_process:
        return None
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(h_process, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
        kernel32.CloseHandle(h_process)
        return buffer.raw[:bytes_read.value]
    kernel32.CloseHandle(h_process)
    return None

def scan_process_memory(pid, strings_to_find, progress_callback=None):
    reasons = []
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.VirtualQueryEx.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, ctypes.POINTER(MEMORY_BASIC_INFORMATION), ctypes.c_size_t]

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD)
        ]

    h_process = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
    if not h_process:
        return reasons

    address = 0
    while True:
        mbi = MEMORY_BASIC_INFORMATION()
        ret = kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if ret == 0:
            break
        if mbi.State == MEM_COMMIT and (mbi.Protect & PAGE_READABLE):
            read_size = min(mbi.RegionSize, 1024 * 1024)
            data = read_process_memory(pid, mbi.BaseAddress, read_size)
            if data:
                for s in strings_to_find:
                    if s.encode('utf-8') in data or s.encode('utf-16-le') in data:
                        if s not in reasons:
                            reasons.append(s)
        address = ctypes.c_void_p(ctypes.cast(mbi.BaseAddress, ctypes.c_void_p).value + mbi.RegionSize).value

    kernel32.CloseHandle(h_process)
    return reasons

def scan_memory_strings(progress_callback=None):
    results = []
    if not psutil or not os.name == 'nt':
        return results

    mc_procs = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if "java" in name or "minecraft" in name or "lunar" in name or "badlion" in name:
                mc_procs.append(proc)
        except:
            continue

    total = len(mc_procs)
    for i, proc in enumerate(mc_procs, 1):
        if progress_callback:
            progress_callback(i, total, f"مسح ذاكرة {proc.info.get('name')}...")
        try:
            pid = proc.info["pid"]
            found = scan_process_memory(pid, SUSPICIOUS_MEMORY_STRINGS)
            if found:
                results.append({
                    "category": "Memory Strings",
                    "name": f"{proc.info.get('name', '?')} (PID {pid})",
                    "path": "ذاكرة العملية",
                    "reasons": [f"نصوص هاك في الذاكرة: {', '.join(found)}"],
                    "score": 90,
                    "severity": "High"
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results


# ---------- 🧩 كشف مكتبات DLL المحقونة ----------
KNOWN_CHEAT_DLLS = [
    "cheatengine-x86_64.dll", "cheatengine.dll", "vape.dll", "sigma.dll",
    "wurst.dll", "meteor.dll", "inject.dll", "ghost.dll", "hack.dll", "xray.dll"
]

def scan_loaded_modules(progress_callback=None):
    results = []
    if not psutil or not os.name == 'nt':
        return results

    mc_procs = []
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            name = (proc.info.get("name") or "").lower()
            if "java" in name or "minecraft" in name or "lunar" in name or "badlion" in name:
                mc_procs.append(proc)
        except:
            continue

    total = len(mc_procs)
    for i, proc in enumerate(mc_procs, 1):
        if progress_callback:
            progress_callback(i, total, f"فحص مكتبات {proc.info.get('name')}...")
        try:
            pid = proc.info["pid"]
            proc_obj = psutil.Process(pid)
            mmaps = proc_obj.memory_maps(grouped=False)
            for mm in mmaps:
                if not mm.path:
                    continue
                fname = os.path.basename(mm.path).lower()
                for cheat_dll in KNOWN_CHEAT_DLLS:
                    if cheat_dll in fname:
                        results.append({
                            "category": "Injected DLL",
                            "name": f"{proc.info.get('name', '?')} (PID {pid})",
                            "path": mm.path,
                            "reasons": [f"تم تحميل مكتبة حقن معروفة: {cheat_dll}"],
                            "score": 95,
                            "severity": "High"
                        })
                        break
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return results