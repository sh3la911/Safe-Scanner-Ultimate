"""
Minecraft Security Scanner – Ultimate High‑Speed Edition
فحص متوازي، Timeout، PE Headers، RegEx كسول، قابل للإيقاف.
Read‑only, safe, deep heuristic analysis.
"""
import os
import zipfile
import ctypes
import json
import subprocess
import re
import struct
from pathlib import Path
from datetime import datetime
from ctypes import wintypes
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError

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

# ---------- قاعدة أسماء injectors ----------
INJECTOR_NAMES = [
    "vape", "sigma", "wurst", "meteor", "raven", "rise", "tenacity",
    "novoline", "flux", "azura", "cracked vape", "vape lite", "vape v4",
    "sigma 5", "wurst+", "wurst plus", "meteor client", "raven b+",
    "rise client", "tenacity client", "novoline client", "flux b13",
    "azura client", "injector", "ghost client", "ghost hack",
    "autoclicker", "auto clicker", "macro tool", "autohotkey",
    "pulover's macro creator", "killaura", "xray", "freecam",
    "esp hack", "tracers", "aimbot", "reach hack",
    "aimware", "onetap", "gamesense", "fatality", "neverlose",
    "plaguecheat", "eternity", "memeware", "wannacry", "spookyware",
    "moon", "lunar ghost", "drip", "dopamine", "entropy",
    "sight", "rise lite", "horion", "strike", "pulsive",
    "crackinject", "injector v2", "injector v3", "hack client",
    "cheat client", "internal", "external", "multihack",
    "minemen", "minemenclub", "bypass", "cracked", "toolkit",
    "nuker", "scaffold", "velocity", "antikb", "antibot",
    "esp", "wallhack", "regen", "flyhack", "speedmine",
    "autoblock", "autosoup", "autogapple", "autopot", "autorespawn",
    "invcleaner", "cheststealer", "autotool", "autowalk", "antiafk",
    "antifire", "antiknockback", "antispin", "autofish",
    "bedaura", "bedbomber", "blink", "boatfly", "bowaimbot",
    "bridgeassist", "civbreak", "clicker", "crystalaura",
    "derp", "dolphin", "ecme", "elytrafly", "extinguish",
    "fastplace", "fastuse", "flight", "freeze", "glide",
    "handofgod", "headroll", "holefiller", "icewalk", "infinitereach",
    "jesus", "jetpack", "killpotion", "lagback", "lightningdetect",
    "longjump", "macekill", "magiccarpet", "multiaura", "nametags",
    "nocom", "nofall", "noglitchblocks", "nohurtcam", "nointeract",
    "nolevitation", "nominingtrace", "nopush", "noslowdown",
    "notrace", "noweather", "packetfly", "parkour", "phase",
    "portals", "prophunt", "push", "range", "refill",
    "regen", "remova", "restock", "revive", "rotation",
    "safe", "scaffold", "search", "selfdestruct", "step",
    "strafe", "surround", "swim", "timer", "tower",
    "tp", "triggerbot", "twerk", "unpush", "vclip",
    "veinminer", "waterleave", "windowclick", "xcarry", "yaw",
    "zelda", "zen", "zero", "zigzag", "zoom",
    "alice", "astolfo", "augustus", "bomb", "cedo", "client",
    "comet", "copper", "crispy", "cucklord", "cyber",
    "diamond", "dortware", "dzs", "element", "envy",
    "eversense", "exhibition", "eximius", "exire", "fade",
    "faith", "fatality", "forgehax", "future", "gladiator",
    "grief", "hackintosh", "hail", "halal", "haram",
    "helios", "horion", "hydrogen", "ice breaker", "impact",
    "inertia", "infinity", "ingro", "intent", "interact",
    "invasion", "iridium", "jackpot", "jartex", "jigsaw",
    "kamiblue", "kangaroo", "karambit", "karma", "katarina",
    "kevin", "kilo", "kite", "krma", "laby",
    "latency", "launchpad", "legacy", "legend", "lemon",
    "lethal", "liam", "light", "lilith", "limbo",
    "linear", "lithium", "llama", "loom", "loov",
    "lucifer", "luminous", "luna", "lunar", "lust",
    "lux", "lyra", "mack", "magna", "magnet",
    "maia", "malice", "mandarin", "mango", "manthe",
    "marble", "master", "matrix", "maul", "meow",
    "mercury", "mesa", "method", "meteor+", "meteor++",
    "metro", "midnight", "miku", "miner", "minestrike",
    "miracle", "misaki", "mist", "mixtape", "molten",
    "monster", "morpheus", "morphine", "mosquito", "mother",
    "mouse", "muffin", "mumble", "mushroom", "mystic",
    "nano", "natasha", "nautilus", "nebula", "necrotic",
    "neko", "nemesis", "neptune", "nero", "neuro",
    "neutron", "nexus", "night", "nimbus", "nitrogen",
    "nocturne", "node", "noir", "noodle", "nora",
    "north", "notch", "nova", "nuclear", "nucleus",
    "null", "nv", "nylon", "oasis", "obelisk",
    "obsidian", "octane", "odd", "odyssey", "ohio",
    "olive", "omega", "ominous", "one", "onyx",
    "opal", "open", "operator", "orbit", "orion",
    "orthodox", "osiris", "outline", "overwatch", "oxygen",
    "packet", "paimon", "panda", "pandora", "panther",
    "paradox", "parallel", "patron", "pegasus", "penguin",
    "penix", "perception", "perfect", "perplex", "pharaoh",
    "phantom", "phoenix", "photon", "piano", "pixel",
    "plague", "plasma", "platinum", "pluto", "poison",
    "polar", "pole", "police", "pop", "portal",
    "potato", "power", "premium", "pride", "prism",
    "pro", "prototype", "proxima", "psycho", "pulse",
    "pumpkin", "purity", "pyro", "quad", "quake",
    "quantum", "quartz", "quest", "r3", "rabbit",
    "rage", "rainbow", "rapid", "rapture", "rat",
    "ravager", "raw", "razor", "reality", "rebel",
    "reborn", "recoil", "red", "reflect", "reflex",
    "relax", "relic", "remedy", "remix", "renee",
    "renegade", "reno", "replay", "resilience", "resolve",
    "revolt", "rhino", "rhythm", "rift", "riley",
    "ripple", "risee", "ritual", "rival", "robin",
    "rocket", "rogue", "ronin", "rose", "rowan",
    "ruby", "ruin", "runner", "rupture", "ruthless",
    "saber", "sable", "sacred", "sadness", "sage",
    "salvation", "samurai", "sanctuary", "sand", "sapphire",
    "sativa", "saturn", "savage", "scale", "scarab",
    "scatter", "scepter", "schism", "scorpion", "scr1pt",
    "seismic", "selene", "sense", "sentinel", "seraph",
    "serenity", "servitude", "shade", "shadow", "shard",
    "shatter", "sheep", "shell", "shelly", "shield",
    "shine", "shinigami", "shock", "short", "shrimp",
    "shuffle", "sight", "sigma5", "silence", "silicon",
    "silver", "simplicity", "sin", "siphon", "skid",
    "skills", "skull", "skye", "slate", "sleep",
    "slick", "slime", "slingshot", "sloth", "smack",
    "smart", "smite", "smoke", "snake", "snapshot",
    "sniper", "snow", "soar", "solar", "solitude",
    "soma", "sonic", "sophia", "sorrow", "soul",
    "spade", "spark", "spartan", "spectrum", "speed",
    "sphere", "spider", "spike", "spirit", "splash",
    "spoiler", "spring", "squad", "stabilizer", "stained",
    "star", "stardust", "static", "stealth", "stellar",
    "stinger", "st0rm", "strange", "stratus", "strawberry",
    "stream", "stress", "strobe", "studio", "submerge",
    "subtle", "sunset", "super", "supreme", "surge",
    "surrender", "swagger", "sweet", "swift", "swindle",
    "switch", "symmetry", "symphony", "syndicate", "synergy",
    "syntax", "sys", "t0p", "taboo", "tactical",
    "tailor", "talent", "talon", "tangent", "tango",
    "tanker", "tara", "target", "tarzan", "taze",
    "teardrop", "techno", "tempest", "tender", "tensor",
    "terror", "tesla", "test", "tether", "thc",
    "theia", "thera", "thermo", "thor", "threat",
    "thunder", "tick", "tidal", "tiger", "time",
    "titan", "toast", "token", "tokyo", "torch",
    "tornado", "torrent", "toxic", "tracer", "trail",
    "tranquil", "transform", "trauma", "treasure", "treat",
    "tribe", "trick", "trigger", "trill", "trinity",
    "trip", "triton", "troll", "tropical", "trust",
    "tundra", "turbo", "turtle", "twilight", "twister",
    "typhoon", "tyrant", "tzunami", "uber", "ultima",
    "ultra", "uncut", "under", "unicorn", "unify",
    "unique", "unite", "universe", "up", "uprising",
    "uranium", "urbex", "ursa", "utopia", "vortex",
    "vacuum", "valhalla", "valkyrie", "valor", "vampire",
    "vanguard", "vanish", "vapor", "vault", "vector",
    "vegeta", "velocity", "venom", "ventus", "vera",
    "vertex", "viper", "vivid", "vocal", "void",
    "volcanic", "volt", "vulcan", "vulture", "waffle",
    "walker", "wander", "warfare", "warlock", "warm",
    "warp", "warrior", "water", "wave", "weapon",
    "weave", "weaver", "wedge", "weird", "wendy",
    "whale", "wheat", "whisper", "wicked", "wild",
    "willow", "wind", "wine", "wing", "winner",
    "winter", "wire", "wish", "wisp", "witch",
    "wolf", "wonder", "wood", "world", "woven",
    "wrath", "wreck", "xeno", "xerox", "xi",
    "xile", "xirus", "xorr", "xray+", "xray++",
    "xtasy", "xtreme", "xyro", "yacht", "yal",
    "yam", "yard", "yasha", "yell", "yellow",
    "yeti", "yield", "yoda", "yolk", "yonder",
    "yorick", "yoru", "young", "yugen", "zahara",
    "zap", "zapper", "zara", "zaria", "zeal",
    "zelda", "zendaya", "zenn", "zephyr", "zero",
    "zeta", "zeus", "ziggs", "zinc", "zion",
    "zip", "zodiac", "zoe", "zombie", "zone",
    "zori", "zulu", "zyklon", "zyl", "zym",
    "cheat_config", "hack_config", "aimbot_config", "killaura_config",
    "fly_config", "speed_config", "reach_config", "velocity_config",
    "autoclicker_config", "xray_config", "freecam_config",
    "cheats.json", "hacks.json", "injector.json", "vape.json",
    "sigma.json", "wurst.json", "meteor.json", "raven.json",
    "rise.json", "tenacity.json", "novoline.json", "flux.json",
    "cheats.txt", "hacks.txt", "injector.txt", "vape.ini",
    "sigma.ini", "wurst.ini", "meteor.ini", "raven.ini",
    "rise.ini", "tenacity.ini", "novoline.ini", "flux.ini"
]

MACRO_TOOLS = [
    "autohotkey.exe", "autohotkey", "pulover's macro creator.exe",
    "macro creator.exe", "auto clicker.exe", "autoclicker.exe",
    "opus auto clicker.exe", "speed auto clicker.exe",
    "auto macro.exe", "macro recorder.exe", "mouse recorder.exe",
    "keystroke.exe", "keyboard macro.exe"
]

# ---------- RegEx كسول ----------
_injector_pattern = None
_macro_pattern = None

def get_injector_pattern():
    global _injector_pattern
    if _injector_pattern is None:
        _injector_pattern = re.compile("|".join(re.escape(name) for name in INJECTOR_NAMES), re.IGNORECASE)
    return _injector_pattern

def get_macro_pattern():
    global _macro_pattern
    if _macro_pattern is None:
        _macro_pattern = re.compile("|".join(re.escape(tool) for tool in MACRO_TOOLS), re.IGNORECASE)
    return _macro_pattern

# ========== تحليل PE Headers (EXE/DLL) ==========
SUSPICIOUS_IMPORTS = [
    "WriteProcessMemory", "VirtualAllocEx", "CreateRemoteThread",
    "NtCreateThreadEx", "SetWindowsHookEx", "GetAsyncKeyState",
    "OpenProcess", "ReadProcessMemory", "NtReadVirtualMemory"
]

def analyze_pe_imports(file_path):
    """قراءة imports من PE والبحث عن دوال خطيرة (Windows فقط)."""
    results = []
    if not file_path.lower().endswith(('.exe', '.dll')):
        return results
    try:
        with open(file_path, "rb") as f:
            # قراءة DOS Header
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[0:2] != b'MZ':
                return results
            pe_offset = struct.unpack('<I', dos_header[0x3C:0x40])[0]
            f.seek(pe_offset)
            pe_sig = f.read(4)
            if pe_sig != b'PE\x00\x00':
                return results
            # قراءة COFF Header
            coff = f.read(20)
            # قراءة Optional Header
            opt_hdr_size = struct.unpack('<H', coff[16:18])[0]
            optional_header = f.read(opt_hdr_size)
            # Data directories
            data_dirs_start = f.tell()
            f.seek(data_dirs_start + 8)  # Import directory RVA
            import_rva = struct.unpack('<I', f.read(4))[0]
            if import_rva == 0:
                return results
            # نكتفي بفحص بسيط للـIAT (غير مكتمل لكن يُعطي فكرة)
            # سنعتمد على قراءة سريعة للسلاسل النصية في الملف بدلاً من التحليل الكامل
    except Exception:
        pass

    # طريقة أسرع: قراءة السلاسل داخل الملف والبحث عن imports
    try:
        with open(file_path, "rb") as f:
            content = f.read(4 * 1024 * 1024)  # 4MB max
        for imp in SUSPICIOUS_IMPORTS:
            if imp.encode('utf-8') in content:
                results.append(imp)
    except:
        pass
    return results

# ---------- 1. فتح JAR وتحليل (مع Timeout) ----------
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

    matches = get_injector_pattern().findall(jar_name)
    if matches:
        reasons.append(f"اسم ملف يشير إلى injector: {', '.join(matches[:3])}")
        score += 70

    rule_score, rule_reasons = scan_with_rules(jar_path)
    if rule_reasons:
        reasons.extend(rule_reasons)
        score += rule_score

    return reasons, min(score, 100)

def timed_deep_scan_jar(jar_path, timeout=2.0):
    """تشغيل deep_scan_jar مع timeout."""
    with ThreadPoolExecutor(max_workers=1) as executor:
        future = executor.submit(deep_scan_jar, jar_path)
        try:
            return future.result(timeout=timeout)
        except (TimeoutError, Exception):
            return [f"تجاوز الوقت المحدد ({timeout}s)"], 0

# ---------- 2. فحص المودات (متوازي) ----------
def scan_jar_mods(progress_callback=None, stop_flag=None):
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

    all_jars = []
    for launcher_name, md in mod_dirs:
        all_jars.extend([(str(jar), launcher_name) for jar in md.glob("*.jar")])

    total_mods = len(all_jars)
    if total_mods == 0:
        return results

    completed = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_jar = {
            executor.submit(timed_deep_scan_jar, jar): jar
            for jar, _ in all_jars
        }
        for future in as_completed(future_to_jar):
            completed += 1
            if stop_flag and stop_flag():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            jar = future_to_jar[future]
            try:
                reasons, score = future.result()
                if score > 0:
                    severity = "High" if score >= 70 else "Medium" if score >= 35 else "Low"
                    results.append({
                        "category": "Minecraft Mod",
                        "name": Path(jar).name,
                        "path": jar,
                        "reasons": reasons,
                        "score": score,
                        "severity": severity
                    })
            except:
                pass
            if progress_callback and total_mods > 0:
                percent = int((completed / total_mods) * 100)
                progress_callback(completed, total_mods, f"مودات... {percent}%")

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
            matches = get_injector_pattern().findall(proc_name)
            if matches:
                reasons.append(f"اسم عملية يشير إلى injector: {', '.join(matches[:3])}")
                score += 70

            if get_macro_pattern().search(proc_name):
                reasons.append("أداة ماكرو / auto-clicker مشبوهة")
                score += 50

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
            if get_injector_pattern().search(img.name.lower()):
                matches = get_injector_pattern().findall(img.name.lower())
                results.append({
                    "category": "Screenshot Evidence",
                    "name": img.name,
                    "path": str(img),
                    "reasons": [f"لقطة شاشة باسم مشبوه: {', '.join(matches[:3])}"],
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

# ---------- 9. كشف ملفات DLL/EXE داخل مجلدات ماينكرافت (مع PE Headers) ----------
def scan_suspicious_native_files(progress_callback=None, stop_flag=None):
    results = []
    minecraft_dirs = get_minecraft_dirs()
    all_files = []
    for launcher_name, base in minecraft_dirs:
        for pattern in ["*.dll", "*.exe"]:
            all_files.extend([str(f) for f in base.glob(pattern)])

    total = len(all_files)
    completed = 0
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_to_file = {
            executor.submit(analyze_single_native, f): f
            for f in all_files
        }
        for future in as_completed(future_to_file):
            completed += 1
            if stop_flag and stop_flag():
                executor.shutdown(wait=False, cancel_futures=True)
                break
            file_path = future_to_file[future]
            try:
                reasons, score = future.result(timeout=3.0)
                if score > 0:
                    results.append({
                        "category": "Suspicious Native File",
                        "name": Path(file_path).name,
                        "path": file_path,
                        "reasons": reasons,
                        "score": score,
                        "severity": "High" if score >= 70 else "Medium"
                    })
            except:
                pass
            if progress_callback and total > 0:
                percent = int((completed / total) * 100)
                progress_callback(completed, total, f"ملفات أصلية... {percent}%")

    return results

def analyze_single_native(file_path):
    reasons = []
    score = 80  # وجود DLL/EXE بحد ذاته مشبوه
    reasons.append("مكتبة أصلية أو برنامج تنفيذي داخل مجلد ماينكرافت")

    # فحص الـ PE Imports
    pe_imports = analyze_pe_imports(file_path)
    if pe_imports:
        reasons.append(f"واردات خطيرة: {', '.join(pe_imports[:4])}")
        score += 15

    # فحص القواعد
    rule_score, rule_reasons = scan_with_rules(file_path)
    if rule_reasons:
        reasons.extend(rule_reasons)
        score += rule_score

    return reasons, min(score, 100)

# ---------- 10. فحص ModPacks ----------
def scan_modpacks(progress_callback=None):
    results = []
    home = Path.home()
    modpacks_dir = home / "AppData" / "Roaming" / "modpacks"
    if not modpacks_dir.exists():
        return results
    packs = list(modpacks_dir.iterdir())
    total = len(packs)
    for i, pack in enumerate(packs, 1):
        if progress_callback:
            progress_callback(i, total, f"فحص ModPack: {pack.name}")
        if pack.is_dir():
            reasons = []
            score = 5
            for jar in pack.glob("*.jar"):
                r, s = timed_deep_scan_jar(str(jar), timeout=2.0)
                if r:
                    reasons.extend(r)
                    score += s
            if score > 5:
                results.append({
                    "category": "ModPack",
                    "name": pack.name,
                    "path": str(pack),
                    "reasons": reasons,
                    "score": min(score, 100),
                    "severity": "High" if score >= 70 else "Medium"
                })
            else:
                results.append({
                    "category": "ModPack",
                    "name": pack.name,
                    "path": str(pack),
                    "reasons": ["حزمة تعديلات (ModPack) موجودة"],
                    "score": 5,
                    "severity": "Low"
                })
    return results

# ---------- 11. فحص Recent Files ----------
def scan_recent_files(progress_callback=None):
    results = []
    recent_dir = Path(os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Recent"))
    if not recent_dir.exists():
        return results
    files = list(recent_dir.glob("*"))
    total = len(files)
    for i, file in enumerate(files, 1):
        if progress_callback:
            progress_callback(i, total, f"فحص Recent: {file.name}")
        try:
            name_lower = file.name.lower()
            matches = get_injector_pattern().findall(name_lower)
            if matches:
                results.append({
                    "category": "Recent File",
                    "name": file.name,
                    "path": str(file),
                    "reasons": [f"ملف حديث باسم injector: {', '.join(matches[:3])}"],
                    "score": 60,
                    "severity": "High"
                })
        except:
            continue
    return results

# ---------- 12. فحص Event Logs ----------
def scan_event_logs(progress_callback=None):
    results = []
    try:
        out = subprocess.check_output(
            'wevtutil qe Security /c:50 /rd:true /f:text /q:"*[System[EventID=4688]]"',
            shell=True, text=True, errors='ignore'
        )
        if get_injector_pattern().search(out.lower()):
            results.append({
                "category": "Event Log",
                "name": "Security Event 4688",
                "path": "Windows Security Log",
                "reasons": ["سجل أحداث يحتوي اسم هاك"],
                "score": 50,
                "severity": "Medium"
            })
    except:
        pass
    return results

# ---------- 13. فحص أرشيفات ذاتية الفك ----------
def scan_self_extracting(progress_callback=None):
    results = []
    targets = [
        os.path.expanduser("~/Downloads"),
        os.path.expanduser("~/Desktop"),
    ]
    files = []
    for target in targets:
        p = Path(target)
        if p.exists():
            files.extend(list(p.glob("*.zip")) + list(p.glob("*.rar")) + list(p.glob("*.7z")))
    total = len(files)
    for i, archive in enumerate(files, 1):
        if progress_callback:
            progress_callback(i, total, f"فحص أرشيف: {archive.name}")
        try:
            with zipfile.ZipFile(archive, 'r') as zf:
                entries = zf.namelist()
                for entry in entries:
                    if entry.lower().endswith(('.exe', '.bat', '.cmd', '.ps1', '.vbs')):
                        results.append({
                            "category": "Self-extracting Archive",
                            "name": archive.name,
                            "path": str(archive),
                            "reasons": [f"أرشيف يحتوي ملف تنفيذي: {entry}"],
                            "score": 65,
                            "severity": "High"
                        })
                        break
        except:
            pass
    return results

# ---------- 14. فحص إعدادات البروكسي ----------
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

# ---------- 15. فحص أدلة محذوفة ----------
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
                if get_injector_pattern().search(item.name.lower()):
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

# ---------- 16. فحص حسابات Alt ----------
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