"""
Forensic Mode – Safe Scanner Ultimate
يلتقط لقطة جنائية كاملة للجهاز (ملفات، عمليات، ريجستري، اتصالات).
Read-only، يصدر تقرير JSON مع طوابع زمنية.
"""
import os
import json
import ctypes
import platform
import socket
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

def is_windows():
    return platform.system().lower() == "windows"

def get_file_snapshot(target_paths):
    """جمع معلومات الملفات (اسم، حجم، تاريخ تعديل، هاش MD5 خفيف)."""
    files = []
    for base in target_paths:
        if not os.path.exists(base):
            continue
        for root, _, filenames in os.walk(base):
            for fname in filenames:
                fp = os.path.join(root, fname)
                try:
                    st = os.stat(fp)
                    files.append({
                        "path": fp,
                        "size": st.st_size,
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat()
                    })
                except OSError:
                    pass
    return files

def get_process_snapshot():
    """قائمة العمليات الجارية مع تفاصيلها."""
    procs = []
    if psutil is None:
        return procs
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            procs.append(proc.info)
        except:
            continue
    return procs

def get_registry_snapshot():
    """قراءة مفاتيح بدء التشغيل من الريجستري."""
    keys = []
    if not is_windows():
        return keys
    import winreg
    reg_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hkey, subkey in reg_paths:
        try:
            with winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        keys.append({"name": name, "path": value})
                        i += 1
                    except OSError:
                        break
        except Exception:
            continue
    return keys

def get_network_snapshot():
    """الاتصالات الشبكية النشطة."""
    conns = []
    if psutil is None:
        return conns
    try:
        for conn in psutil.net_connections(kind='inet'):
            if conn.status == 'ESTABLISHED':
                conns.append({
                    "local": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                    "remote": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "pid": conn.pid
                })
    except:
        pass
    return conns

def take_forensic_snapshot(target_paths, progress_callback=None):
    """
    التقاط لقطة جنائية كاملة.
    يُرجع قاموساً بكل البيانات.
    """
    if progress_callback:
        progress_callback(0, 4, "جمع الملفات...")
    files = get_file_snapshot(target_paths)

    if progress_callback:
        progress_callback(1, 4, "جمع العمليات...")
    processes = get_process_snapshot()

    if progress_callback:
        progress_callback(2, 4, "جمع الريجستري...")
    registry = get_registry_snapshot()

    if progress_callback:
        progress_callback(3, 4, "جمع الاتصالات...")
    network = get_network_snapshot()

    snapshot = {
        "timestamp": datetime.now().isoformat(),
        "system": platform.platform(),
        "files": files,
        "processes": processes,
        "registry_startup": registry,
        "network_connections": network
    }

    if progress_callback:
        progress_callback(4, 4, "اكتملت اللقطة")

    return snapshot

def save_forensic_snapshot(snapshot, file_path):
    """حفظ اللقطة كملف JSON."""
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, ensure_ascii=False, indent=2)
    return file_path