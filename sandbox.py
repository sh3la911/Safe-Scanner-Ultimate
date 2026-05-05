"""
Smart Sandbox – Safe Scanner Ultimate
يشغّل ملف JAR في بيئة Java معزولة مع سياسة أمان صارمة.
يراقب السلوك ويكشف محاولات الحقن.
يتطلب Java مثبتاً على الجهاز.
"""
import os
import subprocess
import tempfile
import time
import threading
import re
from pathlib import Path
from datetime import datetime

# ---------- كلمات دالة على سلوك مشبوه ----------
SUSPICIOUS_SANDBOX_STRINGS = [
    "SecurityException", "access denied", "permission denied",
    "java.net.Socket", "java.io.FileOutputStream", "Runtime.getRuntime",
    "ProcessBuilder", "ClassLoader", "defineClass", "java.lang.reflect",
    "setAccessible", "invoke", "java.awt.Robot", "com.sun.jna",
    "WriteProcessMemory", "VirtualAlloc", "hack", "cheat", "inject"
]

SANDBOX_POLICY_TEMPLATE = """
grant codeBase "file:{jar_path}" {{
    permission java.io.FilePermission "<<ALL FILES>>", "read";
    permission java.lang.RuntimePermission "accessDeclaredMembers";
    permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
    // ممنوع: الكتابة، التنفيذ، الشبكة
}};
"""

def create_policy_file(jar_path):
    policy_content = f"""
grant {{
    permission java.io.FilePermission "<<ALL FILES>>", "read";
    permission java.lang.RuntimePermission "accessDeclaredMembers";
    permission java.lang.reflect.ReflectPermission "suppressAccessChecks";
    // لا تمنح أي صلاحيات خطيرة
}};
"""
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.policy', delete=False, encoding='utf-8')
    tmp.write(policy_content)
    tmp.close()
    return tmp.name

def run_jar_sandbox(jar_path, timeout=15, progress_callback=None):
    """
    تشغيل JAR مع Security Manager.
    يُرجع (reasons, score).
    """
    reasons = []
    score = 0

    if not os.path.exists(jar_path):
        return ["الملف غير موجود"], 0

    # التحقق من وجود Java
    java_home = os.environ.get("JAVA_HOME")
    java_cmd = os.path.join(java_home, "bin", "java.exe") if java_home else "java"
    try:
        subprocess.run([java_cmd, "-version"], capture_output=True, timeout=5)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ["Java غير مثبت أو لا يعمل"], 0

    # إعداد سياسة الأمان
    policy_file = create_policy_file(jar_path)

    # بناء الأمر
    cmd = [
        java_cmd,
        "-Djava.security.manager",
        f"-Djava.security.policy={policy_file}",
        "-jar", jar_path
    ]

    try:
        if progress_callback:
            progress_callback(0, 1, f"جاري تشغيل {os.path.basename(jar_path)} في وضع الأمان...")

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        output_lines = []
        start_time = time.time()
        while True:
            line = proc.stdout.readline()
            if line:
                output_lines.append(line.lower())
                # فحص فوري للكلمات المفتاحية
                for kw in SUSPICIOUS_SANDBOX_STRINGS:
                    if kw.lower() in line.lower():
                        reasons.append(f"سلوك مشبوه: {kw}")
                        score += 40
            if proc.poll() is not None:
                break
            if time.time() - start_time > timeout:
                proc.kill()
                reasons.append("تم إيقاف الملف لتجاوزه الوقت المسموح")
                score += 20
                break

        out = "".join(output_lines)
        # تحليل إضافي للمخرجات
        if "socket" in out:
            reasons.append("محاولة فتح اتصال شبكي")
            score += 50
        if "fileoutputstream" in out:
            reasons.append("محاولة الكتابة على القرص")
            score += 60
        if "runtime.getruntime" in out:
            reasons.append("محاولة تشغيل أمر خارجي")
            score += 70
        if "classloader" in out:
            reasons.append("محاولة تحميل كلاس ديناميكي (دليل حقن)")
            score += 80

    except Exception as e:
        reasons.append(f"خطأ في المحاكاة: {e}")
        score += 10
    finally:
        # تنظيف ملف السياسة
        try:
            os.unlink(policy_file)
        except:
            pass

    if score == 0 and reasons:
        # رفع بسيط للتنبيه حتى لو score=0
        score = 5
    return reasons, min(score, 100)