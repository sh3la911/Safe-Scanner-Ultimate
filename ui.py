import os
import sys
import subprocess
import threading
import queue
import json
import math
import csv
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
from pathlib import Path

from scanner import (scan_files_parallel, quick_scan_files, scan_processes, scan_startup,
                     save_report_json, scan_registry_startup, scan_scheduled_tasks, scan_network_connections,
                     manual_scan_path, scan_browsers, get_system_tools_list, open_system_tool)
from minecraft_scanner import (scan_jar_mods, scan_launchers, scan_minecraft_processes,
                               scan_deleted_evidence, scan_screenshots, scan_configs,
                               scan_resource_packs, scan_command_history, scan_suspicious_native_files,
                               scan_proxy_settings, scan_alt_accounts,
                               scan_memory_strings, scan_loaded_modules,
                               scan_modpacks, scan_recent_files, scan_event_logs, scan_self_extracting)
from integrity_checker import scan_system_integrity
from sandbox import run_jar_sandbox
from forensic import take_forensic_snapshot, save_forensic_snapshot
from lan_scanner import scan_lan
from yara_updater import update_yara_rules
from report_pdf import generate_pdf_report

# ---------- إشعار سطح المكتب ----------
try:
    from win10toast import ToastNotifier
    toaster = ToastNotifier()
    _notify_available = True
except ImportError:
    _notify_available = False

def notify(title, message):
    if _notify_available:
        try:
            toaster.show_toast(title, message, duration=5, threaded=True)
        except:
            pass

# ---------- Tooltip ----------
class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None
        widget.bind('<Enter>', self.show)
        widget.bind('<Leave>', self.hide)

    def show(self, event=None):
        if self.tip_window or not self.text:
            return
        x = self.widget.winfo_rootx() + 25
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 5
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = tk.Label(tw, text=self.text, justify='left',
                         background="#ffffe0", foreground="black",
                         relief='solid', borderwidth=1, font=("Segoe UI", 9))
        label.pack()

    def hide(self, event=None):
        if self.tip_window:
            self.tip_window.destroy()
            self.tip_window = None

# ---------- رسم بياني ----------
def draw_pie_chart(canvas, data, cx, cy, radius):
    total = sum(data.values())
    if total == 0:
        canvas.create_text(cx, cy, text="لا توجد نتائج", font=("Segoe UI", 10))
        return
    start_angle = 0
    colors = {"High": "#dc3545", "Medium": "#ffc107", "Low": "#28a745"}
    for label, count in data.items():
        extent = (count / total) * 360
        if extent > 0:
            canvas.create_arc(cx - radius, cy - radius, cx + radius, cy + radius,
                              start=start_angle, extent=extent,
                              fill=colors.get(label, "#6c757d"), outline="white")
        start_angle += extent
    y = cy - radius - 20
    for label, color in colors.items():
        canvas.create_oval(cx + radius + 10, y - 5, cx + radius + 20, y + 5, fill=color, outline="")
        canvas.create_text(cx + radius + 50, y, text=label, anchor="w", font=("Segoe UI", 9))
        y += 20

def draw_bar_chart(canvas, data, x0, y0, width, height):
    max_val = max(data.values()) if data else 1
    y = y0
    colors = {"High": "#dc3545", "Medium": "#ffc107", "Low": "#28a745"}
    for label, count in data.items():
        if count > 0:
            bar_width = (count / max_val) * width
            canvas.create_rectangle(x0, y, x0 + bar_width, y + 20,
                                    fill=colors.get(label, "#6c757d"), outline="")
            canvas.create_text(x0 + bar_width + 5, y + 10, text=f"{label} ({count})",
                               anchor="w", font=("Segoe UI", 9))
        y += 30

# ---------- Stop flag ----------
class StopFlag:
    def __init__(self):
        self._stop = threading.Event()
    def stop(self):
        self._stop.set()
    def is_set(self):
        return self._stop.is_set()
    def clear(self):
        self._stop.clear()

# ---------- نافذة أدوات النظام ----------
class SystemToolsWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("أدوات النظام")
        self.geometry("300x400")
        ttk.Label(self, text="أدوات النظام المساعدة", font=("Segoe UI", 12, "bold")).pack(pady=10)
        tools = get_system_tools_list()
        for tool in tools:
            name = tool["name"]
            ttk.Button(self, text=f"🔧 {name}", command=lambda n=name: self.open_tool(n)).pack(fill="x", padx=20, pady=4)

    def open_tool(self, name):
        if open_system_tool(name):
            messagebox.showinfo("تم", f"تم فتح {name}")
        else:
            messagebox.showerror("خطأ", f"تعذر فتح {name}")

# ---------- ScanTab العام ----------
class ScanTab(ttk.Frame):
    def __init__(self, parent, scan_func, scan_name, supports_parallel=False):
        super().__init__(parent)
        self.scan_func = scan_func
        self.scan_name = scan_name
        self.results = []
        self.scanning = False
        self.stop_flag = StopFlag()
        self.q = queue.Queue()
        self.supports_parallel = supports_parallel
        self.create_widgets()
        self.after(100, self.process_queue)

    def create_widgets(self):
        toolbar = ttk.Frame(self, padding=10)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text=self.scan_name, font=("Segoe UI", 14, "bold")).pack(side="left")
        self.scan_btn = ttk.Button(toolbar, text="🔍 ابدأ الفحص", command=self.start_scan)
        self.scan_btn.pack(side="right", padx=5)
        self.stop_btn = ttk.Button(toolbar, text="⏹️ إيقاف", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(side="right", padx=5)
        ttk.Button(toolbar, text="📂 فحص ملف/مجلد", command=self.manual_scan).pack(side="right", padx=5)
        ttk.Button(toolbar, text="🔧 أدوات النظام", command=self.show_system_tools).pack(side="right", padx=5)
        ttk.Button(toolbar, text="📄 HTML", command=self.export_html).pack(side="right", padx=2)
        ttk.Button(toolbar, text="💾 JSON", command=self.save_json).pack(side="right", padx=2)
        ttk.Button(toolbar, text="📊 CSV", command=self.export_csv).pack(side="right", padx=2)
        ttk.Button(toolbar, text="📕 PDF", command=self.export_pdf).pack(side="right", padx=2)
        ttk.Button(toolbar, text="📋 نسخ المسار", command=self.copy_path).pack(side="right", padx=2)
        ttk.Button(toolbar, text="🗑️ مسح", command=self.clear).pack(side="right", padx=2)

        Tooltip(self.scan_btn, "ابدأ فحصاً كاملاً")
        Tooltip(self.stop_btn, "إيقاف الفحص الجاري بأمان")

        search_frame = ttk.Frame(self, padding=(10, 0))
        search_frame.pack(fill="x")
        ttk.Label(search_frame, text="🔎").pack(side="left")
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self.refresh_tree())
        ttk.Entry(search_frame, textvariable=self.search_var, width=35).pack(side="left", padx=5)

        tree_frame = ttk.Frame(self, padding=10)
        tree_frame.pack(fill="both", expand=True)
        columns = ("severity", "score", "category", "name", "path", "reasons")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        headings = {"severity": "Risk", "score": "Score%", "category": "Category",
                    "name": "Name", "path": "Path", "reasons": "Reasons"}
        widths = [70, 70, 130, 180, 360, 320]
        for i, col in enumerate(columns):
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[i], anchor="w")
        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        scroll_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        scroll_x.grid(row=1, column=0, sticky="ew")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)
        self.tree.bind("<Double-1>", self.open_location)

        status_frame = ttk.Frame(self, padding=10)
        status_frame.pack(fill="x", side="bottom")
        self.progress = ttk.Progressbar(status_frame, mode="indeterminate", length=200)
        self.progress.pack(side="left", padx=(0, 10))
        self.status_var = tk.StringVar(value="جاهز.")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side="left")
        self.summary_var = tk.StringVar(value="")
        ttk.Label(status_frame, textvariable=self.summary_var, font=("Segoe UI", 9, "bold")).pack(side="right")

    def clear(self):
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.progress.stop()
        self.progress.config(mode="indeterminate", value=0)
        self.status_var.set("جاهز.")
        self.summary_var.set("🔹 لا توجد نتائج")

    def start_scan(self):
        if self.scanning:
            messagebox.showwarning("Busy", "الفحص جارٍ بالفعل.")
            return
        self.scanning = True
        self.stop_flag.clear()
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.progress.start()
        self.status_var.set("جاري الفحص...")
        self.summary_var.set("⏳")
        thread = threading.Thread(target=self.run_scan, daemon=True)
        thread.start()

    def stop_scan(self):
        if self.scanning:
            self.stop_flag.stop()
            self.status_var.set("جاري الإيقاف...")

    def run_scan(self):
        all_results = []
        def prog_cb(current, total, msg=""):
            percent = int((current / total) * 100) if total > 0 else 0
            self.q.put(("progress", percent))
            self.q.put(("status", f"{msg} ({percent}%)"))

        try:
            if self.supports_parallel:
                all_results = self.scan_func(prog_cb, stop_flag=self.stop_flag)
            else:
                all_results = self.scan_func(prog_cb)
        except Exception as e:
            self.q.put(("error", str(e)))
            return
        self.q.put(("done", all_results))

    def process_queue(self):
        try:
            while True:
                msg_type, payload = self.q.get_nowait()
                if msg_type == "status":
                    self.status_var.set(payload)
                elif msg_type == "progress":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=payload)
                elif msg_type == "done":
                    self.progress.stop()
                    self.progress.config(mode="determinate", value=100)
                    self.results = payload
                    self.refresh_tree()
                    self.status_var.set(f"تم. النتائج: {len(self.results)}")
                    self.scanning = False
                    self.scan_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.update_summary()
                    high = sum(1 for r in self.results if r.get("severity") == "High")
                    if high > 0:
                        notify("Safe Scanner", f"تم اكتشاف {high} عنصر عالي الخطورة!")
                    messagebox.showinfo("Done", f"انتهى الفحص.\nعدد النتائج: {len(self.results)}")
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def manual_scan(self):
        path = filedialog.askopenfilename(title="اختر ملف للفحص")
        if not path:
            path = filedialog.askdirectory(title="اختر مجلد للفحص")
        if not path:
            return
        self.scanning = True
        self.scan_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.results = []
        self.tree.delete(*self.tree.get_children())
        self.progress.start()
        self.status_var.set("جاري الفحص اليدوي...")
        thread = threading.Thread(target=self.run_manual_scan, args=(path,), daemon=True)
        thread.start()

    def run_manual_scan(self, target):
        all_results = manual_scan_path(target, progress_callback=None)
        self.q.put(("done", all_results))

    def show_system_tools(self):
        SystemToolsWindow(self)

    def refresh_tree(self):
        self.tree.delete(*self.tree.get_children())
        query = self.search_var.get().strip().lower()
        self.tree.tag_configure("high", background="#FFD2D2", foreground="black")
        self.tree.tag_configure("medium", background="#FFF3CD", foreground="black")
        self.tree.tag_configure("low", background="#D4EDDA", foreground="black")

        for idx, item in enumerate(self.results):
            text_blob = " ".join([
                str(item.get("severity")), str(item.get("score")),
                str(item.get("category")), str(item.get("name")),
                str(item.get("path")), " ".join(item.get("reasons", []))
            ]).lower()
            if query and query not in text_blob:
                continue

            severity = item.get("severity", "Low")
            tag = "low"
            if severity == "High": tag = "high"
            elif severity == "Medium": tag = "medium"
            self.tree.insert("", "end", iid=str(idx),
                             values=(severity, f"{item.get('score',0)}%",
                                     item.get("category"), item.get("name"),
                                     item.get("path"), " | ".join(item.get("reasons", []))),
                             tags=(tag,))
        self.update_summary()

    def update_summary(self):
        high = sum(1 for r in self.results if r.get("severity") == "High")
        med = sum(1 for r in self.results if r.get("severity") == "Medium")
        low = sum(1 for r in self.results if r.get("severity") == "Low")
        self.summary_var.set(f"🔴 {high}  🟡 {med}  🟢 {low}")

    def get_selected_item(self):
        sel = self.tree.selection()
        if not sel: return None
        idx = int(sel[0])
        if 0 <= idx < len(self.results):
            return self.results[idx]
        return None

    def open_location(self, event=None):
        item = self.get_selected_item()
        if not item: return
        path = item.get("path", "")
        if not path or not os.path.exists(path):
            messagebox.showwarning("Missing", "المسار غير موجود.")
            return
        folder = path if os.path.isdir(path) else os.path.dirname(path)
        try:
            if os.name == "nt": os.startfile(folder)
            elif sys.platform == "darwin": subprocess.run(["open", folder])
            else: subprocess.run(["xdg-open", folder])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def copy_path(self):
        item = self.get_selected_item()
        if not item: return
        path = item.get("path", "")
        if path:
            self.clipboard_clear()
            self.clipboard_append(path)
            messagebox.showinfo("Copied", "تم نسخ المسار.")

    def save_json(self):
        if not self.results:
            messagebox.showwarning("No Data", "اعمل فحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON", "*.json")])
        if path:
            save_report_json(self.results, path)
            messagebox.showinfo("Saved", f"تم الحفظ في:\n{path}")

    def export_html(self):
        if not self.results:
            messagebox.showwarning("No Data", "اعمل فحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if not path: return
        html = self.build_html()
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        messagebox.showinfo("Saved", f"تم تصدير HTML إلى:\n{path}")

    def export_csv(self):
        if not self.results:
            messagebox.showwarning("No Data", "اعمل فحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path: return
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Risk", "Score%", "Category", "Name", "Path", "Reasons"])
            for r in self.results:
                writer.writerow([
                    r.get("severity"),
                    r.get("score"),
                    r.get("category"),
                    r.get("name"),
                    r.get("path"),
                    " | ".join(r.get("reasons", []))
                ])
        messagebox.showinfo("Saved", f"تم تصدير CSV إلى:\n{path}")

    def export_pdf(self):
        if not self.results:
            messagebox.showwarning("No Data", "اعمل فحص أولاً.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not path: return
        generate_pdf_report(self.results, path, self.scan_name)
        messagebox.showinfo("Saved", f"تم تصدير PDF إلى:\n{path}")

    def build_html(self):
        rows = ""
        for r in self.results:
            sev = r.get("severity", "Low")
            color = {"High": "#dc3545", "Medium": "#ffc107", "Low": "#28a745"}.get(sev, "#6c757d")
            reasons = "<br>".join(r.get("reasons", []))
            rows += f"""<tr>
                <td style='color:{color};font-weight:bold'>{sev}</td>
                <td>{r.get('score',0)}%</td>
                <td>{r.get('category')}</td>
                <td>{r.get('name')}</td>
                <td>{r.get('path')}</td>
                <td>{reasons}</td></tr>"""
        return f"""<html dir="rtl"><head><meta charset="UTF-8"><title>تقرير {self.scan_name}</title>
        <style>body{{font-family:Tahoma;background:#f8f9fa;padding:20px}}
        table{{border-collapse:collapse;width:100%;background:white;box-shadow:0 2px 8px rgba(0,0,0,.1)}}
        th{{background:#007bff;color:white;padding:10px;text-align:right}}
        td{{padding:8px;border-bottom:1px solid #ddd}}</style></head>
        <body><h1>تقرير {self.scan_name}</h1><p>{datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
        <table><tr><th>Risk</th><th>Score</th><th>Category</th><th>Name</th><th>Path</th><th>Reasons</th></tr>
        {rows}</table></body></html>"""


# ---------- Dashboard (مع Quick Scan) ----------
class Dashboard(ttk.Frame):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.create_widgets()

    def create_widgets(self):
        ttk.Label(self, text="Safe Scanner Ultimate", font=("Segoe UI", 24, "bold")).pack(pady=20)
        ttk.Label(self, text="الدرع الواقي لجهازك وألعابك", font=("Segoe UI", 11)).pack()

        stats_frame = ttk.LabelFrame(self, text="إحصائيات آخر فحص", padding=15)
        stats_frame.pack(fill="x", padx=30, pady=10)

        self.lbl_total = ttk.Label(stats_frame, text="إجمالي النتائج: --", font=("Segoe UI", 12))
        self.lbl_total.grid(row=0, column=0, padx=10)
        self.lbl_high = ttk.Label(stats_frame, text="🔴 عالي: --", font=("Segoe UI", 12))
        self.lbl_high.grid(row=0, column=1, padx=10)
        self.lbl_med = ttk.Label(stats_frame, text="🟡 متوسط: --", font=("Segoe UI", 12))
        self.lbl_med.grid(row=0, column=2, padx=10)
        self.lbl_low = ttk.Label(stats_frame, text="🟢 منخفض: --", font=("Segoe UI", 12))
        self.lbl_low.grid(row=0, column=3, padx=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="🔍 فحص كامل", command=self.app.run_full_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="⚡ فحص سريع", command=self.app.run_quick_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🧩 فحص ماينكرافت", command=self.app.run_minecraft_scan).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="📂 فحص ملف/مجلد", command=self.manual_scan_dashboard).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="🔧 أدوات النظام", command=self.show_system_tools).pack(side="left", padx=5)

        remote_frame = ttk.Frame(self)
        remote_frame.pack(pady=10)
        ttk.Button(remote_frame, text="🖥️ Remote Server", command=self.start_remote_server).pack(side="left", padx=5)
        ttk.Button(remote_frame, text="🖱️ Remote Client", command=self.start_remote_client).pack(side="left", padx=5)

        quick_frame = ttk.Frame(self)
        quick_frame.pack(pady=5)
        ttk.Button(quick_frame, text="📁 فتح Downloads", command=lambda: os.startfile(os.path.expanduser("~/Downloads"))).pack(side="left", padx=5)
        ttk.Button(quick_frame, text="📁 فتح Desktop", command=lambda: os.startfile(os.path.expanduser("~/Desktop"))).pack(side="left", padx=5)

        chart_frame = ttk.Frame(self)
        chart_frame.pack(fill="both", expand=True, padx=20, pady=10)
        self.pie_canvas = tk.Canvas(chart_frame, width=300, height=300, bg="#f8f9fa", highlightthickness=0)
        self.pie_canvas.pack(side="left", padx=20)
        self.bar_canvas = tk.Canvas(chart_frame, width=250, height=150, bg="#f8f9fa", highlightthickness=0)
        self.bar_canvas.pack(side="left", padx=20)

    def update_stats(self, results):
        total = len(results)
        high = sum(1 for r in results if r.get("severity") == "High")
        med = sum(1 for r in results if r.get("severity") == "Medium")
        low = sum(1 for r in results if r.get("severity") == "Low")
        self.lbl_total.config(text=f"إجمالي النتائج: {total}")
        self.lbl_high.config(text=f"🔴 عالي: {high}")
        self.lbl_med.config(text=f"🟡 متوسط: {med}")
        self.lbl_low.config(text=f"🟢 منخفض: {low}")

        self.pie_canvas.delete("all")
        draw_pie_chart(self.pie_canvas, {"High": high, "Medium": med, "Low": low}, 130, 150, 100)
        self.bar_canvas.delete("all")
        draw_bar_chart(self.bar_canvas, {"High": high, "Medium": med, "Low": low}, 10, 10, 200, 100)

    def manual_scan_dashboard(self):
        self.app.general_tab.manual_scan()

    def show_system_tools(self):
        SystemToolsWindow(self)

    def start_remote_server(self):
        threading.Thread(target=lambda: subprocess.run([sys.executable, "remote_server.py"]), daemon=True).start()

    def start_remote_client(self):
        threading.Thread(target=lambda: subprocess.run([sys.executable, "remote_client.py"]), daemon=True).start()


# ---------- Behavioral Tab ----------
class BehavioralTab(ttk.Frame):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.snapshot_file = Path("snapshot.json")
        self.busy = False
        self.q = queue.Queue()
        self.create_widgets()
        self.after(100, self.process_queue)

    def create_widgets(self):
        ttk.Label(self, text="كاشف التغييرات السلوكي", font=("Segoe UI", 14, "bold")).pack(pady=10)
        ttk.Label(self, text="يحفظ لقطة للملفات والعمليات ثم يقارن ليكشف التغيرات الجديدة").pack()

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=10)
        self.snap_btn = ttk.Button(btn_frame, text="📸 حفظ لقطة الآن", command=self.take_snapshot)
        self.snap_btn.pack(side="left", padx=5)
        self.cmp_btn = ttk.Button(btn_frame, text="🔍 مقارنة باللقطة", command=self.compare_snapshot)
        self.cmp_btn.pack(side="left", padx=5)

        Tooltip(self.snap_btn, "يحفظ لقطة للملفات والعمليات الجارية حالياً")
        Tooltip(self.cmp_btn, "يقارن الوضع الحالي باللقطة المحفوظة")

        self.progress = ttk.Progressbar(self, mode="indeterminate", length=200)
        self.progress.pack(pady=5)

        self.status_lbl = ttk.Label(self, text="")
        self.status_lbl.pack()

        self.results_tree = ttk.Treeview(self, columns=("type", "detail"), show="headings", height=15)
        self.results_tree.heading("type", text="نوع التغيير")
        self.results_tree.heading("detail", text="التفاصيل")
        self.results_tree.column("type", width=150)
        self.results_tree.column("detail", width=600)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        self.results_tree.pack(side="left", fill="both", expand=True, padx=10, pady=5)
        scrollbar.pack(side="right", fill="y")

    def process_queue(self):
        try:
            while True:
                msg_type, payload = self.q.get_nowait()
                if msg_type == "status":
                    self.status_lbl.config(text=payload)
                elif msg_type == "done_snap":
                    self.progress.stop()
                    self.snap_btn.config(state="normal")
                    self.status_lbl.config(text="✅ تم حفظ اللقطة بنجاح.")
                elif msg_type == "done_comp":
                    self.progress.stop()
                    self.cmp_btn.config(state="normal")
                    self.results_tree.delete(*self.results_tree.get_children())
                    for item in payload:
                        self.results_tree.insert("", "end", values=item)
                    self.status_lbl.config(text="✅ تمت المقارنة. التغييرات معروضة أعلاه.")
        except queue.Empty:
            pass
        self.after(100, self.process_queue)

    def take_snapshot(self):
        if self.busy:
            messagebox.showwarning("Busy", "العملية جارية.")
            return
        self.busy = True
        self.snap_btn.config(state="disabled")
        self.progress.start()
        self.status_lbl.config(text="جاري حفظ اللقطة...")
        thread = threading.Thread(target=self._do_snapshot, daemon=True)
        thread.start()

    def _do_snapshot(self):
        try:
            home = os.path.expanduser("~")
            targets = [
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
                os.path.expandvars(r"%APPDATA%"),
            ]
            snapshot = {"files": {}, "processes": []}
            for target in targets:
                for root, _, files in os.walk(target):
                    for file in files:
                        fp = os.path.join(root, file)
                        try:
                            snapshot["files"][fp] = os.path.getsize(fp)
                        except OSError:
                            pass
            import psutil
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    snapshot["processes"].append(proc.info)
                except:
                    continue
            with open(self.snapshot_file, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            self.q.put(("done_snap", None))
        except Exception as e:
            self.q.put(("status", f"❌ خطأ: {e}"))
        finally:
            self.busy = False

    def compare_snapshot(self):
        if self.busy:
            messagebox.showwarning("Busy", "العملية جارية.")
            return
        if not self.snapshot_file.exists():
            self.status_lbl.config(text="⚠️ لا توجد لقطة محفوظة. احفظ لقطة أولاً.")
            return
        self.busy = True
        self.cmp_btn.config(state="disabled")
        self.progress.start()
        self.status_lbl.config(text="جاري المقارنة...")
        thread = threading.Thread(target=self._do_compare, daemon=True)
        thread.start()

    def _do_compare(self):
        changes = []
        try:
            with open(self.snapshot_file, "r", encoding="utf-8") as f:
                old = json.load(f)
            home = os.path.expanduser("~")
            targets = [
                os.path.join(home, "Downloads"),
                os.path.join(home, "Desktop"),
            ]
            new_files = {}
            for target in targets:
                for root, _, files in os.walk(target):
                    for file in files:
                        fp = os.path.join(root, file)
                        try:
                            new_files[fp] = os.path.getsize(fp)
                        except OSError:
                            pass

            for fp, size in new_files.items():
                if fp not in old["files"]:
                    changes.append(("ملف جديد", fp))
                elif old["files"][fp] != size:
                    changes.append(("ملف معدل", fp))

            import psutil
            new_pids = set()
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    new_pids.add(proc.info["pid"])
                except:
                    pass
            old_pids = {p["pid"] for p in old["processes"] if p["pid"] is not None}
            new_procs = new_pids - old_pids
            for pid in new_procs:
                changes.append(("عملية جديدة", f"PID {pid}"))
            self.q.put(("done_comp", changes))
        except Exception as e:
            self.q.put(("status", f"❌ خطأ: {e}"))
        finally:
            self.busy = False


# ---------- History Tab ----------
class HistoryTab(ttk.Frame):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.history_file = Path("scan_history.json")
        self.history = self.load_history()
        self.create_widgets()

    def load_history(self):
        if self.history_file.exists():
            try:
                with open(self.history_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except:
                return []
        return []

    def save_history(self):
        with open(self.history_file, "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)

    def add_entry(self, results, scan_name):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "scan_name": scan_name,
            "total": len(results),
            "high": sum(1 for r in results if r.get("severity") == "High"),
            "results": results
        }
        self.history.append(entry)
        self.save_history()
        self.refresh_list()

    def create_widgets(self):
        ttk.Label(self, text="سجل الفحوصات", font=("Segoe UI", 14, "bold")).pack(pady=10)
        list_frame = ttk.Frame(self)
        list_frame.pack(fill="both", expand=True, padx=10)

        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side="right", fill="y")
        self.listbox = tk.Listbox(list_frame, yscrollcommand=scrollbar.set,
                                  height=20, font=("Consolas", 10))
        self.listbox.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.listbox.yview)
        self.listbox.bind("<Double-1>", self.load_selected)
        self.refresh_list()

        ttk.Button(self, text="تصدير كامل التاريخ إلى JSON",
                   command=self.export_full_history).pack(pady=5)

    def refresh_list(self):
        self.listbox.delete(0, tk.END)
        for i, entry in enumerate(self.history):
            ts = entry.get("timestamp", "?")
            name = entry.get("scan_name", "?")
            total = entry.get("total", 0)
            high = entry.get("high", 0)
            self.listbox.insert(tk.END, f"{i+1}. [{ts}] {name} - {total} نتائج (🔴{high})")

    def load_selected(self, event=None):
        sel = self.listbox.curselection()
        if not sel: return
        idx = sel[0]
        if idx < len(self.history):
            entry = self.history[idx]
            results = entry.get("results", [])
            self.app.show_results_in_new_tab(results, f"History: {entry['timestamp']}")

    def export_full_history(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON", "*.json")])
        if not path: return
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.history, f, ensure_ascii=False, indent=2)
        messagebox.showinfo("Saved", "تم تصدير السجل.")


# ---------- System Integrity Tab ----------
class IntegrityTab(ScanTab):
    def __init__(self, parent, app_ref):
        self.app = app_ref
        def integrity_func(prog, stop_flag=None):
            return scan_system_integrity(prog)
        super().__init__(parent, integrity_func, "🛡️ System Integrity Checker", supports_parallel=False)


# ---------- Sandbox Tab ----------
class SandboxTab(ttk.Frame):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        self.results = []
        self.create_widgets()

    def create_widgets(self):
        toolbar = ttk.Frame(self, padding=10)
        toolbar.pack(fill="x")
        ttk.Label(toolbar, text="🧪 Smart Sandbox", font=("Segoe UI", 14, "bold")).pack(side="left")
        self.scan_btn = ttk.Button(toolbar, text="📂 اختر ملف JAR", command=self.select_jar)
        self.scan_btn.pack(side="right", padx=5)

        self.progress = ttk.Progressbar(self, mode="indeterminate", length=200)
        self.progress.pack(pady=5)

        self.status_var = tk.StringVar(value="اختر ملف JAR لفحصه في بيئة آمنة")
        ttk.Label(self, textvariable=self.status_var, font=("Segoe UI", 10)).pack()

        tree_frame = ttk.Frame(self, padding=10)
        tree_frame.pack(fill="both", expand=True)
        columns = ("severity", "score", "category", "name", "path", "reasons")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings")
        headings = {"severity": "Risk", "score": "Score%", "category": "Category",
                    "name": "Name", "path": "Path", "reasons": "Reasons"}
        for i, col in enumerate(columns):
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=[70,70,130,180,360,300][i], anchor="w")
        scroll_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll_y.set)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scroll_y.grid(row=0, column=1, sticky="ns")
        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

    def select_jar(self):
        path = filedialog.askopenfilename(title="اختر ملف JAR", filetypes=[("JAR files", "*.jar")])
        if not path:
            return
        self.scan_btn.config(state="disabled")
        self.progress.start()
        self.status_var.set(f"جاري محاكاة {os.path.basename(path)}...")
        threading.Thread(target=self.run_sandbox, args=(path,), daemon=True).start()

    def run_sandbox(self, jar_path):
        reasons, score = run_jar_sandbox(jar_path)
        result = {
            "category": "Sandbox Analysis",
            "name": os.path.basename(jar_path),
            "path": jar_path,
            "reasons": reasons,
            "score": score,
            "severity": "High" if score >= 70 else "Medium" if score >= 35 else "Low"
        }
        self.results = [result]
        self.after(0, self.show_results)

    def show_results(self):
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.tree.delete(*self.tree.get_children())
        for idx, r in enumerate(self.results):
            self.tree.insert("", "end", iid=str(idx),
                             values=(r["severity"], f"{r['score']}%", r["category"],
                                     r["name"], r["path"], " | ".join(r["reasons"])))
        self.status_var.set(f"اكتملت المحاكاة")


# ---------- Forensic Tab ----------
class ForensicTab(ScanTab):
    def __init__(self, parent, app_ref):
        self.app = app_ref
        def forensic_func(prog, stop_flag=None):
            snapshot = take_forensic_snapshot([
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
            ], prog)
            # تحويل اللقطة إلى قائمة
            results = []
            for f in snapshot["files"]:
                results.append({
                    "category": "Forensic File",
                    "name": os.path.basename(f["path"]),
                    "path": f["path"],
                    "reasons": [f"تاريخ التعديل: {f['modified']}"],
                    "score": 0,
                    "severity": "Low"
                })
            for p in snapshot["processes"]:
                results.append({
                    "category": "Process",
                    "name": p.get("name", "?"),
                    "path": p.get("exe", ""),
                    "reasons": [f"PID: {p.get('pid','')}"],
                    "score": 0,
                    "severity": "Low"
                })
            return results
        super().__init__(parent, forensic_func, "🕵️ Forensic Snapshot", supports_parallel=False)


# ---------- LAN Scanner Tab ----------
class LANTab(ScanTab):
    def __init__(self, parent, app_ref):
        self.app = app_ref
        def lan_func(prog, stop_flag=None):
            return scan_lan(prog)
        super().__init__(parent, lan_func, "📡 LAN Scanner", supports_parallel=False)


# ---------- YARA Updater Tab ----------
class YARAUpdateTab(ttk.Frame):
    def __init__(self, parent, app_ref):
        super().__init__(parent)
        self.app = app_ref
        ttk.Label(self, text="تحديث قواعد YARA", font=("Segoe UI", 14, "bold")).pack(pady=10)
        self.status_lbl = ttk.Label(self, text="")
        self.status_lbl.pack()
        ttk.Button(self, text="🔄 تحديث الآن", command=self.update).pack(pady=5)

    def update(self):
        self.status_lbl.config(text="جاري التحميل...")
        threading.Thread(target=self._do_update, daemon=True).start()

    def _do_update(self):
        success, msg = update_yara_rules()
        self.after(0, lambda: self.status_lbl.config(text=f"✅ {msg}" if success else f"❌ {msg}"))


# ---------- التطبيق الرئيسي ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Safe Scanner Ultimate")
        self.geometry("1400x900")
        self.minsize(1100, 700)

        self.dark_mode = False
        self.style = ttk.Style()
        self.style.theme_use("clam")

        self.light_bg = "#f0f0f0"
        self.dark_bg = "#2b2b2b"
        self.light_fg = "black"
        self.dark_fg = "white"

        self.configure(bg=self.light_bg)

        menubar = tk.Menu(self)
        self.config(menu=menubar)
        settings_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Settings", menu=settings_menu)
        settings_menu.add_command(label="Toggle Dark Mode", command=self.toggle_dark_mode)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True)

        # Dashboard
        self.dashboard = Dashboard(self.notebook, self)
        self.notebook.add(self.dashboard, text="📊 Dashboard")

        # General Tab
        def full_scan_func(prog, stop_flag=None):
            res = []
            targets = self.get_targets()
            res.extend(scan_files_parallel(targets, prog, quick_mode=False, stop_flag=stop_flag))
            res.extend(scan_processes(prog))
            res.extend(scan_startup(prog))
            res.extend(scan_registry_startup())
            res.extend(scan_scheduled_tasks())
            res.extend(scan_network_connections())
            res.extend(scan_browsers())
            return res
        self.general_tab = ScanTab(self.notebook, full_scan_func, "🛡️ General Scanner", supports_parallel=True)
        self.notebook.add(self.general_tab, text="🛡️ عام")

        # Minecraft Tab
        def mc_scan_func(prog, stop_flag=None):
            res = []
            res.extend(scan_jar_mods(prog, stop_flag=stop_flag))
            res.extend(scan_launchers(prog))
            res.extend(scan_minecraft_processes(prog))
            res.extend(scan_screenshots(prog))
            res.extend(scan_configs(prog))
            res.extend(scan_resource_packs(prog))
            res.extend(scan_command_history(prog))
            res.extend(scan_suspicious_native_files(prog, stop_flag=stop_flag))
            res.extend(scan_modpacks(prog))
            res.extend(scan_recent_files(prog))
            res.extend(scan_event_logs(prog))
            res.extend(scan_self_extracting(prog))
            res.extend(scan_proxy_settings())
            res.extend(scan_alt_accounts(prog))
            res.extend(scan_deleted_evidence(prog))
            res.extend(scan_memory_strings(prog))
            res.extend(scan_loaded_modules(prog))
            return res
        self.mc_tab = ScanTab(self.notebook, mc_scan_func, "🧩 Minecraft Scanner", supports_parallel=True)
        self.notebook.add(self.mc_tab, text="🧩 ماينكرافت")

        # System Integrity
        self.integrity_tab = IntegrityTab(self.notebook, self)
        self.notebook.add(self.integrity_tab, text="🛡️ سلامة النظام")

        # Sandbox
        self.sandbox_tab = SandboxTab(self.notebook, self)
        self.notebook.add(self.sandbox_tab, text="🧪 Sandbox")

        # Forensic
        self.forensic_tab = ForensicTab(self.notebook, self)
        self.notebook.add(self.forensic_tab, text="🕵️ Forensic")

        # LAN Scanner
        self.lan_tab = LANTab(self.notebook, self)
        self.notebook.add(self.lan_tab, text="📡 LAN")

        # YARA Updater
        self.yara_tab = YARAUpdateTab(self.notebook, self)
        self.notebook.add(self.yara_tab, text="🔄 YARA")

        # Behavioral
        self.behavioral_tab = BehavioralTab(self.notebook, self)
        self.notebook.add(self.behavioral_tab, text="📸 التغييرات")

        # History
        self.history_tab = HistoryTab(self.notebook, self)
        self.notebook.add(self.history_tab, text="📜 History")

        credit_frame = ttk.Frame(self)
        credit_frame.pack(side="bottom", fill="x", pady=5)
        ttk.Label(credit_frame, text="🛡️ صنع بواسطة sh3la | تم تطويره بواسطة Rlue",
                  font=("Segoe UI", 8), foreground="gray").pack()

        self.all_results = []

    def get_targets(self):
        home = os.path.expanduser("~")
        return [
            os.path.join(home, "Downloads"),
            os.path.join(home, "Desktop"),
            os.path.expandvars(r"%APPDATA%"),
            os.path.expandvars(r"%LOCALAPPDATA%"),
        ]

    def toggle_dark_mode(self):
        self.dark_mode = not self.dark_mode
        if self.dark_mode:
            bg = self.dark_bg
            fg = self.dark_fg
            self.style.theme_use("default")
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("Treeview", background="#3c3f41", foreground="white", fieldbackground="#3c3f41")
            self.style.configure("Treeview.Heading", background="#555", foreground="white")
        else:
            bg = self.light_bg
            fg = self.light_fg
            self.style.theme_use("clam")
            self.style.configure("TFrame", background=bg)
            self.style.configure("TLabel", background=bg, foreground=fg)
            self.style.configure("Treeview", background="white", foreground="black", fieldbackground="white")
            self.style.configure("Treeview.Heading", background="#eee", foreground="black")
        self.configure(bg=bg)

    def run_full_scan(self):
        self.general_tab.start_scan()
        def check():
            if not self.general_tab.scanning:
                self.all_results = self.general_tab.results
                self.dashboard.update_stats(self.all_results)
                self.history_tab.add_entry(self.all_results, "General Scan")
                return
            self.after(500, check)
        self.after(500, check)

    def run_quick_scan(self):
        if self.general_tab.scanning:
            messagebox.showwarning("Busy", "الفحص جارٍ بالفعل.")
            return
        self.general_tab.scanning = True
        self.general_tab.stop_flag.clear()
        self.general_tab.scan_btn.config(state="disabled")
        self.general_tab.stop_btn.config(state="normal")
        self.general_tab.results = []
        self.general_tab.tree.delete(*self.general_tab.tree.get_children())
        self.general_tab.progress.start()
        self.general_tab.status_var.set("جاري الفحص السريع...")
        self.general_tab.summary_var.set("⏳")
        def task():
            targets = self.get_targets()
            res = quick_scan_files(targets, progress_callback=lambda c, t, m: self.general_tab.q.put(("progress", int((c/t)*100) if t else 0)))
            self.general_tab.q.put(("done", res))
        thread = threading.Thread(target=task, daemon=True)
        thread.start()
        def check():
            if not self.general_tab.scanning:
                self.all_results = self.general_tab.results
                self.dashboard.update_stats(self.all_results)
                self.history_tab.add_entry(self.all_results, "Quick Scan")
                return
            self.after(500, check)
        self.after(500, check)

    def run_minecraft_scan(self):
        self.mc_tab.start_scan()
        def check():
            if not self.mc_tab.scanning:
                self.all_results = self.mc_tab.results
                self.dashboard.update_stats(self.all_results)
                self.history_tab.add_entry(self.all_results, "Minecraft Scan")
                return
            self.after(500, check)
        self.after(500, check)

    def show_results_in_new_tab(self, results, tab_name):
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text=tab_name[:20])
        tree = ttk.Treeview(tab, columns=("severity", "score", "category", "name", "path", "reasons"), show="headings")
        for col, w, title in zip(("severity", "score", "category", "name", "path", "reasons"),
                                 [70,70,130,180,360,320],
                                 ["Risk", "Score%", "Category", "Name", "Path", "Reasons"]):
            tree.heading(col, text=title)
            tree.column(col, width=w, anchor="w")
        tree.pack(fill="both", expand=True)
        for idx, item in enumerate(results):
            tree.insert("", "end", iid=str(idx),
                        values=(item.get("severity"), f"{item.get('score',0)}%",
                                item.get("category"), item.get("name"),
                                item.get("path"), " | ".join(item.get("reasons", []))))


if __name__ == "__main__":
    app = App()
    app.mainloop()