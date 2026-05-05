"""
Remote Desktop Server – Safe Scanner Ultimate
يُشغّل على جهاز المستضيف، يولّد كود، يستقبل اتصال، يسمح بمشاركة الشاشة والتحكم.
"""
import socket
import threading
import struct
import random
import tkinter as tk
from tkinter import messagebox
import io
import mss
import pyautogui
from PIL import Image

# ---------- إعدادات ----------
PORT = 9999
BUFFER_SIZE = 65536
CODE_LENGTH = 6

# ---------- إنشاء كود عشوائي ----------
def generate_code():
    return ''.join(str(random.randint(0, 9)) for _ in range(CODE_LENGTH))

# ---------- نافذة قبول/رفض الاتصال ----------
class AcceptWindow:
    def __init__(self, client_name, callback):
        self.callback = callback
        self.win = tk.Tk()
        self.win.title("طلب اتصال")
        self.win.geometry("350x150")
        self.win.resizable(False, False)
        tk.Label(self.win, text=f"هل تسمح لـ '{client_name}' بالاتصال بجهازك؟",
                 font=("Segoe UI", 11), wraplength=300).pack(pady=15)
        frame = tk.Frame(self.win)
        frame.pack()
        tk.Button(frame, text="✅ نعم", bg="green", fg="white", width=10,
                  command=lambda: self.answer(True)).pack(side='left', padx=10)
        tk.Button(frame, text="❌ لا", bg="red", fg="white", width=10,
                  command=lambda: self.answer(False)).pack(side='left', padx=10)
        self.win.protocol("WM_DELETE_WINDOW", lambda: self.answer(False))
        self.win.mainloop()

    def answer(self, accepted):
        self.win.destroy()
        self.callback(accepted)

# ---------- السيرفر الرئيسي ----------
class RemoteServer:
    def __init__(self):
        self.code = generate_code()
        self.server_socket = None
        self.client_socket = None
        self.running = False
        self.streaming = False

    def show_code_window(self):
        """نافذة تعرض الكود وحالة الانتظار."""
        self.code_win = tk.Tk()
        self.code_win.title("Remote Server – Safe Scanner")
        self.code_win.geometry("400x250")
        self.code_win.resizable(False, False)
        tk.Label(self.code_win, text="🔴 Remote Desktop Server",
                 font=("Segoe UI", 14, "bold")).pack(pady=10)
        tk.Label(self.code_win, text="رمز الاتصال:", font=("Segoe UI", 11)).pack()
        self.code_label = tk.Label(self.code_win, text=self.code, font=("Consolas", 28, "bold"), fg="blue")
        self.code_label.pack(pady=5)
        self.status_label = tk.Label(self.code_win, text="⏳ في انتظار اتصال...", font=("Segoe UI", 10))
        self.status_label.pack(pady=10)
        tk.Button(self.code_win, text="❌ إغلاق", command=self.shutdown, bg="red", fg="white").pack()
        threading.Thread(target=self.start_listening, daemon=True).start()
        self.code_win.protocol("WM_DELETE_WINDOW", self.shutdown)
        self.code_win.mainloop()

    def start_listening(self):
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', PORT))
        self.server_socket.listen(1)
        self.server_socket.settimeout(3)
        while self.running:
            try:
                client, addr = self.server_socket.accept()
                # استقبال الكود المُرسل من العميل
                data = client.recv(10).decode().strip()
                if data == self.code:
                    # طلب قبول المستخدم
                    client_name = f"{addr[0]}"
                    accepted = threading.Event()
                    def callback(result):
                        self._accepted = result
                        accepted.set()
                    self.code_win.after(0, lambda: self.ask_accept(client_name, client))
                else:
                    client.send(b"WRONG_CODE")
                    client.close()
            except socket.timeout:
                continue
            except:
                break

    def ask_accept(self, client_name, client_socket):
        self.client_socket = client_socket
        win = tk.Toplevel(self.code_win)
        win.title("طلب اتصال")
        win.geometry("350x150")
        win.resizable(False, False)
        tk.Label(win, text=f"هل تسمح لـ '{client_name}' بالاتصال؟",
                 font=("Segoe UI", 11)).pack(pady=15)
        frame = tk.Frame(win)
        frame.pack()
        def accept():
            win.destroy()
            self.client_socket.send(b"ACCEPTED")
            self.status_label.config(text="✅ متصل – جاري بث الشاشة...")
            threading.Thread(target=self.stream_screen, daemon=True).start()
            threading.Thread(target=self.receive_control, daemon=True).start()
        def decline():
            win.destroy()
            self.client_socket.send(b"DECLINED")
            self.client_socket.close()
            self.client_socket = None
        tk.Button(frame, text="✅ نعم", bg="green", fg="white", width=10,
                  command=accept).pack(side='left', padx=10)
        tk.Button(frame, text="❌ لا", bg="red", fg="white", width=10,
                  command=decline).pack(side='left', padx=10)

    def stream_screen(self):
        self.streaming = True
        with mss.mss() as sct:
            while self.streaming and self.client_socket:
                try:
                    # التقاط الشاشة
                    monitor = sct.monitors[1]  # الشاشة الأساسية
                    img = sct.grab(monitor)
                    pil_img = Image.frombytes("RGB", img.size, img.bgra, "raw", "BGRX")
                    # ضغط JPEG
                    buf = io.BytesIO()
                    pil_img.save(buf, format='JPEG', quality=50)
                    data = buf.getvalue()
                    # إرسال الطول ثم الصورة
                    try:
                        self.client_socket.sendall(struct.pack('>I', len(data)) + data)
                    except:
                        break
                except:
                    break
        self.streaming = False

    def receive_control(self):
        """استقبال أوامر التحكم (إحداثيات الماوس، نقرات، ضغطات مفاتيح)."""
        while self.streaming and self.client_socket:
            try:
                header = self.client_socket.recv(12)
                if len(header) < 12:
                    break
                msg_type, x, y = struct.unpack('>III', header)
                if msg_type == 0:  # Mouse move
                    pyautogui.moveTo(x, y, _pause=False)
                elif msg_type == 1:  # Left click
                    pyautogui.click(x, y, _pause=False)
                elif msg_type == 2:  # Right click
                    pyautogui.click(x, y, button='right', _pause=False)
                elif msg_type == 3:  # Key press
                    try:
                        key = self.client_socket.recv(4).decode()
                        pyautogui.press(key)
                    except:
                        pass
                elif msg_type == 9:  # إنهاء
                    break
            except:
                break

    def shutdown(self):
        self.running = False
        self.streaming = False
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        if hasattr(self, 'code_win'):
            try:
                self.code_win.destroy()
            except:
                pass

# ---------- تشغيل ----------
if __name__ == "__main__":
    server = RemoteServer()
    server.show_code_window()