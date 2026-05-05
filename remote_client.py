"""
Remote Desktop Client – Safe Scanner Ultimate
يُشغّل على جهاز المشاهد، يدخل الكود، يتصل، يشاهد ويتحكم.
"""
import socket
import struct
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import io
from PIL import Image, ImageTk

PORT = 9999

class RemoteClient:
    def __init__(self):
        self.socket = None
        self.connected = False
        self.streaming = False
        self.photo = None
        self.create_gui()

    def create_gui(self):
        self.win = tk.Tk()
        self.win.title("Remote Client – Safe Scanner")
        self.win.geometry("900x650")

        # شريط الاتصال
        top = ttk.Frame(self.win, padding=10)
        top.pack(fill='x')
        ttk.Label(top, text="🔴 Remote Desktop Client", font=("Segoe UI", 14, "bold")).pack(side='left')
        ttk.Label(top, text="كود الاتصال:").pack(side='left', padx=(40, 5))
        self.code_entry = ttk.Entry(top, width=15, font=("Consolas", 14))
        self.code_entry.pack(side='left', padx=5)
        self.connect_btn = ttk.Button(top, text="🔗 اتصال", command=self.connect)
        self.connect_btn.pack(side='left', padx=5)
        self.disconnect_btn = ttk.Button(top, text="❌ إنهاء", command=self.disconnect, state='disabled')
        self.disconnect_btn.pack(side='left', padx=5)
        self.status_lbl = ttk.Label(top, text="جاهز للإدخال")
        self.status_lbl.pack(side='left', padx=10)

        # شاشة العرض
        self.canvas = tk.Canvas(self.win, bg='black', cursor='crosshair')
        self.canvas.pack(fill='both', expand=True)

        # ربط الأحداث
        self.canvas.bind('<Motion>', self.on_mouse_move)
        self.canvas.bind('<Button-1>', self.on_left_click)
        self.canvas.bind('<Button-3>', self.on_right_click)

        self.win.protocol("WM_DELETE_WINDOW", self.disconnect)
        self.win.mainloop()

    def connect(self):
        code = self.code_entry.get().strip()
        if len(code) != 6 or not code.isdigit():
            messagebox.showwarning("خطأ", "أدخل كوداً صحيحاً مكوناً من 6 أرقام.")
            return
        self.status_lbl.config(text="جاري الاتصال...")
        threading.Thread(target=self._connect, args=(code,), daemon=True).start()

    def _connect(self, code):
        try:
            self.socket = socket.create_connection(('localhost', PORT), timeout=10)
            self.socket.send(code.encode())
            response = self.socket.recv(20).decode()
            if response == "ACCEPTED":
                self.connected = True
                self.streaming = True
                self.win.after(0, self.on_connected)
                threading.Thread(target=self.receive_stream, daemon=True).start()
            elif response == "DECLINED":
                self.win.after(0, lambda: self.status_lbl.config(text="❌ تم الرفض من المضيف"))
                self.socket.close()
            else:
                self.win.after(0, lambda: self.status_lbl.config(text="❌ كود خاطئ"))
                self.socket.close()
        except Exception as e:
            self.win.after(0, lambda: self.status_lbl.config(text=f"❌ خطأ في الاتصال: {e}"))

    def on_connected(self):
        self.status_lbl.config(text="✅ متصل – يمكنك التحكم")
        self.connect_btn.config(state='disabled')
        self.disconnect_btn.config(state='normal')

    def receive_stream(self):
        while self.streaming and self.socket:
            try:
                # استقبال طول الصورة
                header = self.socket.recv(4)
                if len(header) < 4:
                    break
                msg_len = struct.unpack('>I', header)[0]
                data = b''
                while len(data) < msg_len:
                    packet = self.socket.recv(msg_len - len(data))
                    if not packet:
                        break
                    data += packet
                # عرض الصورة
                pil_img = Image.open(io.BytesIO(data))
                # تغيير الحجم ليتناسب مع Canvas
                canvas_w = self.canvas.winfo_width()
                canvas_h = self.canvas.winfo_height()
                if canvas_w > 10 and canvas_h > 10:
                    pil_img = pil_img.resize((canvas_w, canvas_h), Image.LANCZOS)
                self.photo = ImageTk.PhotoImage(pil_img)
                self.canvas.create_image(0, 0, anchor='nw', image=self.photo)
            except:
                break
        self.streaming = False

    def send_control(self, msg_type, x, y):
        """إرسال أمر تحكم."""
        if self.socket and self.connected:
            try:
                self.socket.sendall(struct.pack('>III', msg_type, x, y))
            except:
                pass

    def on_mouse_move(self, event):
        self.send_control(0, event.x, event.y)

    def on_left_click(self, event):
        self.send_control(1, event.x, event.y)

    def on_right_click(self, event):
        self.send_control(2, event.x, event.y)

    def disconnect(self):
        self.streaming = False
        self.connected = False
        if self.socket:
            try:
                self.send_control(9, 0, 0)
                self.socket.close()
            except:
                pass
        self.status_lbl.config(text="تم قطع الاتصال")
        self.connect_btn.config(state='normal')
        self.disconnect_btn.config(state='disabled')
        try:
            self.win.destroy()
        except:
            pass

if __name__ == "__main__":
    RemoteClient()