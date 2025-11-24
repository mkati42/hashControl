
import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import base64
from io import BytesIO
from PIL import Image, ImageTk

def calculate_hash(text, algorithm):
    try:
        if algorithm == 'MD5':
            return hashlib.md5(text.encode()).hexdigest()
        elif algorithm == 'SHA1':
            return hashlib.sha1(text.encode()).hexdigest()
        elif algorithm == 'SHA256':
            return hashlib.sha256(text.encode()).hexdigest()
        elif algorithm == 'SHA512':
            return hashlib.sha512(text.encode()).hexdigest()
        else:
            return 'Unsupported algorithm'
    except Exception as e:
        return f'Error: {e}'

class HashApp(tk.Tk):

    def __init__(self):
        super().__init__()
        self.title('Hash Otomasyon')
        self.geometry('1280x720')
        self.resizable(True, True)

        # Renkler: görseldeki gibi koyu arka plan ve beyaz-açık metinler
        bg_color = '#101014'  # çok koyu gri/siyah
        fg_color = '#ffffff'  # beyaz
        accent_color = '#bdbdbd'  # açık gri
        button_color = '#22223a'  # koyu morumsu
        button_fg = '#ffffff'
        entry_bg = '#232336'
        entry_fg = '#ffffff'

        self.configure(bg=bg_color)


        # Görseli dosya yolundan yükle (örn: banner.png)
        try:
            image = Image.open('banner.png')
            self.logo_img = ImageTk.PhotoImage(image)
            self.logo_label = tk.Label(self, image=self.logo_img, bg=bg_color)
            self.logo_label.pack(pady=(30, 10))
        except Exception as e:
            self.logo_label = tk.Label(self, text='[Görsel Yüklenemedi]', fg=fg_color, bg=bg_color)
            self.logo_label.pack(pady=(30, 10))

        # Başlık yazısı kaldırıldı (görselde mevcut)

        self.label = tk.Label(self, text='Metin Girin:', font=('Montserrat', 16), fg=accent_color, bg=bg_color)
        self.label.pack(pady=10)

        self.text_entry = tk.Entry(self, width=100, font=('Montserrat', 14), bg=entry_bg, fg=entry_fg, insertbackground=entry_fg, relief='flat', highlightthickness=1, highlightbackground=accent_color)
        self.text_entry.pack(pady=5)

        self.alg_label = tk.Label(self, text='Algoritma Seçin:', font=('Montserrat', 16), fg=accent_color, bg=bg_color)
        self.alg_label.pack(pady=10)

        self.algorithm = tk.StringVar(value='MD5')
        self.alg_combo = ttk.Combobox(self, textvariable=self.algorithm, values=['MD5', 'SHA1', 'SHA256', 'SHA512'], state='readonly', font=('Montserrat', 14))
        self.alg_combo.pack(pady=5)

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Montserrat', 14, 'bold'), background=button_color, foreground=button_fg)
        style.map('TButton', background=[('active', '#39396a')])
        style.configure('TCombobox', fieldbackground=entry_bg, background=entry_bg, foreground=entry_fg)

        self.hash_button = ttk.Button(self, text='Hash Hesapla', command=self.hash_text)
        self.hash_button.pack(pady=10)

        self.result_label = tk.Label(self, text='Sonuç:', font=('Montserrat', 16), fg=accent_color, bg=bg_color)
        self.result_label.pack(pady=5)

        self.result_text = tk.Text(self, height=10, width=100, font=('Consolas', 13), bg=entry_bg, fg=entry_fg, relief='flat', highlightthickness=1, highlightbackground=accent_color)
        self.result_text.pack(pady=5, expand=True, fill='both')
        self.result_text.config(state='disabled')

    def hash_text(self):
        text = self.text_entry.get()
        algorithm = self.algorithm.get()
        if not text:
            messagebox.showwarning('Uyarı', 'Lütfen bir metin girin!')
            return
        result = calculate_hash(text, algorithm)
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = HashApp()
    app.mainloop()