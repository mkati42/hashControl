


import tkinter as tk
from tkinter import ttk, messagebox
import requests
import re
import threading

VT_API_KEYS = [
    "461487a0683448178d99a1094a25b0bc334120197b9edb54666cffad112ece9c",
    "2ff08b30aa5de23a75845df7f9b6d816281fe330bfacf9950bd7d6159a8e2d7a",
    "a33edc2b32c06f5ccc957257e4aeb6b66be3edc47b4ce3192175e625ac54028e",
    "aa6aedff18fed16475d60c2f1f2443dbeffd9752d28e35b11e004dd88b134319"
]
current_vt_index = 0
HA_API_KEYS = [
    "gqdwy3c55ce9e708lxa2m0j73ed252a9oel1cy7u724f99d4x8h71xbh2d14ca1d",
    "1zzcm0lxab98a0b0b6nxqkw1cf43ec7cnjkcuplq3c922bd7e7mfahiw2d92f999"
]
current_ha_index = 0
ABUSEIPDB_API_KEYS = [
    "dba48d1552f55e1d6ec1d4b624cc6f3886d108502d8a2b8666bd54b4580af99d7c350895b855916a",
    "2bf205486adfc09e1dc27e216aa5c89ade0b81c07145f54a5921bb816682d6ebc7db6278ef88bc17"
]
current_abuse_index = 0

def vt_hash_lookup(h):
    global current_vt_index
    # Tüm anahtarları sırayla dene, biri başarılı olursa sonucu döndür
    global current_vt_index
    for i in range(len(VT_API_KEYS)):
        key = VT_API_KEYS[(current_vt_index + i) % len(VT_API_KEYS)]
        url = f"https://www.virustotal.com/api/v3/files/{h}"
        headers = {"x-apikey": key}
        try:
            r = requests.get(url, headers=headers)
            if r.status_code == 200:
                current_vt_index = (current_vt_index + i + 1) % len(VT_API_KEYS)
                data = r.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return stats
        except Exception as e:
            continue
    return {"error": "Tüm VirusTotal API anahtarları başarısız."}

def ha_hash_lookup(h):
    url = "https://www.hybrid-analysis.com/api/v2/search/hash"
    h = h.strip()
    if not h:
        return {"info": "Hybrid Analysis API için boş hash değeri gönderilemez."}
    # Hash türünü otomatik tespit et
    hash_type = None
    if re.fullmatch(r"[a-fA-F0-9]{32}", h):
        hash_type = "md5"
    elif re.fullmatch(r"[a-fA-F0-9]{40}", h):
        hash_type = "sha1"
    elif re.fullmatch(r"[a-fA-F0-9]{64}", h):
        hash_type = "sha256"
    elif re.fullmatch(r"[a-fA-F0-9]{128}", h):
        hash_type = "sha512"
    else:
        return {"info": "Geçersiz hash formatı. MD5, SHA1, SHA256 veya SHA512 olmalı."}
    global current_ha_index
    for i in range(len(HA_API_KEYS)):
        key = HA_API_KEYS[(current_ha_index + i) % len(HA_API_KEYS)]
        headers = {
            "api-key": key,
            "user-agent": "Falcon Sandbox",
            "Accept": "application/json"
        }
        params = {"hash": h}
        try:
            r = requests.get(url, headers=headers, params=params)
            if r.status_code == 200:
                current_ha_index = (current_ha_index + i + 1) % len(HA_API_KEYS)
                data = r.json()
                if len(data) == 0:
                    return {"verdict": "bulunamadı"}
                return {"verdict": data[0].get("verdict", "unknown"), "score": data[0].get("threat_score", 0)}
            else:
                # Hata durumunda ham cevabı da döndür
                return {"error": f"HA hata: {r.status_code}", "response": r.text}
        except Exception as e:
            continue
    return {"error": "Tüm Hybrid Analysis API anahtarları başarısız."}

def abuse_lookup(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": "90"}
    global current_abuse_index
    for i in range(len(ABUSEIPDB_API_KEYS)):
        key = ABUSEIPDB_API_KEYS[(current_abuse_index + i) % len(ABUSEIPDB_API_KEYS)]
        headers = {"Key": key, "Accept": "application/json"}
        try:
            r = requests.get(url, headers=headers, params=params)
            if r.status_code == 200:
                current_abuse_index = (current_abuse_index + i + 1) % len(ABUSEIPDB_API_KEYS)
                data = r.json().get("data", {})
                return {"abuseScore": data.get("abuseConfidenceScore"), "totalReports": data.get("totalReports"), "country": data.get("countryCode")}
        except Exception as e:
            continue
    return {"error": "Tüm AbuseIPDB API anahtarları başarısız."}

def analyze_entry(entry):
    results = []
    items = [x.strip() for x in entry.split(',')]
    for item in items:
        item = item.strip()
        if not item:
            continue
        if re.match(r"^\d+\.\d+\.\d+\.\d+$", item):
            results.append(f"\n🌐 IP inceleniyor: {item}\nAbuseIPDB: {abuse_lookup(item)}\n")
        else:
            vt = vt_hash_lookup(item)
            ha = ha_hash_lookup(item)
            results.append(f"\n🔍 Hash inceleniyor: {item}\nVirusTotal: {vt}\nHybridAnalysis: {ha}\n")
    return '\n---\n'.join(results)

class SuperSearchApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('SUPER SEARCH - SUPERNOVA')
        self.geometry('900x600')
        self.configure(bg='#101014')

        banner = (
            '  ____  _   _ ____    ____  _____ _____ ____  \n'
            '/ ___|| | | |  _ \\  / ___|| ____|_   _|  _ \\ \n'
            '\\___ \\| | | | | | | \\___ \\|  _|   | | | | | |\n'
            '  ___) | |_| | |_| |  ___) | |___  | | | |_| |\n'
            '|____/ \\___/|____/  |____/|_____| |_| |____/\n'
            '\n                SUPERNOVA\n                gururla sunar\n'
        )
        self.banner_label = tk.Label(self, text=banner, font=('Consolas', 12, 'bold'), fg='#00e6e6', bg='#101014', justify='left')
        self.banner_label.pack(pady=(20, 10))

        self.input_label = tk.Label(self, text='Hash veya IP girin (virgülle ayırabilirsiniz):', font=('Montserrat', 14), fg='#bdbdbd', bg='#101014')
        self.input_label.pack(pady=(10, 0))

        self.input_entry = tk.Entry(self, width=80, font=('Consolas', 13), bg='#232336', fg='#ffffff', insertbackground='#ffffff', relief='flat', highlightthickness=1, highlightbackground='#bdbdbd')
        self.input_entry.pack(pady=10)

        self.search_button = ttk.Button(self, text='Sorgula', command=self.start_search)
        self.search_button.pack(pady=10)

        self.result_text = tk.Text(self, height=18, width=100, font=('Consolas', 12), bg='#232336', fg='#ffffff', relief='flat', highlightthickness=1, highlightbackground='#bdbdbd')
        self.result_text.pack(pady=10, expand=True, fill='both')
        self.result_text.config(state='disabled')

    def start_search(self):
        entry = self.input_entry.get()
        if not entry:
            messagebox.showwarning('Uyarı', 'Lütfen bir hash veya IP girin!')
            return
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, 'Sorgulanıyor, lütfen bekleyin...')
        self.result_text.config(state='disabled')
        threading.Thread(target=self.run_search, args=(entry,), daemon=True).start()

    def run_search(self, entry):
        result = analyze_entry(entry)
        self.result_text.config(state='normal')
        self.result_text.delete('1.0', tk.END)
        self.result_text.insert(tk.END, result)
        self.result_text.config(state='disabled')

if __name__ == '__main__':
    app = SuperSearchApp()
    app.mainloop()