import tkinter as tk
from tkinter import messagebox, ttk
from PIL import Image, ImageTk
import threading
import time
import requests
from io import BytesIO
import LowMode
import MediumMode
import ProMode
import backup
import socket
import sys
import ctypes
import os
import win32com.client
import subprocess
from datetime import datetime


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if sys.platform == 'win32':
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        print("Nie obsługiwano")
    sys.exit()

if not is_admin():
    run_as_admin()

image_url = 'https://i.fmfile.com/I3L9suyZSKkKsLtt1FUmd/RaiseFPS.png'
DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/1358464113747165441/a_YTOXS1D1688vmIAyyKUvmTsXD0VW14i3x1HtMbZbg_Pg5Be1Ib5A5baORa7Zh7E4mx"

def send_discord_log(username, action):
    hostname = socket.gethostname()
    timestamp = datetime.now().strftime("%H:%M:%S %d-%m-%Y")

    payload = {
        "embeds": [{
            "title": "Logi RaiseFPS",
            "color": 0x00ff00,
            "thumbnail": {
                "url": image_url
            },
            "fields": [
                {"name": "Komputer:", "value": hostname, "inline": False},
                {"name": "Akcja:", "value": action, "inline": False},
                {"name": "Użytkownik:", "value": username, "inline": False},
                {"name": "Data i godzina:", "value": timestamp, "inline": False}
            ],
        }]
    }

    try:
        response = requests.post(DISCORD_WEBHOOK_URL, json=payload)
        if response.status_code != 204:
            print(f"Błąd podczas wysyłania logów na Discord: {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"Błąd podczas wysyłania logów na Discord: {e}")

def get_login_data():
    try:
        response = requests.get("http://fazerp.eu/databaseRaiseFPS.json")
        if response.status_code == 200:
            return response.json()
        else:
            messagebox.showerror("Błąd", "Nie udało się pobrać danych logowania.")
            return None
    except requests.exceptions.RequestException as e:
        messagebox.showerror("Błąd", f"Problem z połączeniem: {e}")
        return None

def login():
    username = username_entry.get()
    password = password_entry.get()

    login_data = get_login_data()

    if login_data is None:
        return
    
    if username in login_data and login_data[username] == password:
        messagebox.showinfo("Login", "Zalogowano pomyślnie!")
        send_discord_log(username, "Zalogowano jako użytkownik")
        login_window.destroy()
        create_gui(user_type="registered")
    else:
        messagebox.showerror("Błąd", "Błędny login lub hasło.")

def login_guest():
    username = "Gość"  # Gość nie ma loginu
    messagebox.showinfo("Login", "Zalogowano jako gość!")
    send_discord_log(username, "Zalogowano jako gość")
    login_window.destroy()
    create_gui(user_type="guest")

def create_shortcut(target, shortcut_name):
    taskbar_path = os.path.join(os.environ['APPDATA'], r'Microsoft\Internet Explorer\Quick Launch\User Pinned\TaskBar')
    shortcut_path = os.path.join(taskbar_path, f"{shortcut_name}.lnk")
    
    shell = win32com.client.Dispatch('WScript.Shell')
    shortcut = shell.CreateShortcut(shortcut_path)
    
    shortcut.TargetPath = target
    shortcut.WorkingDirectory = os.path.dirname(target)
    shortcut.IconLocation = target
    shortcut.save()

    return shortcut_path

def pin_to_taskbar(shortcut_path):
    pin_command = f"$shell = New-Object -ComObject Shell.Application; $folder = $shell.Namespace('{os.path.dirname(shortcut_path)}'); $item = $folder.Items().Item('{os.path.basename(shortcut_path)}'); $item.InvokeVerb('Pin to Taskbar')"
    subprocess.run(["powershell", "-ExecutionPolicy", "Bypass", "-Command", pin_command])

def create_login_window():
    global login_window, username_entry, password_entry

    login_window = tk.Tk()
    login_window.title("Login")
    login_window.geometry("380x550")
    login_window.configure(bg="#012025")
    login_window.resizable(False, False)
    bg_color = "#012025"

    response = requests.get(image_url)
    img_data = BytesIO(response.content)
    img = Image.open(img_data)
    img = img.resize((125, 100))
    logo_image = ImageTk.PhotoImage(img)
    header_frame = tk.Frame(login_window, bg=bg_color)
    header_frame.pack(fill=tk.X, pady=(5, 0))

    logo_label = tk.Label(header_frame, image=logo_image, bg=bg_color)
    logo_label.image = logo_image
    logo_label.pack(pady=(20, 0))

    tk.Label(
        login_window,
        text="Login:",
        font=("Verdana", 14),
        fg="white",
        bg=bg_color
    ).pack(pady=(20, 10))

    username_entry = tk.Entry(
        login_window,
        font=("Verdana", 14),
        bg="#2C3E50",
        fg="white",
        relief="flat",
        width=25
    )
    username_entry.pack(pady=(10, 20))

    tk.Label(
        login_window,
        text="Hasło:",
        font=("Verdana", 14),
        fg="white",
        bg=bg_color
    ).pack(pady=(10, 10))

    password_entry = tk.Entry(
        login_window,
        font=("Verdana", 14),
        bg="#2C3E50",
        fg="white",
        relief="flat",
        width=25,
        show="*"
    )
    password_entry.pack(pady=(10, 20))

    login_button = tk.Button(
        login_window,
        text="Zaloguj",
        command=login,
        bg="#FFDC57",
        fg="black",
        activebackground="#FFDC57",
        activeforeground="white",
        font=("Verdana", 14, "bold"),
        relief="flat",
        padx=40,
        pady=10
    )
    login_button.pack(pady=(20, 10))

    guest_button = tk.Button(
        login_window,
        text="Zaloguj jako gość",
        command=login_guest,
        bg="#305afc",
        fg="black",
        activebackground="#201afc",
        activeforeground="white",
        font=("Verdana", 14, "bold"),
        relief="flat",
        padx=40,
        pady=10
    )
    guest_button.pack(pady=(10, 20))

    login_window.mainloop()


stop_loading_flag = False

def show_loading(level, callback):
    global stop_loading_flag
    stop_loading_flag = False

    loading_window = tk.Toplevel()
    loading_window.title("Optymalizacja...")
    loading_window.geometry("360x160")
    loading_window.configure(bg="#012025")
    loading_window.resizable(False, False)

    label = tk.Label(
        loading_window,
        text="Rozpoczynanie optymalizacji...",
        font=("Verdana", 12, "bold"),
        fg="white",
        bg="#012025"
    )
    label.pack(pady=(20, 10))

    progress = ttk.Progressbar(
        loading_window,
        orient="horizontal",
        length=250,
        mode="determinate",
        style="Custom.Horizontal.TProgressbar"
    )
    progress.pack(pady=(0, 10))

    style = ttk.Style()
    style.theme_use("default")
    style.configure(
        "Custom.Horizontal.TProgressbar",
        troughcolor="#2C3E50",
        background="#1ABC9C",
        thickness=20,
        bordercolor="#000000"
    )

    loading_texts = ["Optymalizacja...", "Wczytywanie plików...", "Przyspieszanie gry...", "Finalizowanie..."]

    def update_animation():
        for i in range(101):
            if stop_loading_flag:
                loading_window.destroy() 
                return
            
            progress["value"] = i 
            if i % 25 == 0 and i // 25 < len(loading_texts):
                label.config(text=loading_texts[i // 25])

            loading_window.update_idletasks()

            time.sleep(0.1)

        loading_window.destroy()
        callback()

    threading.Thread(target=update_animation, daemon=True).start()

def stop_loading():
    global stop_loading_flag
    stop_loading_flag = True

def optimize(level):
    if level == "low":
        LowMode.optimize_low()
    elif level == "medium":
        MediumMode.optimize_medium()
    elif level == "pro":
        ProMode.optimize_pro()
    elif level == "backup":
        backup.backup("Punkt przywracania wykonany przez RaiseFPS")

    def do_optimization():
        if level == "low":
            messagebox.showinfo("RaiseFPS", "Optymalizacja LOW zakończona pomyślnie!")
        elif level == "medium":
            messagebox.showinfo("RaiseFPS", "Optymalizacja MEDIUM zakończona pomyślnie!")
        elif level == "pro":
            messagebox.showinfo("RaiseFPS", "Optymalizacja PRO zakończona pomyślnie!")

    show_loading(level, do_optimization)


def create_gui(user_type):
    root = tk.Tk()
    root.title("RaiseFPS")
    root.geometry("480x600")
    root.configure(bg="#012025")
    root.resizable(False, False)

    bg_color = "#012025"        # ciemne tło
    low_color = "#FFDC57"       # zieleń
    medium_color = "#7EDA53"    # żółty
    pro_color = "#FF5558"      # czerwony
    backup_color = "#305afc"    # ciemnoszary

    response = requests.get(image_url)
    img_data = BytesIO(response.content)
    img = Image.open(img_data)
    img = img.resize((150, 125))
    logo_image = ImageTk.PhotoImage(img)

    header_frame = tk.Frame(root, bg=bg_color)
    header_frame.pack(fill=tk.X, pady=(10, 0))

    logo_label = tk.Label(header_frame, image=logo_image, bg=bg_color)
    logo_label.image = logo_image
    logo_label.pack(pady=(20, 0))

    canvas = tk.Canvas(root, width=400, height=60, bg=bg_color, highlightthickness=0)
    canvas.pack()

    text = "GAMING MODE!"
    font = ("Arial Black", 18, "bold")

    for dx, dy in [(-4, 0), (4, 0), (0, -4), (0, 4), (-4, -4), (-4, 4), (4, -4), (4, 4)]:
        canvas.create_text(200+dx, 10+dy, text=text, font=font, fill="black")

    canvas.create_text(200, 10, text=text, font=font, fill="white")
    
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=0)

    def darken_color(hex_color, factor=0.8):
        hex_color = hex_color.lstrip('#')
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
        darkened = tuple(int(c * factor) for c in rgb)
        return '#%02x%02x%02x' % darkened

    def create_button(text, color, command, font_size=16, btn_padx=60, btn_pady=15, text_color="black", state="normal"):
        button = tk.Button(
            button_frame, 
            text=text,
            command=command,
            bg=color, 
            fg=text_color,
            activebackground=color,
            activeforeground="white",
            font=("Verdana", font_size, "bold"),
            padx=btn_padx,
            pady=btn_pady,
            bd=0,
            relief="flat",
            highlightthickness=0,
            cursor="hand2",
            state=state
        )

        def on_enter(e):
            if not state == "disabled":
                button['bg'] = darken_color(color, 0.4) 
                button['fg'] = "white"

        def on_leave(e):
            if not state == "disabled":
                button['bg'] = color
                button['fg'] = text_color

        def on_disabled():
            button['bg'] = "#BDC3C7"
            button['fg'] = "#7F8C8D"

        if state == "disabled":
            on_disabled()

        button.bind("<Enter>", on_enter)
        button.bind("<Leave>", on_leave)
        return button

    low_button = create_button("Low", low_color, lambda: optimize("low"))
    medium_button = create_button("Medium", medium_color, lambda: optimize("medium"), state="disabled" if user_type == "guest" else "normal")
    pro_button = create_button("Pro", pro_color, lambda: optimize("pro"), state="disabled" if user_type == "guest" else "normal")
    backup_button = create_button("Zrób punkt przywracania", backup_color, lambda: optimize("backup"), font_size=10, btn_padx=30, btn_pady=12, text_color="white")

    low_button.pack(pady=10, fill=tk.X, padx=50)
    medium_button.pack(pady=10, fill=tk.X, padx=50)
    pro_button.pack(pady=10, fill=tk.X, padx=50)
    backup_button.pack(pady=10, fill=tk.X, padx=10)
    backup_button.config(fg='white', height=1)

    footer_label = tk.Label(
        root,
        text="© 2025 RaiseFPS",
        font=("Verdana", 10),
        bg=bg_color,
        fg="#636e72"
    )
    footer_label.pack(side=tk.BOTTOM, pady=15)
    root.mainloop()


if __name__ == "__main__":
    create_login_window()
    target_app = os.path.abspath(sys.argv[0])
    shortcut_name = os.path.splitext(os.path.basename(target_app))[0]
    shortcut_path = create_shortcut(target_app, shortcut_name)
    pin_to_taskbar(shortcut_path)
