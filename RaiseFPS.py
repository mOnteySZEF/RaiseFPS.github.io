import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import requests
from io import BytesIO
import LowMode
import MediumMode
import ProMode
import backup

def optimize(level):
    if level == "low":
        LowMode.optimize_low()
        messagebox.showinfo("Optymalizacja", "Optymalizacja LOW zakończona pomyślnie!")
    elif level == "medium":
        MediumMode.optimize_medium()
        messagebox.showinfo("Optymalizacja", "Optymalizacja MEDIUM zakończona pomyślnie!")
    elif level == "pro":
        ProMode.optimize_pro()
        messagebox.showinfo("Optymalizacja", "Optymalizacja PRO zakończona pomyślnie!")
    elif level == "backup":
        backup.backup("Punkt przywracania wykonany przez RaiseFPS")
        messagebox.showinfo("Backup", "Backup wykonano pomyślnie!")

def create_gui():
    root = tk.Tk()
    root.title("RaiseFPS")
    root.geometry("480x600")
    root.configure(bg="#012025")
    root.resizable(False, False)

    bg_color = "#012025"        # ciemne tło
    low_color = "#FFDC57"       # zieleń
    medium_color = "#7EDA53"    # żółty
    pro_color = "#FF5558"      # czerwony
    backup_color = "#2D2D2D"    # ciemnoszary

    image_url = 'https://i.fmfile.com/I3L9suyZSKkKsLtt1FUmd/RaiseFPS.png'
    response = requests.get(image_url)
    img_data = BytesIO(response.content)
    img = Image.open(img_data)
    img = img.resize((150, 125))
    logo_image = ImageTk.PhotoImage(img)

    header_frame = tk.Frame(root, bg=bg_color)
    header_frame.pack(fill=tk.X, pady=(10, 0))

    logo_label = tk.Label(
        header_frame, 
        image=logo_image,
        bg=bg_color
    )
    logo_label.image = logo_image
    logo_label.pack(pady=(20, 0))

    subtitle_label = tk.Label(
        root,
        text="GAMING MODE!",
        font=("Poppins", 18, "bold"),
        fg="white",
        bg=bg_color
    )
    subtitle_label.pack(pady=(0, 20))
    
    button_frame = tk.Frame(root, bg=bg_color)
    button_frame.pack(pady=5)

    def create_button(text, color, command, font_size=16, btn_padx=60, btn_pady=15):
        button = tk.Button(
            button_frame, 
            text=text,
            command=command,
            bg=color, 
            fg="black",
            activebackground=color,
            activeforeground="white",
            font=("Verdana", font_size, "bold"),
            padx=btn_padx, 
            pady=btn_pady,
            bd=0, 
            relief="flat",
            highlightthickness=0,
            cursor="hand2"
        )
        return button

    low_button = create_button("Low", low_color, lambda: optimize("low"))
    medium_button = create_button("Medium", medium_color, lambda: optimize("medium"))
    pro_button = create_button("Pro", pro_color, lambda: optimize("pro"))
    backup_button = create_button("Zrób punkt przywracania", backup_color, lambda: optimize("backup"), font_size=10, btn_padx=30, btn_pady=12)

    low_button.pack(pady=10, fill=tk.X, padx=50)
    medium_button.pack(pady=10, fill=tk.X, padx=50)
    pro_button.pack(pady=10, fill=tk.X, padx=50)
    backup_button.pack(pady=10, fill=tk.X, padx=10)

    footer_label = tk.Label(
        root,
        text="© 2025 RaiseFPS",
        font=("Poppins", 10),
        bg=bg_color,
        fg="#636e72"
    )
    footer_label.pack(side=tk.BOTTOM, pady=15)

    root.mainloop()

if __name__ == "__main__":
    create_gui()