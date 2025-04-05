import tkinter as tk
from tkinter import messagebox
import os
import shutil
from io import BytesIO

def clear_temp_files():
    temp_dir = os.path.join(os.getenv('TEMP'))
    try:
        for filename in os.listdir(temp_dir):
            file_path = os.path.join(temp_dir, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        messagebox.showinfo("Sukces", "Pliki tymczasowe zostały usunięte.")
    except Exception as e:
        messagebox.showerror("Błąd", f"Wystąpił błąd: {e}")

def optimize(level):
    clear_temp_files()
    if level == "low":
        messagebox.showinfo("Optymalizacja", "Optymalizacja niska zakończona!")
    elif level == "medium":
        messagebox.showinfo("Optymalizacja", "Optymalizacja średnia zakończona!")
    elif level == "hard":
        messagebox.showinfo("Optymalizacja", "Optymalizacja trudna - Bądź ostrożny z procesami!")

def create_gui():
    root = tk.Tk()
    root.title("RaiseFPS")
    root.geometry("450x500")
    root.configure(bg="#012025")
    root.resizable(False, False)

    bg_color = "#012025"        # ciemne tło
    low_color = "#FFDC57"       # zieleń
    medium_color = "#7EDA53"    # żółty
    hard_color = "#FF5558"      # czerwony

    header_frame = tk.Frame(root, bg=bg_color)
    header_frame.pack(fill=tk.X, pady=(10, 0))

    logo_label = tk.Label(
        header_frame, 
        text="RaiseFPS",
        font=("Poppins", 35, "bold"),
        fg="white",
        bg=bg_color
    )
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
    button_frame.pack(pady=20)

    def create_button(text, color, command):
        button = tk.Button(
            button_frame, text=text,
            command=command,
            bg=color, fg="black",
            activebackground=color,
            activeforeground="white",
            font=("Verdana", 16, "bold"),
            padx=60, pady=15,
            bd=0, relief="flat",
            highlightthickness=0,
            cursor="hand2"
        )

        return button

    low_button = create_button("Low", low_color, lambda: optimize("low"))
    medium_button = create_button("Medium", medium_color, lambda: optimize("medium"))
    hard_button = create_button("Pro", hard_color, lambda: optimize("hard"))

    low_button.pack(pady=10, fill=tk.X, padx=50)
    medium_button.pack(pady=10, fill=tk.X, padx=50)
    hard_button.pack(pady=10, fill=tk.X, padx=50)

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
