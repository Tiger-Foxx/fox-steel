# -*- coding: utf-8 -*-
"""
SteelFox — Professional Output System

Console modes:
  • default  (verbosity=0) — in-place progress bar per module, HTML report at end
  • verbose  (verbosity≥1) — full credential output per module + report
  • quiet    (quiet_mode)  — no console output, report only
  • stealth  (stealth_mode)— silent execution, console hidden, report only

Report formats: html (default) | json | txt | all
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from steelfox.core.config import config

logger = logging.getLogger("steelfox")

# ─── Force UTF-8 Console Output on Windows ───────────────────────────────
try:
    ctypes.windll.kernel32.SetConsoleOutputCP(65001)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ─── Win32 Console Colour Helpers ────────────────────────────────────────
STD_OUTPUT_HANDLE = -11


class _C:
    RESET   = 0x07
    HEADER  = 0x0F
    CYAN    = 0x0B
    GREEN   = 0x0A
    YELLOW  = 0x0E
    RED     = 0x0C
    BLUE    = 0x09
    GREY    = 0x08
    MAGENTA = 0x0D
    ORANGE  = 0x06


def _set_color(c: int) -> None:
    try:
        h = ctypes.windll.kernel32.GetStdHandle(STD_OUTPUT_HANDLE)
        ctypes.windll.kernel32.SetConsoleTextAttribute(h, c)
    except Exception:
        pass


def _cprint(text: str, c: int = _C.RESET, end: str = "\n") -> None:
    if config.quiet_mode or config.stealth_mode:
        return
    _set_color(c)
    sys.stdout.write(text + end)
    sys.stdout.flush()
    _set_color(_C.RESET)


# ─── Progress Display ─────────────────────────────────────────────────────

class ProgressDisplay:
    """In-place console progress bar for default scan mode (verbosity=0)."""

    BAR_WIDTH = 30

    def __init__(self, total: int) -> None:
        self._total = max(total, 1)
        self._done = 0
        self._current_name = ""
        self._start = time.time()
        self._active = False

    def start(self) -> None:
        self._active = True
        self._render()

    def set_current(self, name: str) -> None:
        self._current_name = name
        if self._active:
            self._render()

    def advance(self) -> None:
        self._done += 1
        if self._active:
            self._render()

    def _render(self) -> None:
        if not self._active or config.quiet_mode or config.stealth_mode:
            return
        if config.verbosity >= 1:
            return  # verbose mode has its own output
        pct = self._done / self._total
        filled = int(pct * self.BAR_WIDTH)
        bar = "█" * filled + "░" * (self.BAR_WIDTH - filled)
        name = (self._current_name[:36] + "…") if len(self._current_name) > 37 else self._current_name
        line = f"  [{bar}] {int(pct * 100):3d}%  {self._done:3d}/{self._total}  ►  {name:<38}"
        sys.stdout.write(f"\r{line:<90}")
        sys.stdout.flush()

    def clear(self) -> None:
        self._active = False
        if not config.quiet_mode and not config.stealth_mode and config.verbosity == 0:
            sys.stdout.write(f"\r{' ' * 90}\r")
            sys.stdout.flush()


# ─── Standard Output ─────────────────────────────────────────────────────

class StandardOutput:
    """Controls all console output for SteelFox execution.

    Modes:
      verbosity=0 — progress bar only (default)
      verbosity=1 — full per-module credential output
      verbosity=2 — same as 1 + debug messages
      quiet_mode  — nothing
      stealth_mode— nothing
    """

    def __init__(self, progress: ProgressDisplay | None = None) -> None:
        self._start_time = time.time()
        self.progress = progress

    def _silent(self) -> bool:
        return config.quiet_mode or config.stealth_mode

    def _default_mode(self) -> bool:
        """True when verbosity=0 (progress bar or silent bar-less mode)."""
        return not self._silent() and config.verbosity == 0

    # ── Banner ────────────────────────────────────────────────────────
    def print_banner(self) -> None:
        if self._silent():
            return
        _cprint(config.BANNER, _C.ORANGE)
        _cprint(
            f"    {config.APP_NAME} v{config.VERSION}  ─  "
            f"Advanced Windows Credential Recovery & Reconnaissance",
            _C.HEADER,
        )
        _cprint(
            f"    {config.AUTHOR}  |  "
            f"Python {sys.version.split()[0]}  |  "
            f"{datetime.now():%Y-%m-%d %H:%M:%S}",
            _C.GREY,
        )
        _cprint("    " + "─" * 72, _C.GREY)
        print()
        if self._default_mode():
            _cprint("    Starting scan…", _C.GREY)
            print()
            if self.progress:
                self.progress.start()

    # ── Section Headers ──────────────────────────────────────────────
    def print_user(self, username: str) -> None:
        if self._silent():
            return
        if self._default_mode():
            _cprint(f"\n  ▶  User: {username}", _C.CYAN)
            return
        _cprint(f"\n  ╔══════════════════════════════════════════════════════════════╗", _C.CYAN)
        _cprint(f"  ║  User: {username:<54}║", _C.CYAN)
        _cprint(f"  ╚══════════════════════════════════════════════════════════════╝", _C.CYAN)

    def print_category(self, category: str) -> None:
        if self._silent() or self._default_mode():
            return
        _cprint(f"\n  ┌─ {category.upper()} {'─' * max(1, 58 - len(category))}┐", _C.BLUE)

    def title_info(self, title: str) -> None:
        """Called before each module starts — updates bar or prints header."""
        if self._silent():
            return
        if self._default_mode():
            if self.progress:
                self.progress.set_current(title)
            return
        _cprint(f"  │  ► {title}", _C.HEADER)

    # ── Results ──────────────────────────────────────────────────────
    def print_output(self, title: str, results: list[dict[str, Any]] | None) -> None:
        """Print module results. Default: advance bar. Verbose: print creds."""
        if self.progress:
            self.progress.advance()

        if self._silent():
            return

        if self._default_mode():
            return

        # ── Verbose output ────────────────────────────────────────
        if not results:
            _cprint(f"  │    No credentials found.", _C.GREY)
            return

        for cred in results:
            _cprint(f"  │  ┌── {title}", _C.GREEN)
            for key, value in cred.items():
                if str(key).startswith("_"):
                    continue
                display_val = str(value)
                if len(display_val) > 120:
                    display_val = display_val[:120] + "…"
                key_lower = str(key).lower()
                is_sensitive = any(w in key_lower for w in (
                    "password", "token", "secret", "key", "hash", "cookie"
                ))
                col = _C.YELLOW if is_sensitive else _C.RESET
                _cprint(f"  │  │  {str(key):<22}: {display_val}", col)
            _cprint(f"  │  └{'─' * 42}", _C.GREEN)

    # ── Footer ────────────────────────────────────────────────────────
    def print_footer(self) -> None:
        if self._silent():
            return
        if self.progress:
            self.progress.clear()

        elapsed = time.time() - self._start_time
        print()
        _cprint(f"  {'─' * 66}", _C.GREY)

        if config.nb_credentials_found > 0:
            _cprint(
                f"  ✔  {config.nb_credentials_found:,} credentials recovered",
                _C.GREEN,
            )
        else:
            _cprint("  ─  No credentials found.", _C.YELLOW)

        _cprint(f"  ✔  Completed in {elapsed:.2f}s", _C.GREY)
        _cprint(f"  {'─' * 66}", _C.GREY)
        print()

    def print_report_path(self, paths: list[str]) -> None:
        """Print the generated report path(s) in the footer."""
        if self._silent():
            return
        for p in paths:
            _cprint(f"  ✔  Report  →  {p}", _C.CYAN)
        print()


# ─── JSON Sanitizer ───────────────────────────────────────────────────────

def _sanitize_for_json(obj: Any) -> Any:
    """Recursively sanitize objects for safe JSON serialization."""
    if isinstance(obj, bytes):
        try:
            return obj.decode("utf-8")
        except UnicodeDecodeError:
            return obj.decode("latin-1")
    if isinstance(obj, str):
        return obj.encode("utf-8", errors="replace").decode("utf-8")
    if isinstance(obj, dict):
        return {_sanitize_for_json(k): _sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_sanitize_for_json(item) for item in obj]
    return obj


# ─── HTML Report Template ────────────────────────────────────────────────
# Placeholders ___DATA___ and ___META___ are replaced at generate time.
# Using .replace() avoids any conflict with CSS/JS curly braces.

_HTML_TEMPLATE = "\n".join([
    '<!DOCTYPE html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width,initial-scale=1">',
    '<title>SteelFox &mdash; Security Audit Report</title>',
    '<style>',
    "@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');",
    '*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}',
    ':root{',
    '  --bg:#050505;--bg-alt:#0a0a0a;--surf:#111;--surf-h:#161616;',
    '  --bd:#222;--bd-h:#333;',
    '  --txt:#e0e0e0;--txt-mute:#777;--txt-dim:#444;',
    '  --acc:#de5312;--acc-h:#ff6b26;--acc-dim:rgba(222,83,18,0.15);',
    '  --red:#cf3535;--red-dim:rgba(207,53,53,0.15);',
    '  --grn:#35cf5f;--grn-dim:rgba(53,207,95,0.15);',
    '  --blu:#358ccf;--blu-dim:rgba(53,140,207,0.15);',
    "  --font-main:'Inter',system-ui,-apple-system,sans-serif;",
    "  --font-mono:'JetBrains Mono','Consolas',monospace;",
    '  --gap:20px;',
    '}',
    'html{scroll-behavior:smooth}',
    'body{background:var(--bg);color:var(--txt);font-family:var(--font-main);font-size:13px;line-height:1.5;height:100vh;overflow:hidden}',
    'a{color:inherit;text-decoration:none}',
    'button{cursor:pointer;border:none;outline:none;font-family:inherit;background:transparent;color:inherit}',
    'input{font-family:inherit;outline:none;border:none;color:inherit}',
    '.app{display:grid;grid-template-rows:50px 1fr;grid-template-columns:240px 1fr;height:100vh}',
    '.top-bar{grid-column:1/-1;background:var(--bg-alt);border-bottom:1px solid var(--bd);display:flex;align-items:center;padding:0 20px;justify-content:space-between;z-index:10}',
    '.sidebar{grid-row:2;background:var(--bg-alt);border-right:1px solid var(--bd);display:flex;flex-direction:column;overflow:hidden}',
    '.main{grid-row:2;grid-column:2;background:var(--bg);overflow-y:auto;padding:30px;position:relative}',
    '.brand{font-size:16px;font-weight:700;letter-spacing:0.5px;color:var(--txt);display:flex;align-items:center;gap:10px}',
    '.brand span{color:var(--acc)}',
    '.meta{display:flex;gap:20px;font-size:12px;color:var(--txt-mute);font-family:var(--font-mono)}',
    '.meta-item strong{color:var(--txt);margin-right:5px}',
    '.sb-search{padding:15px;border-bottom:1px solid var(--bd)}',
    '.sb-search-box{background:var(--surf);border:1px solid var(--bd);border-radius:4px;display:flex;align-items:center;padding:0 10px;height:32px;transition:border-color .2s}',
    '.sb-search-box:focus-within{border-color:var(--acc)}',
    '.sb-search-input{width:100%;background:transparent;font-size:12px}',
    '.sb-list{flex:1;overflow-y:auto;padding:10px 0}',
    '.sb-head{padding:15px 15px 5px;font-size:10px;text-transform:uppercase;letter-spacing:1px;color:var(--txt-dim);font-weight:600}',
    '.sb-item{display:flex;justify-content:space-between;align-items:center;padding:8px 15px;cursor:pointer;color:var(--txt-mute);border-left:2px solid transparent;transition:all .15s}',
    '.sb-item:hover{background:var(--surf);color:var(--txt)}',
    '.sb-item.active{background:var(--acc-dim);color:var(--acc);border-left-color:var(--acc)}',
    '.sb-badge{font-family:var(--font-mono);font-size:10px;padding:2px 6px;border-radius:3px;background:var(--bd);color:var(--txt-mute)}',
    '.dash-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:var(--gap);margin-bottom:40px}',
    '.dash-card{background:var(--bg-alt);border:1px solid var(--bd);padding:20px;display:flex;flex-direction:column;gap:5px;position:relative;overflow:hidden}',
    '.dash-card::after{content:"";position:absolute;top:0;left:0;width:3px;height:100%;background:var(--bd)}',
    '.dash-card:hover{border-color:var(--bd-h);transform:translateY(-1px);transition:all .2s}',
    '.dash-val{font-size:28px;font-weight:300;color:var(--txt);font-family:var(--font-mono)}',
    '.dash-lbl{font-size:11px;text-transform:uppercase;letter-spacing:1px;color:var(--txt-mute)}',
    '.dash-card.p-acc::after{background:var(--acc)}',
    '.dash-card.p-acc .dash-val{color:var(--acc)}',
    '.dash-card.p-blu::after{background:var(--blu)}',
    '.dash-card.p-blu .dash-val{color:var(--blu)}',
    '.dash-card.p-grn::after{background:var(--grn)}',
    '.dash-card.p-grn .dash-val{color:var(--grn)}',
    '.cat-sect{margin-bottom:50px;scroll-margin-top:20px}',
    '.cat-head{display:flex;align-items:center;gap:15px;margin-bottom:20px;padding-bottom:10px;border-bottom:1px solid var(--bd)}',
    '.cat-title{font-size:18px;font-weight:600;color:var(--txt);text-transform:uppercase;letter-spacing:1px}',
    ".cat-badge{font-family:var(--font-mono);font-size:11px;padding:3px 8px;background:var(--surf);color:var(--txt-mute);border:1px solid var(--bd);border-radius:4px}",
    '.mod-grp{background:var(--bg-alt);border:1px solid var(--bd);border-radius:0;margin-bottom:20px;overflow:hidden}',
    '.mod-head{padding:12px 15px;background:var(--surf);border-bottom:1px solid var(--bd);display:flex;align-items:center;justify-content:space-between;cursor:pointer;user-select:none}',
    '.mod-head:hover{background:var(--surf-h)}',
    '.mod-info{display:flex;align-items:center;gap:10px}',
    '.mod-name{font-weight:600;font-size:13px;color:var(--txt)}',
    '.mod-user{font-family:var(--font-mono);font-size:11px;color:var(--txt-mute);background:var(--bg);padding:2px 6px;border-radius:3px;border:1px solid var(--bd)}',
    '.mod-count{font-size:11px;color:var(--txt-dim);font-weight:500}',
    '.mod-body{background:var(--bg-alt);padding:15px;display:none}',
    '.mod-body.open{display:block;animation:fadeIn .2s ease}',
    '.creds-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:15px}',
    '.c-card{background:var(--bg);border:1px solid var(--bd);border-radius:0;transition:border-color .15s}',
    '.c-card:hover{border-color:var(--bd-h)}',
    '.c-head{padding:8px 12px;background:var(--surf);border-bottom:1px solid var(--bd);display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--txt-mute)}',
    '.c-src{font-weight:600;color:var(--txt);max-width:200px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}',
    '.c-body{padding:10px 12px}',
    '.c-row{display:grid;grid-template-columns:100px 1fr 24px;gap:10px;font-family:var(--font-mono);font-size:11px;margin-bottom:6px;align-items:start}',
    '.c-row:last-child{margin-bottom:0}',
    '.k{color:var(--txt-mute);word-wrap:break-word}',
    '.v{color:var(--txt);word-break:break-all}',
    '.v.sens{color:var(--acc)}',
    '.v.hidden{color:var(--txt-dim);cursor:pointer;transition:color .2s}',
    '.v.hidden:hover{color:var(--txt-mute)}',
    '.act{opacity:0;transition:opacity .2s;color:var(--txt-mute);display:flex;justify-content:center;cursor:pointer}',
    '.c-row:hover .act{opacity:1}',
    '.act:hover{color:var(--acc)}',
    '@keyframes fadeIn{from{opacity:0;transform:translateY(-5px)}to{opacity:1;transform:translateY(0)}}',
    '.empty-state{grid-column:1/-1;text-align:center;padding:40px;color:var(--txt-mute);font-style:italic}',
    '.filtered-out{display:none!important}',
    '#toast{position:fixed;bottom:20px;right:20px;background:var(--surf);color:var(--acc);border:1px solid var(--acc);padding:10px 20px;border-radius:4px;font-weight:500;transform:translateY(100px);transition:transform .3s cubic-bezier(0.175,0.885,0.32,1.275);z-index:999}',
    '#toast.vis{transform:translateY(0)}',
    '::-webkit-scrollbar{width:6px}',
    '::-webkit-scrollbar-track{background:var(--bg)}',
    '::-webkit-scrollbar-thumb{background:var(--bd-h);border-radius:3px}',
    '::-webkit-scrollbar-thumb:hover{background:var(--txt-mute)}',
    '</style>',
    '</head>',
    '<body>',
    '<div class="app">',
    '  <header class="top-bar">',
    '    <div class="brand"><span>//</span>SteelFox</div>',
    '    <div class="meta">',
    '      <div class="meta-item">Host: <strong id="m-host">-</strong></div>',
    '      <div class="meta-item">Scanned: <strong id="m-date">-</strong></div>',
    '      <div class="meta-item">Ver: <strong id="m-ver">-</strong></div>',
    '    </div>',
    '  </header>',
    '  <div class="sidebar">',
    '    <div class="sb-search">',
    '      <div class="sb-search-box">',
    '        <input type="text" class="sb-search-input" id="search" placeholder="Type to filter..." oninput="handleSearch(this.value)">',
    '      </div>',
    '    </div>',
    '    <div class="sb-list" id="sb-list"></div>',
    '    <div class="sb-head">Targets</div>',
    '    <div class="sb-list" id="sb-users" style="flex:0 auto;max-height:150px"></div>',
    '  </div>',
    '  <main class="main">',
    '    <div class="dash-grid" id="dashboard">',
    '      <div class="dash-card p-acc"><div class="dash-val" id="d-total">-</div><div class="dash-lbl">Total Credentials</div></div>',
    '      <div class="dash-card p-blu"><div class="dash-val" id="d-cats">-</div><div class="dash-lbl">Categories Found</div></div>',
    '      <div class="dash-card p-grn"><div class="dash-val" id="d-users">-</div><div class="dash-lbl">Users Targeted</div></div>',
    '    </div>',
    '    <div id="content"></div>',
    '  </main>',
    '</div>',
    '<div id="toast">Copied to clipboard</div>',
    '<script>',
    'const DATA=___DATA___;',
    'const META=___META___;',
    "const CATS={browsers:'Browsers',cloud:'Cloud',databases:'Databases',devtools:'Dev Tools',gaming:'Gaming',mails:'Mail',messaging:'Messaging',network:'Network',passwords:'Password Mgr',reconnaissance:'Recon',sysadmin:'SysAdmin',windows:'Windows'};",
    "const SENS=['password','token','secret','key','hash','cookie','private','api','card','cvv'];",
    'function init(){',
    '  renderMeta();',
    '  var map=processData();',
    '  renderSidebar(map);',
    '  renderContent(map);',
    "  var first=document.querySelector('.mod-body');",
    "  if(first)first.classList.add('open');",
    '}',
    'function processData(){',
    '  var map={};',
    '  DATA.forEach(function(d){',
    '    var u=d.User;',
    '    Object.entries(d).forEach(function(pair){',
    "      var k=pair[0],v=pair[1];",
    "      if(k==='User'||!v||typeof v!=='object')return;",
    '      if(!map[k])map[k]=[];',
    '      Object.entries(v).forEach(function(mp){',
    '        var mod=mp[0],arr=mp[1];',
    '        if(Array.isArray(arr)&&arr.length)map[k].push({u:u,mod:mod,creds:arr});',
    '      });',
    '    });',
    '  });',
    '  return Object.entries(map).sort(function(a,b){return countCreds(b[1])-countCreds(a[1]);});',
    '}',
    'function countCreds(arr){return arr.reduce(function(a,c){return a+c.creds.length;},0);}',
    'function renderMeta(){',
    "  document.getElementById('m-host').textContent=META.hostname;",
    "  document.getElementById('m-date').textContent=META.timestamp;",
    "  document.getElementById('m-ver').textContent=META.version;",
    "  document.getElementById('d-total').textContent=META.total_creds.toLocaleString();",
    "  var users=[];DATA.forEach(function(x){if(users.indexOf(x.User)===-1)users.push(x.User);});",
    "  document.getElementById('d-users').textContent=users.length;",
    '}',
    'function renderSidebar(map){',
    "  var ct=document.getElementById('sb-list');",
    "  document.getElementById('d-cats').textContent=map.length;",
    "  var h='';",
    '  map.forEach(function(pair){',
    '    var k=pair[0],arr=pair[1];',
    '    var c=countCreds(arr);',
    '    h+=\'<div class="sb-item" onclick="scrollCat(\\\'\'+ k +\'\\\')" id="nav-\'+k+\'"><span>\'+(CATS[k]||k)+\'</span><span class="sb-badge">\'+c+\'</span></div>\';',
    '  });',
    '  ct.innerHTML=h;',
    "  var users=[];DATA.forEach(function(x){if(users.indexOf(x.User)===-1)users.push(x.User);});",
    "  document.getElementById('sb-users').innerHTML=users.map(function(u){return '<div class=\"sb-item\"><span>'+esc(u)+'</span></div>';}).join('');",
    '}',
    'function renderContent(map){',
    "  var ct=document.getElementById('content');",
    '  if(!map.length){ct.innerHTML=\'<div class="empty-state">No credentials found in this scan.</div>\';return;}',
    "  var h='';",
    '  map.forEach(function(pair){',
    '    var k=pair[0],arr=pair[1];',
    '    h+=\'<div class="cat-sect" id="cat-\'+k+\'"><div class="cat-head"><div class="cat-title">\'+(CATS[k]||k)+\'</div><div class="cat-badge">\'+countCreds(arr)+\' items</div></div>\';',
    '    arr.forEach(function(m,i){',
    "      var mid=k+'-'+i;",
    '      h+=\'<div class="mod-grp"><div class="mod-head" onclick="toggle(\\\'\'+mid+\'\\\')">\'+',
    '        \'<div class="mod-info"><span class="mod-name">\'+esc(m.mod)+\'</span><span class="mod-user">\'+esc(m.u)+\'</span></div>\'+',
    '        \'<span class="mod-count">\'+m.creds.length+\'</span></div>\'+',
    '        \'<div class="mod-body" id="\'+mid+\'">\'+renderCreds(m.creds)+\'</div></div>\';',
    '    });',
    "    h+='</div>';",
    '  });',
    '  ct.innerHTML=h;',
    '}',
    'function renderCreds(arr){',
    '  var h=\'<div class="creds-grid">\';',
    '  arr.forEach(function(c){',
    "    h+='<div class=\"c-card\"><div class=\"c-head\"><span class=\"c-src\">'+esc(c.Source||'Unknown')+'</span></div><div class=\"c-body\">';",
    '    Object.entries(c).forEach(function(pair){',
    '      var k=pair[0],v=pair[1];',
    "      if(k.charAt(0)==='_')return;",
    '      var isS=SENS.some(function(x){return k.toLowerCase().indexOf(x)!==-1;});',
    "      var vStr=String(v===null||v===undefined?'':v);",
    '      var vEsc=esc(vStr);',
    "      var safe=vEsc.replace(/'/g,'&#39;');",
    '      if(isS){',
    "        h+='<div class=\"c-row\"><span class=\"k\">'+esc(k)+'</span><span class=\"v sens hidden\" onclick=\"togVis(this,\\''+safe+'\\')\">&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;</span><span class=\"act\" onclick=\"copy(\\''+safe+'\\')\">&oplus;</span></div>';",
    '      }else{',
    "        h+='<div class=\"c-row\"><span class=\"k\">'+esc(k)+'</span><span class=\"v\">'+vEsc+'</span><span class=\"act\" onclick=\"copy(\\''+safe+'\\')\">&oplus;</span></div>';",
    '      }',
    '    });',
    "    h+='</div></div>';",
    '  });',
    "  h+='</div>';",
    '  return h;',
    '}',
    "function toggle(id){document.getElementById(id).classList.toggle('open');}",
    'function scrollCat(id){',
    "  var el=document.getElementById('cat-'+id);",
    "  if(el)el.scrollIntoView({behavior:'smooth',block:'start'});",
    "  document.querySelectorAll('.sb-item').forEach(function(x){x.classList.remove('active');});",
    "  var nav=document.getElementById('nav-'+id);",
    "  if(nav)nav.classList.add('active');",
    '}',
    'function togVis(el,raw){',
    "  if(el.classList.contains('hidden')){el.innerHTML=raw;el.classList.remove('hidden');}",
    "  else{el.innerHTML='&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;';el.classList.add('hidden');}",
    '}',
    'function copy(txt){',
    "  var t=document.createElement('textarea');t.value=txt;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);",
    "  var el=document.getElementById('toast');el.classList.add('vis');setTimeout(function(){el.classList.remove('vis');},2000);",
    '}',
    "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}",
    'var _tm;',
    'function handleSearch(q){',
    '  clearTimeout(_tm);',
    '  _tm=setTimeout(function(){',
    '    var low=q.toLowerCase();',
    "    document.querySelectorAll('.c-card').forEach(function(c){",
    '      var match=c.innerText.toLowerCase().indexOf(low)!==-1;',
    "      c.classList.toggle('filtered-out',!match);",
    '    });',
    "    document.querySelectorAll('.mod-grp').forEach(function(m){",
    "      var vis=m.querySelectorAll('.c-card:not(.filtered-out)').length>0;",
    "      m.classList.toggle('filtered-out',!vis);",
    "      if(q&&vis){var mb=m.querySelector('.mod-body');if(mb)mb.classList.add('open');}",
    '    });',
    "    document.querySelectorAll('.cat-sect').forEach(function(s){",
    "      s.classList.toggle('filtered-out',s.querySelectorAll('.mod-grp:not(.filtered-out)').length===0);",
    '    });',
    '  },200);',
    '}',
    'window.onload=init;',
    '</script>',
    '</body>',
    '</html>',
])


# ─── HTML Report Writer ───────────────────────────────────────────────────

def write_html_report(results: list[dict[str, Any]], output_dir: str = ".") -> str:
    """Write a fully interactive HTML audit report. Returns the file path."""
    path = Path(output_dir) / f"{config.file_name_results}.html"
    path.parent.mkdir(parents=True, exist_ok=True)

    hostname = os.environ.get("COMPUTERNAME", "unknown")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    meta = {
        "tool": config.APP_NAME,
        "version": config.VERSION,
        "timestamp": timestamp,
        "hostname": hostname,
        "total_creds": config.nb_credentials_found,
    }

    clean_results = _sanitize_for_json(results)
    data_json = json.dumps(clean_results, ensure_ascii=False, default=str)
    meta_json = json.dumps(meta, ensure_ascii=False)

    # Neutralise any </script> injection in data
    data_json = data_json.replace("</script>", r"<\/script>").replace("<!--", r"<\!--")

    html = _HTML_TEMPLATE.replace("___DATA___", data_json).replace("___META___", meta_json)

    path.write_text(html, encoding="utf-8")
    logger.info("HTML report written to %s", path)
    return str(path)


# ─── JSON / TXT Report Writers ────────────────────────────────────────────

def write_json_report(results: list[dict[str, Any]], output_dir: str = ".") -> str:
    path = Path(output_dir) / f"{config.file_name_results}.json"
    path.parent.mkdir(parents=True, exist_ok=True)

    report = {
        "tool": config.APP_NAME,
        "version": config.VERSION,
        "timestamp": datetime.now().isoformat(),
        "hostname": os.environ.get("COMPUTERNAME", "unknown"),
        "results": _sanitize_for_json(results),
    }

    path.write_text(json.dumps(report, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
    logger.info("JSON report written to %s", path)
    return str(path)


def write_txt_report(results: list[dict[str, Any]], output_dir: str = ".") -> str:
    path = Path(output_dir) / f"{config.file_name_results}.txt"
    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "=" * 72,
        f"  {config.APP_NAME} v{config.VERSION} — Credential Recovery Report",
        f"  Generated: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"  Hostname:  {os.environ.get('COMPUTERNAME', 'unknown')}",
        f"  Total:     {config.nb_credentials_found} credentials",
        "=" * 72, "",
    ]

    for entry in results:
        user = entry.get("User", "Unknown")
        lines.append(f"\n  User: {user}")
        lines.append("  " + "─" * 60)
        for cat_name, cat_data in entry.items():
            if cat_name == "User":
                continue
            if isinstance(cat_data, dict):
                lines.append(f"\n  [{cat_name.upper()}]")
                for mod_name, creds in cat_data.items():
                    if isinstance(creds, list) and creds:
                        lines.append(f"    {mod_name}:")
                        for cred in creds:
                            if isinstance(cred, dict):
                                for k, v in cred.items():
                                    lines.append(f"      {k}: {v}")
                            lines.append("")
        lines.append("  " + "─" * 60)

    lines += ["", f"  Credentials: {config.nb_credentials_found}", "=" * 72]
    path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("TXT report written to %s", path)
    return str(path)


def write_reports(results: list[dict[str, Any]], output_dir: str = ".") -> list[str]:
    """Write reports in the configured format(s). Returns list of generated paths."""
    fmt = (config.output_format or "html").lower()
    paths: list[str] = []

    if fmt in ("json", "all"):
        paths.append(write_json_report(results, output_dir))
    if fmt in ("txt", "all"):
        paths.append(write_txt_report(results, output_dir))
    if fmt in ("html", "all"):
        paths.append(write_html_report(results, output_dir))

    # Safety fallback
    if not paths:
        paths.append(write_html_report(results, output_dir))

    return paths


# ─── Debug / Log Printer ─────────────────────────────────────────────────

def print_debug(level: str, message: str) -> None:
    """Route debug messages to the appropriate log level."""
    level_map = {
        "ERROR": logger.error,
        "WARNING": logger.warning,
        "DEBUG": logger.debug,
        "INFO": logger.info,
        "CRITICAL": logger.critical,
    }
    level_map.get(level.upper(), logger.debug)(message)
