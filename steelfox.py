#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
 ███████╗████████╗███████╗███████╗██╗     ███████╗ ██████╗ ██╗  ██╗
 ██╔════╝╚══██╔══╝██╔════╝██╔════╝██║     ██╔════╝██╔═══██╗╚██╗██╔╝
 ███████╗   ██║   █████╗  █████╗  ██║     █████╗  ██║   ██║ ╚███╔╝
 ╚════██║   ██║   ██╔══╝  ██╔══╝  ██║     ██╔══╝  ██║   ██║ ██╔██╗
 ███████║   ██║   ███████╗███████╗███████╗██║     ╚██████╔╝██╔╝ ██╗
 ╚══════╝   ╚═╝   ╚══════╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
 
                                    =-                                   
                                +*%%%%#+-                               
                             +#%%%%%%%%%%%+-              :             
             #%%=         -#%%%%%%%%%%%%%#%%%=         +%%%-            
            -%%%%%%*=  -*%%%%%%%%%%%%%%%%%%#=#%#=  -+%%%%%%=            
            +%%-#%%%%%*=%%%%%%%%%%%%%%%%%%%%%%*+#=%%%%%#:%%#            
            #%%: +%%%%#%*=%%%%%%%%%%%%%%%%%%%%+*%%#%%%*  #%*            
            *%%.-%+*%%%+#%%*%%%%%%%%%%%%%%%%++%%-%%%#-#- %%*            
            #%%-  %%+%%%*-%%%%%%%%%%%%%#**%#%%=+%%%+%%+ :%%*            
            +%%* +=#%%%%%* *%%%%%%%%%%%%%%%%* *%%%%%#++ =%%#            
            -%%*  =%%%%%%%#-#%%%%%%%%%%#-*+%#+%%%%%%%+ =*%%=            
             %%### *%%%%%%%%%*%%%%%%%%*#%%%*=-%%%%%%# =%*%%-            
             -%%*%%**%%%%%*=#%%%%%%%%%%%%%++=#+ +%%*+%%*%%+             
             +%%%%%%%%%#+-#%%%%%#*-  -+*%%%%%#-   +%%%%%%%#             
            =%%#%%%%%%=-#%%%%*-          -=%%%%%#:  +%%%%%%*            
            #%##%%%%+=%%%%%-                -+%%%%%+ -%%#-%%-           
           *%%+ %%#-#%%%*:                     =#%%%%#-*# *%#           
          -%%%##%+%%%%=                          -*%%%%#=* #%*          
          #%#%%%%%%%-                               +%%%%#=:%%+         
         +%*#%%%%%-       -                           #%%%%++%%=        
        +%#+%%%%+    -+##%#%*=*-         *+*%%%#*=     :#%%%#-%#:       
       +%#-%%%+:        *=-+#%%%-      -%#%*+ =*-        -%%%%%%#       
      -%#-#%%:     *%+-  *%%#-+%%*=  -##%=-*%%#-  =##      *%%%%%#      
     -%#:#%*     :#%%*%%#+  ::-        -  ::  =*%%%%%#-     +%%%%%+     
    =%#-+%=   ==**#%%%%%%%%*    +-     =    +#%%%%%%%%#*+=   -%%%%%*    
   =%%=+%-           -=#%%%%# #**+    ++* +#%%%%%==-          :#%%%%+   
  -%%-:#-          .-#%%%%%%# #*+#    #+##*#%%%%%%#=            #%+%%-  
  #%%+ =#:              +%%=* #%%%    %%#%-+-%%+               *%*-#%*  
   +%%#--*=   -           =#- %%%%#***%%%%*-#=            -   *%++%%+   
    -*%%* -*  =*  +         * %%# *+=# #%%*+            -#= .#%=%%*-    
      :#%%+ *  *#- * #        *%%*    =%%#             -%= -%#%%%:      
    -*#%%%%#+   *%*+#-%+       -*##+-*#*:        -*   #%# *%%%#=+-      
  =*%#*%%%%%%%=  =%%#%=%*        =##%#*+       :##  =%%**%%%#-*%%%%%#=  
      =%#: -=%%%: :*%%%*%%+        -=         =%* :%%%#%%%= +%%%=-      
         =##+  -#%- =%%%%%%#:==             +%#:=%%%%%%*:-#%#-          
            =*+   *#+ -##+%%%=#*          +%*:=#%**%#= -#*=             
               +=   =+= =#+-%%*#*       +*= +%+--#+- :#=                
                           = -%##-    -   -%=  +-   =                   
                               -#%=     =*-                             
                                 -#=   ==                               
                                   =  =                                 


 SteelFox — Advanced Windows Credential & Reconnaissance Framework
 Version  : 1.0.0
 Author   : Fox
 Purpose  : Authorized security auditing and research only.

 Usage:
   python steelfox.py all                 — Run every module
   python steelfox.py browsers            — Browsers only
   python steelfox.py -oA -output ./loot  — All formats in ./loot
   python steelfox.py all -oH             — HTML dark-theme report

 DISCLAIMER:
   This tool is provided for EDUCATIONAL and AUTHORIZED security
   research ONLY. Unauthorized access to computer systems is illegal.
   The author assumes no liability for misuse.
"""

from __future__ import annotations

import argparse
import logging
import sys
import time

# ─── Ensure we're on a supported Python version ─────────────────────────
if sys.version_info < (3, 10):
    sys.exit(
        "[!] SteelFox requires Python 3.10 or later.\n"
        f"    Current version: {sys.version}"
    )

from steelfox.core.config import config
from steelfox.core.module_loader import get_categories, instantiate_modules, module_summary
from steelfox.core.output import ProgressDisplay, StandardOutput, write_reports
from steelfox.core.runner import run_steelfox

logger = logging.getLogger("steelfox")


# ─── CLI Builder ─────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with category subcommands."""

    parser = argparse.ArgumentParser(
        prog="steelfox",
        description=(
            "SteelFox — Advanced Windows Credential & Reconnaissance Framework\n"
            "                          by Fox\n"
            "\n"
            "Recovers credentials, tokens, sessions, and system information\n"
            "from 80+ sources across 12 categories."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  steelfox.py all                       Run every module\n"
            "  steelfox.py browsers                  Browser passwords only\n"
            "  steelfox.py all -oA -output results   All reports in ./results\n"
            "  steelfox.py messaging -oJ             Messaging + JSON output\n"
            "  steelfox.py reconnaissance -vv        Recon with debug output\n"
            "  steelfox.py all --password P@ss       Supply a master password\n"
            "\n"
            "DISCLAIMER: For AUTHORIZED security research and education ONLY.\n"
            "            Unauthorized use is illegal and unethical.\n"
        ),
    )

    # ─── Category subcommand ────────────────────────────────────────
    categories = [
        "all", "browsers", "messaging", "mails", "passwords", "cloud",
        "gaming", "devtools", "network", "sysadmin", "databases",
        "windows", "reconnaissance",
    ]

    parser.add_argument(
        "category",
        nargs="?",
        default="all",
        choices=categories,
        help="Module category to run (default: all)",
    )

    # ─── Output Options ─────────────────────────────────────────────
    output_group = parser.add_argument_group("output options")
    output_group.add_argument(
        "-oJ", "--json",
        action="store_const",
        const="json",
        dest="output_format",
        help="Write results as a JSON report",
    )
    output_group.add_argument(
        "-oN", "--txt",
        action="store_const",
        const="txt",
        dest="output_format",
        help="Write results as a plaintext TXT report",
    )
    output_group.add_argument(
        "-oH", "--html",
        action="store_const",
        const="html",
        dest="output_format",
        help="Write results as an HTML dark-theme report",
    )
    output_group.add_argument(
        "-oA", "--all-formats",
        action="store_const",
        const="all",
        dest="output_format",
        help="Write results in ALL formats (JSON + TXT + HTML)",
    )
    output_group.add_argument(
        "-output", "--output",
        type=str,
        default=".",
        metavar="DIR",
        help="Directory for saved report files (default: current dir)",
    )

    # ─── Behavior Options ───────────────────────────────────────────
    behaviour_group = parser.add_argument_group("behaviour options")
    behaviour_group.add_argument(
        "-p", "--password",
        type=str,
        default=None,
        help="Master / user password for encrypted vaults (e.g. Firefox master pw)",
    )
    behaviour_group.add_argument(
        "-s", "--stealth",
        action="store_true",
        default=False,
        help="Stealth mode: hide console window, silent execution, HTML report only",
    )
    behaviour_group.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Suppress banner and per-module console output",
    )
    behaviour_group.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity (-v = verbose, -vv = debug)",
    )
    behaviour_group.add_argument(
        "--list-modules",
        action="store_true",
        default=False,
        help="List all available modules and exit",
    )
    behaviour_group.add_argument(
        "--version",
        action="version",
        version=f"SteelFox {config.VERSION} — by {config.AUTHOR}",
    )

    return parser


# ─── Module Listing ──────────────────────────────────────────────────────

def list_modules() -> None:
    """Print a formatted summary of every available module."""
    from steelfox.core.module_loader import get_modules_by_category

    print()
    print(f"  {'='*60}")
    print(f"  SteelFox {config.VERSION} — Module Summary")
    print(f"  {'='*60}")
    print()

    all_mods = get_modules_by_category()
    total = 0

    for cat in sorted(all_mods.keys()):
        classes = all_mods[cat]
        total += len(classes)
        print(f"  [{cat.upper()}]")
        for cls in classes:
            meta = cls.meta
            admin_flag = "  (admin)" if meta.admin_required else ""
            desc = meta.description[:60] if meta.description else ""
            print(f"    - {meta.name:<30} {desc}{admin_flag}")
        print()

    print(f"  {'─'*60}")
    print(f"  Total: {total} modules across {len(all_mods)} categories")
    print(f"  {'─'*60}")
    print()


# ─── Logging Setup ───────────────────────────────────────────────────────

def setup_logging(verbosity: int) -> None:
    """Configure logging based on verbosity level."""
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity >= 1:
        level = logging.INFO
    else:
        level = logging.WARNING

    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


# ─── Main ────────────────────────────────────────────────────────────────

def main() -> None:
    """SteelFox entry point."""

    parser = build_parser()
    args = parser.parse_args()

    # ─── Setup ───────────────────────────────────────────────────────
    setup_logging(args.verbose)
    config.quiet_mode = args.quiet
    config.verbosity = args.verbose
    config.stealth_mode = getattr(args, "stealth", False)

    # ─── Stealth: Hide Console Window ────────────────────────────────
    if config.stealth_mode:
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)  # SW_HIDE
        except Exception:
            pass
        # Stealth implies quiet in terms of console output
        config.quiet_mode = True

    # ─── List Modules Mode ───────────────────────────────────────────
    if args.list_modules:
        list_modules()
        return

    # ─── Count Modules for Progress Bar ─────────────────────────────
    if not config.quiet_mode and not config.stealth_mode and config.verbosity == 0:
        try:
            cat_arg = args.category if hasattr(args, "category") else "all"
            mods = instantiate_modules(category=cat_arg)
            config.total_modules = len(mods)
        except Exception:
            config.total_modules = 0

    # ─── Build Output Handler ────────────────────────────────────────
    progress: ProgressDisplay | None = None
    if config.total_modules > 0 and config.verbosity == 0 and not config.quiet_mode:
        progress = ProgressDisplay(total=config.total_modules)
    config.st = StandardOutput(progress=progress)

    # ─── Execution ───────────────────────────────────────────────────
    start = time.perf_counter()
    report_paths: list[str] = []

    try:
        for event in run_steelfox(
            category=args.category,
            password=args.password,
            output_dir=args.output,
            output_format=args.output_format,
        ):
            # runner sends: ("User", name) or (success, name, results)
            # All display logic is handled inside StandardOutput / ProgressDisplay
            if isinstance(event, tuple) and len(event) == 3:
                # Module result — runner already handled display
                pass
    except KeyboardInterrupt:
        if not config.quiet_mode and not config.stealth_mode:
            if progress:
                progress.clear()
            print("\n  [!] Scan interrupted by user.")
    except Exception as exc:
        logger.error("Fatal error: %s", exc, exc_info=True)
        if args.verbose >= 2:
            import traceback
            traceback.print_exc()


if __name__ == "__main__":
    main()
