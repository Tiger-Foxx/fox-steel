#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox CLI — Entry point for ``pip install`` / ``console_scripts``.

When installed via ``pip install .``, running ``steelfox`` on the command
line will invoke ``main()`` here, which delegates to the real entry point
in ``steelfox.py``.
"""

import runpy
import sys


def main() -> None:
    """Delegate to steelfox.py's __main__ block."""
    # steelfox.py lives at the package root, next to this file.
    # runpy lets us execute it as a script without import gymnastics.
    sys.argv[0] = "steelfox"
    runpy.run_path(
        str(__import__("pathlib").Path(__file__).resolve().parent / "steelfox.py"),
        run_name="__main__",
    )


if __name__ == "__main__":
    main()
