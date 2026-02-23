#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SteelFox — Setup Script

Allows installation via:
    pip install .
    pip install -e .          (dev / editable)
    pip install .[builder]    (includes builder dependencies)
"""

from pathlib import Path
from setuptools import setup, find_packages

HERE = Path(__file__).resolve().parent
README = (HERE / "README.md").read_text(encoding="utf-8", errors="replace")

# Core dependencies (enough to run steelfox on Windows)
INSTALL_REQUIRES = [
    "pycryptodome>=3.19.0",
    "pyasn1>=0.5.0",
]

# Platform-specific core deps
EXTRAS_REQUIRE = {
    # Linux helpers (future credential recovery on Linux)
    "linux": [
        "psutil",
        "secretstorage",
    ],
    # Builder / packaging dependencies
    "builder": [
        "Pillow>=9.0.0",
        "pyinstaller>=5.0.0",
    ],
    # Everything
    "all": [
        "pycryptodome>=3.19.0",
        "pyasn1>=0.5.0",
        "Pillow>=9.0.0",
        "pyinstaller>=5.0.0",
        "psutil",
    ],
}

setup(
    name="steelfox",
    version="1.3.1",
    author="Fox (Tiger-Foxx)",
    author_email="tiger-foxx@users.noreply.github.com",
    description="Advanced Windows Credential & Reconnaissance Framework",
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/Tiger-Foxx/fox-steel",
    project_urls={
        "Bug Tracker": "https://github.com/Tiger-Foxx/fox-steel/issues",
        "Changelog": "https://github.com/Tiger-Foxx/fox-steel/blob/main/CHANGELOG.md",
        "Source": "https://github.com/Tiger-Foxx/fox-steel",
    },
    license="LGPL-3.0",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={
        "steelfox": ["assets/*"],
    },
    python_requires=">=3.10",
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS_REQUIRE,
    entry_points={
        "console_scripts": [
            "steelfox=steelfox_cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: GNU Lesser General Public License v3 (LGPLv3)",
        "Operating System :: Microsoft :: Windows",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
    keywords="security credentials recovery windows penetration-testing",
)
