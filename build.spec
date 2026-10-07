# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for the Internet Connectivity & Protocol Analyzer.

Build on Windows with:
    pyinstaller build.spec

The resulting standalone executable is written to dist/ICPA/ICPA.exe
(or dist/ICPA.exe if you switch to one-file mode below).
No administrator privileges are required to run it.
"""

import sys

block_cipher = None

a = Analysis(
    ["main.py"],
    pathex=[],
    binaries=[],
    datas=[("app/assets/fonts", "app/assets/fonts")],
    hiddenimports=[
        "app.core",
        "app.gui",
        "app.export",
        "aioquic",
        "aioquic.asyncio",
        "aioquic.h3",
        "aioquic.quic",
        "websockets",
        "httpx",
        "httpcore",
        "h2",
        "hpack",
        "hyperframe",
        "urllib3",
        "requests",
        "dns",
        "dns.resolver",
        "app.core.site_reachability",
        "app.core.tcp_stall_test",
        "app.core.environment_check",
        "app.core.protocol_whitelist",
        "app.core.compare",
        "app.export.history",
        "app.gui.fonts",
        "app.i18n",
        "app.i18n_fa",
        "app.i18n_fa_diag",
        # layered diagnostic engine (imported lazily by several modules)
        "app.diag",
        "app.diag.results",
        "app.diag.neterrors",
        "app.diag.testconfig",
        "app.diag.retry",
        "app.diag.graph",
        "app.diag.correlation",
        "app.diag.adapter",
        "app.diag.probes",
        "app.diag.localnet",
        "app.diag.reportlayers",
        "app.diag.structlog",
        "app.core.runner",
        "app.core.gateway",
        "app.core.icmp",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="ICPA",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,          # windowed application, no console box
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="ICPA",
)
