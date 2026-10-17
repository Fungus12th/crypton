# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = [
    'crypton',
    'crypton.core',
    'crypton.core.crypto',
    'crypton.core.header',
    'crypton.core.vault',
    'crypton.core.windows_mount',
    'crypton.core.fuse_vault',
    'crypton.sync',
    'crypton.sync.gdrive',
    'crypton.ui',
    'crypton.ui.gui',
    'crypton.ui.cli',
    'argon2',
    '_argon2_cffi_bindings',
    'cryptography',
    'customtkinter',
    'typer',
    'rich',
    'googleapiclient',
    'google_auth_oauthlib',
    'google.auth',
]

for pkg in ('customtkinter', '_argon2_cffi_bindings', 'cryptography', 'google_auth_oauthlib', 'googleapiclient', 'PIL'):
    try:
        ret = collect_all(pkg)
        datas += ret[0]
        binaries += ret[1]
        hiddenimports += ret[2]
    except Exception:
        pass

datas += [('crypton/assets', 'crypton/assets'), ('crypton.ico', '.'), ('crypton.png', '.')]

a = Analysis(
    ['crypton/main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='crypton-windows',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='crypton.ico',
)
