# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = []
binaries = []
hiddenimports = ['fuse', 'googleapiclient', 'google_auth_oauthlib', 'google.auth']
tmp_ret = collect_all('customtkinter')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]

for pkg in ['google_auth_oauthlib', 'googleapiclient']:
    try:
        ret = collect_all(pkg)
        datas += ret[0]; binaries += ret[1]; hiddenimports += ret[2]
    except Exception:
        pass

datas += [('crypton/assets', 'crypton/assets'), ('crypton.png', '.'), ('crypton.ico', '.')]


a = Analysis(
    ['crypton/main.py'],
    pathex=[],
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
    name='crypton-linux',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
