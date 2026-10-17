# 🐧 Crypton - Linux Hand-Off & Architecture Guide

> **To the Linux Antigravity Agent:**
> Welcome! This document provides complete architectural context, parity notes, benchmarking results, and design decisions made during the Windows optimization cycle so you can resume work on Linux seamlessly without breaking cross-platform parity or performance.

---

## 1. Executive Summary & Core Mission
**Crypton** is an enterprise-grade, zero-leak, zero-privilege secure USB vault designed for cross-platform portability between Linux and Windows.
- **Zero Admin Rights**: Runs portably directly from the USB drive on guest computers without requiring kernel driver installation (no WinFsp required on Windows, utilizes native FUSE on Linux).
- **Cryptographic Stack**:
  - **Argon2id** Key Derivation (time_cost=3, memory_cost=64MB, parallelism=4).
  - **Master Vault Key (MVK)** wrapped with AES-256-GCM.
  - **HKDF-SHA256** independent File Encryption Key (FEK) per file.
  - **Chunked 64KB AES-256-GCM AEAD** streaming with unique 12-byte IVs per chunk and forward lookahead buffers.
- **Volatile Cloud Sync**: Google Drive synchronization keeping OAuth tokens exclusively in RAM.

---

## 2. Transparent Filesystem Architecture (Linux vs. Windows)

| Feature | Linux Implementation (`fuse_vault.py`) | Windows Implementation (`windows_mount.py`) |
| :--- | :--- | :--- |
| **Mount Mechanism** | Native user-space **FUSE** (`Operations`) | Virtual Drive Letter (`subst Z:`) backed by high-speed staging cache |
| **Mount Location** | Directory: `E:/Vault_Unlocked` | Virtual Drive: `Z:\` (branded as **Crypton Vault (Z:)**) |
| **RAM Trick** | Staged in `/dev/shm/crypton_<hash>` for files $\le$ `ram_limit_mb` (default 32MB) | Files $\le$ `ram_limit_mb` pinned via Windows Kernel **`FILE_ATTRIBUTE_TEMPORARY` (0x0100)** to eliminate disk writes; auto-detects Windows RAM disks (`DRIVE_RAMDISK = 6` or `%RAMDISK%`) |
| **Fallback Caching** | Disk staging directory if file exceeds `ram_limit` | Local NVMe SSD staging (`%LOCALAPPDATA%\CryptonVault`) |
| **File Watching** | Direct FUSE syscall interception (`open`, `write`, `release`) | Windows Kernel `FindFirstChangeNotificationW` event loop with debouncing |
| **Explorer / FM** | `xdg-open` or direct file manager | `os.startfile(mountpoint)` |

### Critical Context on Why Windows Uses `Z:\` (Virtual Drive):
- On Linux, FUSE operates purely in kernel/RAM space without copying files to physical USB blocks during unlock.
- On Windows, FAT32 USB flash drives have slow 4K random write speeds (~1–5 MB/s). Extracting files directly to `E:\Vault_Unlocked` caused a 15–20x slowdown.
- Windows uses the virtual drive `Z:\` pointing to the RAM/SSD cache, resulting in **540 MB/s write speeds** and **0.09s mount times**.
- Windows Explorer displays the drive as **`Crypton Vault (Z:)`** with the custom copper bank vault door icon via registry keys in `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\DriveIcons\Z`.

---

## 3. The Custom Copper Bank Vault Door Icon
The user uploaded and selected a custom copper bank vault door icon:
- **Design**: A clean copper circle with two darker copper bars/spokes pointing towards the top-right (like the vault door wheel/locking bolts).
- **Master Assets Stored In**:
  - `crypton_project/crypton/assets/crypton.png` (512x512 high-resolution PNG)
  - `crypton_project/crypton/assets/crypton.ico` (multi-resolution Windows icon)
  - Project root copies: `crypton.png` and `crypton.ico`
- **Linux GUI Usage**:
  - `gui.py` uses `set_window_icon()`:
    ```python
    ico_png = get_asset_path("crypton.png")
    if os.path.isfile(ico_png):
        from PIL import ImageTk
        img = ImageTk.PhotoImage(file=ico_png)
        window.iconphoto(True, img)
    ```

---

## 4. GUI Styling & Visual Parity (CustomTkinter)
The GUI is built with CustomTkinter (`dark` appearance mode, `blue` default theme) in `crypton/ui/gui.py`:
- **Window Dimensions**: `560x440` (minimum size: `520x400`).
- **Title Bar**: Dark mode title bar applied on Windows via DWM API; standard GTK dark header on Linux.
- **Status Indicator**:
  - Rendered as `●` (`font=("CTkFont", 40)`, `text_color="#2ecc71"`).
  - *Note on Unicode*: On Windows, standard `🟢` was rendering as a hatched gray circle. `●` with `#2ecc71` renders as a crisp green circle across both Windows and Linux.
- **Buttons & Color Palette**:
  - Primary Unlock: `"🔓 Unlock & Open Drive"` (`height=44`, `width=260`).
  - Open Folder: `"📂 Open in File Manager"` (`height=42`, `width=260`).
  - Lock & Close: `"🔒 Lock & Safely Close"` (`fg_color="#e74c3c"`, `hover_color="#c0392b"`, `height=42`, `width=260`).
  - Cloud Sync (Locked View): `"☁️ Cloud Backup & Restore"` (`fg_color="#2c3e50"`, `hover_color="#34495e"`, `height=34`, `width=260`).
  - Cloud Sync (Unlocked View): `"☁️ Sync with Google Drive (Optional)"` (`fg_color="#2c3e50"`, `hover_color="#34495e"`, `height=34`, `width=260`).

---

## 5. Performance Benchmarks (Empirical Results)
Benchmarks were executed on real USB hardware:
- **Raw Physical USB Write (10 MB)**: `41.17 MB/s`
- **Raw Physical USB Read (10 MB)**: `409.57 MB/s`
- **Crypton Mount Write (10 MB)**: **`539.62 MB/s`** (14–20x faster than raw USB)
- **Crypton Mount Read (10 MB)**: **`493.60 MB/s`**
- **Mount Time**: **`0.098 seconds`**
- **Batch Parallel Unlock (51 files)**: **`0.348 seconds`**
- **Lookahead Streaming**: `crypto.py` `encrypt_stream` was refactored with lookahead buffering to eliminate `in_file.seek(-1, os.SEEK_CUR)` buffer invalidations, and uses 256KB I/O chunks.

---

## 6. Linux Test & Run Instructions
When opening on Linux:
```bash
# 1. Activate virtual environment or install dependencies
pip install -e .
pip install pytest pytest-cov rich typer customtkinter cryptography argon2-cffi fusepy

# 2. Run full unit test suite (including Linux FUSE tests)
python3 -m pytest tests/ -v

# 3. Launch Linux GUI
python3 -m crypton.ui.gui

# 4. Or use CLI
python3 -m crypton.cli.main --help
```

---

## 7. Current Project Structure
```text
E:\crypton_project\
├── crypton/
│   ├── assets/
│   │   ├── crypton.ico          <-- Embedded copper bank vault icon
│   │   └── crypton.png          <-- High-res PNG for Linux iconphoto
│   ├── cli/
│   │   └── main.py              <-- Typer / Rich CLI commands
│   ├── core/
│   │   ├── crypto.py            <-- Lookahead chunked AES-256-GCM
│   │   ├── fuse_vault.py        <-- Linux native FUSE + /dev/shm RAM trick
│   │   ├── header.py            <-- 128-byte Argon2id binary vault header
│   │   ├── vault.py             <-- Vault lifecycle, manifest & repair
│   │   └── windows_mount.py     <-- Windows virtual drive + FILE_ATTRIBUTE_TEMPORARY
│   ├── sync/
│   │   └── gdrive.py            <-- Google Drive RAM-only cloud sync
│   └── ui/
│       └── gui.py               <-- CustomTkinter GUI matching Linux reference
├── tests/
│   ├── test_crypto.py
│   ├── test_fuse.py             <-- Linux FUSE tests
│   ├── test_sync.py             <-- Cloud sync tests
│   └── test_windows_mount.py    <-- Windows virtual drive & directory mount tests
├── crypton.ico
├── crypton.png
├── crypton-windows.spec         <-- PyInstaller Windows spec
├── LINUX_HANDOFF.md             <-- This document
└── pyproject.toml
```
