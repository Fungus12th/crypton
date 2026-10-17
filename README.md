# Crypton 🛡️

<p align="center">
  <img src="crypton.png" width="128" height="128" alt="Crypton Logo">
</p>

<p align="center">
  <strong>Portable, Zero-Privilege Encrypted USB Vault &amp; Zero-Knowledge Cloud Sync</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-brightgreen" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.9%2B-blue" alt="Python">
  <img src="https://img.shields.io/badge/Encryption-AES--256--GCM-success" alt="Cipher">
  <img src="https://img.shields.io/badge/KDF-Argon2id-orange" alt="KDF">
  <img src="https://img.shields.io/badge/UI-CustomTkinter-emerald" alt="UI">
  <img src="https://img.shields.io/badge/Tests-16%2F16%20Passed-green" alt="Tests">
</p>

---

## 🌟 Overview

**Crypton** turns any standard USB thumb drive (FAT32, exFAT, NTFS) into a secure, portable, encrypted vault. It allows you to access and edit encrypted files on-the-fly through your native file manager with zero kernel drivers, zero administrator rights, and high-speed RAM/SSD caching.

Whether on Linux or Windows, your files remain sealed with military-grade **AES-256-GCM** encryption and an **Argon2id** key derivation function.

---

## ✨ Features

- **Cross-Platform Transparent Mounting:**
  - **Linux:** Mounts a transparent user-space filesystem (`Vault_Unlocked`) using native **FUSE** (`fusepy`).
  - **Windows:** Mounts a high-speed virtual drive letter (`Z:\`) using Windows built-in services—no admin privileges or WinFsp drivers required.
  - Drag, drop, open, and edit files normally in your desktop file manager (GNOME Files, Dolphin, Windows Explorer)—encryption and decryption occur invisibly in the background.

- **Vibrant Grass-Green Glassmorphic UI:**
  - Built with CustomTkinter featuring a fresh, luminous bright grass-green aesthetic with semi-transparent OS-level glassmorphism.
  - Custom copper bank vault door branding with seamless alpha-transparency.
  - Dark mode title bar integration on Windows via native DWM APIs.

- **High-Speed RAM & SSD Staging Pipeline:**
  - Generic USB thumb drives suffer from slow 4K random write speeds (1–5 MB/s). Crypton eliminates write bottlenecks by staging active files in fast volatile RAM (`/dev/shm` on Linux, kernel `FILE_ATTRIBUTE_TEMPORARY` and RAM disk caching on Windows) with asynchronous background encryption.
  - Sequential reads up to **870+ MB/s** and write speeds up to **540 MB/s**.

- **Envelope Encryption & Sub-100ms Password Rotation:**
  - **Master Vault Key (MVK):** 256-bit cryptographic key protected by Argon2id memory-hard hashing.
  - **Per-File Keys:** Derived uniquely using **HKDF-SHA256** (File UUID as salt).
  - Changing your master password takes under **100 milliseconds** because only the 32-byte MVK envelope is re-wrapped; gigabytes of files never need re-encryption.

- **Zero-Knowledge Google Drive Cloud Sync:**
  - Synchronize encrypted ciphertext blocks (`.crypton/data/`) with Google Drive. Google only ever sees scrambled AES-256-GCM chunks.
  - **Directional Two-Button Control:**
    - `Sync with Local Data`: USB is master (pushes new chunks and prunes deleted cloud files).
    - `Sync with Cloud Data`: Cloud is master (pulls remote chunks to USB and restores vault).
  - **RAM-Only Volatile OAuth:** Credentials and access tokens remain strictly in RAM and are permanently purged upon exit.

- **Automatic Silent Self-Healing:**
  - Entering your master password silently verifies and repairs any broken, orphaned, or externally deleted files in the manifest without disruptive error dialogs.

---

## 🔒 Security Architecture

| Security Layer | Cryptographic Specification |
| :--- | :--- |
| **Key Derivation Function** | **Argon2id** (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`) |
| **Master Vault Key (MVK)** | 256-bit CSPRNG (`os.urandom`) |
| **Key Wrapping** | **AES-256-GCM** with unique 96-bit IV and authentication tag |
| **Per-File Key Derivation** | **HKDF-SHA256** (File UUID as salt, MVK as Input Key Material) |
| **Chunked File Encryption** | **64 KB AEAD chunks** with AES-256-GCM, independent IVs, and chunk index AAD |
| **Integrity Verification** | Per-file **SHA-256** checksums recorded in encrypted manifest |

---

## 🚀 Quickstart & Setup

### Prerequisites
- **Python:** 3.9+
- **Linux:** FUSE 3 (`sudo apt install libfuse3-3 fuse3` on Debian/Ubuntu, pre-installed on most modern distributions).
- **Windows:** Zero external drivers needed.

### 1. Clone the Repository
```bash
git clone https://github.com/Fungus12th/crypton.git
cd crypton
```

### 2. Set Up Virtual Environment & Dependencies
```bash
# On Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# On Windows:
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

---

## 💻 Usage

### A. Launching the GUI
Simply run `crypton` (or launch `crypton/main.py`):
```bash
crypton
```
1. **Initial Setup:** Enter a master password to initialize and protect a new pendrive.
2. **Unlock Vault:** Enter your password to mount your vault.
3. **Manage Files:** Open your native file manager to view and edit files transparently.
4. **Lock & Close:** Click **Lock & Safely Close** to flush all background writes, unmount the drive, and purge keys from memory.

### B. Command-Line Interface (CLI)
Crypton includes a comprehensive CLI for headless setups and automation:

```bash
# Initialize a new vault on a drive
crypton init /media/user/MY_USB

# Display public vault header metadata
crypton info /media/user/MY_USB

# Inspect or adjust RAM staging limit (e.g. 64 MB)
crypton config /media/user/MY_USB --ram-limit 64

# Add and encrypt a file directly
crypton add confidential.pdf --drive /media/user/MY_USB

# List encrypted files in vault
crypton list /media/user/MY_USB

# Decrypt and extract a file
crypton extract confidential.pdf ./restored.pdf --drive /media/user/MY_USB

# Change master password instantly (<100ms)
crypton change-password /media/user/MY_USB
```

---

## 📦 Building Standalone Executables (PyInstaller)

Crypton can be compiled into standalone, zero-dependency executables that run directly off a USB drive without Python installed:

### Linux Binary
```bash
pyinstaller crypton-linux.spec --noconfirm
```
The compiled binary will be placed in `dist/crypton-linux`.

### Windows Executable
On Windows, double-click **`build-windows.bat`** (or `REBUILD_WINDOWS_EXE.bat`). It will install necessary dependencies and compile `Crypton.exe` in one click.

---

## 🧪 Automated Testing

Crypton includes a comprehensive test suite covering Argon2id key derivation, key wrapping, chunked tamper detection, vault lifecycle, directional cloud sync, and filesystem mounting:

```bash
pytest -v
```

All 16 unit tests execute in under 3 seconds.

---

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.
