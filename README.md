# Crypton 🛡️

> **Secure, Zero-Friction USB Vault and Cloud Backup Tool**

Crypton turns any generic USB flash drive into a password-protected encrypted vault with transparent, on-the-fly filesystem mounting and automated self-healing.

---

## ✨ Features

- **Transparent On-the-Fly Mounting (FUSE):** Unlocking your drive mounts a virtual filesystem (`Vault_Unlocked`). Drag and drop, view, or edit files normally in your native file manager (Nautilus, Dolphin, Explorer)—encryption happens invisibly in real-time.
- **Fast RAM Staging Pipeline:** USB flash memory has notoriously slow write speeds (1–2 MB/s). Staging writes through high-speed memory (`/dev/shm`) eliminates double-write penalties and doubles copy speeds.
- **Auto Self-Healing:** Entering your master password silently detects and repairs any orphaned or externally deleted files in the encrypted manifest without annoying prompt dialogs.
- **Envelope Encryption (Key Wrapping):**
  - Master Vault Key (MVK): 256-bit AES-GCM.
  - Key Derivation: **Argon2id** (GPU/ASIC-resistant memory-hard KDF).
  - Password change in **<100ms** (only the 32-byte MVK is re-wrapped; files are never re-encrypted).
- **Chunked Authenticated Streaming:** Files are split into 64 KB authenticated chunks with HKDF-derived keys and Additional Authenticated Data (AAD) tracking chunk indexes to prevent block tampering and reordering.
- **Developer & Performance Settings:** Live `/dev/shm` RAM inspector and customizable RAM staging limits (`16MB` to `1024MB`).

---

## 🚀 Quickstart & Setup

### Prerequisites
- **Python:** 3.9 or higher
- **Linux:** FUSE (`libfuse3` or `fuse3`, pre-installed on most distributions):
  ```bash
  # Ubuntu / Debian
  sudo apt install libfuse3-3 fuse3
  ```

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/crypton.git
cd crypton
```

### 2. Create Virtual Environment & Install
```bash
# On Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# On Windows:
python -m venv .venv
.venv\Scripts\activate

# Install Crypton and development tools
pip install -e ".[dev]"
```

---

## 💻 Usage

### A. Launching the GUI
Simply run `crypton` without arguments (or with `--gui`):
```bash
crypton
```
- Select your target drive.
- Enter your password to unlock.
- The vault will mount to `Vault_Unlocked` and automatically pop open your native file manager.

### B. Command-Line Interface (CLI)
Crypton provides a rich CLI for automation and headless setups:

```bash
# Initialize a new vault on a pendrive
crypton init /media/user/MY_USB

# View public header metadata (salt, parameters, creation date)
crypton info /media/user/MY_USB

# Inspect or adjust RAM staging limit
crypton config /media/user/MY_USB --ram-limit 64

# Encrypt and add a file directly
crypton add sensitive.pdf --drive /media/user/MY_USB

# List encrypted files in vault
crypton list /media/user/MY_USB

# Decrypt and extract a file
crypton extract sensitive.pdf ./restored.pdf --drive /media/user/MY_USB

# Change master password instantly (<100ms)
crypton change-password /media/user/MY_USB
```

---

## 📦 Building Standalone Executables (PyInstaller)

To build a zero-dependency standalone binary that can run directly off a thumb drive:

```bash
pyinstaller crypton-linux.spec --clean
```
The compiled binary will be in `dist/crypton-linux`. You can copy it to your USB drive as `crypton-linux.exe` (on FAT32, the `.exe` extension ensures execution permissions on Linux while hiding it in Windows Explorer).

---

## 🧪 Running Automated Tests

Run the full automated test suite (Argon2id KDF, HKDF, chunked streaming tamper tests, vault lifecycle, recursive folder extraction, FUSE mount I/O, RAM staging):

```bash
pytest -v
```

---

## 🔒 Security Architecture

| Component | Specification |
|---|---|
| Key Derivation Function | Argon2id (`time_cost=3`, `memory_cost=64MB`, `parallelism=4`) |
| Master Vault Key (MVK) | 256-bit CSPRNG (`os.urandom`) |
| Key Wrapping | AES-256-GCM |
| Per-File Key Derivation | HKDF-SHA256 (File UUID as salt, MVK as IKM) |
| File Cipher | 64 KB Chunked AES-256-GCM with AAD tracking chunk index |
