# Crypton 🛡️

<p align="center">
  <img src="crypton.png" width="128" height="128" alt="Crypton Logo">
</p>

<p align="center">
  <strong>Cross-Platform Portable Encrypted USB Vault &amp; Zero-Knowledge Cloud Tool</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Version-v1.1.0-brightgreen" alt="Version">
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue" alt="Platform">
  <img src="https://img.shields.io/badge/Security-AES--256--GCM-success" alt="Cipher">
  <img src="https://img.shields.io/badge/KDF-Argon2id-orange" alt="KDF">
  <img src="https://img.shields.io/badge/Architecture-Zero--Admin%20Portable-blueviolet" alt="Architecture">
</p>

---

## 🌟 Overview

**Crypton** is a portable, zero-installation encrypted vault application designed to live directly on generic USB flash drives. It allows you to unlock, browse, edit, and stream your private files on both Linux and Windows with **zero administrative privileges** and **zero host footprint**.

Unlike conventional full-disk encryption (such as BitLocker or LUKS) which locks you into a single operating system, or tools like VeraCrypt which require installing kernel-level drivers with administrator rights, Crypton runs entirely in user-space:
- On **Linux**, it mounts as a transparent virtual folder (`Vault_Unlocked`) using Linux FUSE.
- On **Windows**, it mounts as a native drive letter (`Z:\`) using an embedded localhost WebDAV streaming engine backed by Windows's built-in WebClient service.

Behind the scenes, files are chunked and encrypted on the fly using **AES-256-GCM** authenticated encryption with keys derived via **Argon2id**. When you click **Lock & Safely Close**, all virtual drives detach, encryption keys are wiped from volatile memory, and no plaintext footprint remains on the host machine.

---

## 🚀 Key Features

### Zero-Footprint WebDAV Streaming (Windows)
Replaces legacy upfront drive unpacking. Crypton hosts an in-memory WebDAV server bound to an ephemeral loopback port (`127.0.0.1:0`). When you unlock your vault, files are **never** decrypted upfront to the host `C:\` drive. Directory trees and metadata are read directly from memory, and 64 KB AES-256-GCM chunks are decrypted on-demand only when a file or media stream is requested.

### Transparent FUSE Filesystem (Linux)
Mounts seamlessly on Linux using user-space FUSE. Files appear directly in your file manager (GNOME Files, Dolphin, Thunar) and can be dragged, opened, or edited in place with zero delay.

### Read-Only "Paranoia" Mode
When plugging into untrusted public computers (e.g., college computer labs or internet cafes), activate **Paranoia Mode** on the unlock screen. Crypton strictly enforces read-only access at the filesystem layer (`EROFS` on Linux, `HTTP_FORBIDDEN` on Windows), preventing malware or ransomware on the host PC from creating, altering, or deleting files in your vault.

### Real-Time "Safe to Unplug" Telemetry
Avoid data corruption caused by premature USB removal. Crypton continuously tracks background write-back encryption workers, displaying a live progress bar:
- `✔ All Data Flushed to USB — Safe to Lock / Unplug` (Emerald Green)
- `⚡ Syncing to USB: X% (N chunks left) — DO NOT UNPLUG` (Crimson Warning)
Clicking the lock button safely drains any in-flight write operations before unmounting.

### Zero-Knowledge Cloud Backup (Google Drive)
Optionally synchronize your vault directly with Google Drive. Google only ever receives encrypted, scrambled ciphertext blocks. OAuth tokens are stored purely in volatile RAM and are wiped the moment the application closes.

### Instant Master Password Rotation (<100ms)
Change your master vault password in milliseconds without re-encrypting a single file. Crypton uses envelope encryption: Argon2id wraps a 256-bit Master Vault Key (MVK), which in turn derives per-file keys via HKDF-SHA256.

---

## 💾 Hardware Reality & Write-Back Caching

USB flash memory drives (especially budget thumb drives formatted to FAT32) suffer from notoriously poor 4 KB random-write performance—often dropping below 1 MB/s when saving documents or small files—alongside strictly limited NAND flash cell endurance.

Crypton does not claim to magically alter the physical write limits of flash silicon. Instead, it employs an **asynchronous RAM write-back cache** designed to protect your hardware and keep your workflow smooth:

1. **Protects Flash NAND Lifespan**: Instead of punishing the USB drive with thousands of fragmented 4 KB random writes, incoming changes are briefly buffered in volatile system RAM (`/dev/shm` on Linux, in-memory buffers on Windows).
2. **Sequential Batch Writes**: Buffered data is packaged into sequential, authenticated 64 KB AES-256-GCM blocks and flushed to the USB storage by background worker pools, significantly reducing flash cell wear.
3. **Responsive UI**: File managers do not freeze during drag-and-drop operations, and the live flush tracker keeps you informed of the exact moment physical writes are safely committed to disk.

---

## 🔒 Security Architecture

| Security Layer | Specification | Implementation Detail |
| :--- | :--- | :--- |
| **Key Derivation Function (KDF)** | **Argon2id** | `memory_cost=64MB`, `time_cost=3`, `parallelism=4` (GPU/ASIC-resistant) |
| **Master Vault Key (MVK)** | 256-bit CSPRNG | Generated via `os.urandom(32)` |
| **Key Wrapping** | **AES-256-GCM** | 96-bit unique IV, 128-bit authentication tag |
| **Per-File Key Derivation** | **HKDF-SHA256** | Salted with unique File UUID, derived from MVK |
| **Data Block Encryption** | **AES-256-GCM (64 KB Chunks)** | Per-chunk monotonic nonce counter + chunk index AAD |
| **Manifest Security** | Encrypted JSON (`manifest.enc`) | Signed and authenticated with dedicated manifest sub-key |
| **Memory Security** | Volatile RAM Only | Master keys and OAuth tokens purged on vault lock and window close |

---

## 📥 Getting Started

### Method 1: Portable Executable (No Python Required)
You can launch Crypton directly from the root of your USB drive:
- **Windows:** Double-click `Crypton.exe` (or run `BUILD_WINDOWS_CRYPTON.bat` to build locally).
- **Linux:** Run `./crypton-linux.exe` directly from the drive.

### Method 2: Running from Source

```bash
# 1. Clone the repository
git clone https://github.com/Fungus12th/crypton.git
cd crypton

# 2. Install dependencies
pip install .

# 3. Launch the GUI
crypton
```

---

## 💻 Command-Line Interface

For server environments, headless machines, or script automation:

```bash
# Initialize a new vault on a pendrive
crypton init /media/user/MY_USB

# View public vault header metadata
crypton info /media/user/MY_USB

# Unlock and verify master password
crypton unlock /media/user/MY_USB

# Encrypt and add a file into the vault
crypton add document.pdf --drive /media/user/MY_USB

# List encrypted files in vault
crypton list /media/user/MY_USB

# Decrypt and extract a file to your local drive
crypton extract document.pdf ./restored.pdf --drive /media/user/MY_USB

# Rotate vault password in milliseconds
crypton change-password /media/user/MY_USB
```

---

## ⚙️ Building Standalone Binaries

Crypton includes automated PyInstaller build configurations for both platforms:

### Linux Binary
```bash
pyinstaller crypton-linux.spec --noconfirm
# Output located at: dist/crypton-linux
```

### Windows Binary
On Windows, run the included batch script:
```cmd
build-windows.bat
# Automatically builds dist\crypton-windows.exe and updates Crypton.exe
```
