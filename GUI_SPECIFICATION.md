# 🎨 Crypton GUI Specification & Visual Parity Guide
> **To the Windows Antigravity Agent:**
> This document provides the complete, component-by-component, pixel-accurate blueprint of the Linux CustomTkinter GUI. Use this guide to ensure 100% visual and functional parity between Windows and Linux.

---

## 1. Global Window Configuration

| Property | Value | Notes |
| :--- | :--- | :--- |
| **Framework** | `customtkinter` (CTk) | `ctk.set_appearance_mode("Dark")`, `ctk.set_default_color_theme("blue")` |
| **Window Size** | `560 x 440` | `self.geometry("560x440")` |
| **Minimum Size** | `520 x 400` | `self.minsize(520, 400)` |
| **Window Title** | `"Crypton - Secure USB Vault"` | |
| **Window Icon** | `crypton.ico` (Win) / `crypton.png` (Linux) | Handled by `set_window_icon(window)` using assets in `crypton/assets/` |
| **Dark Title Bar** | `apply_dark_title_bar(window)` | Enabled on Windows via DWM API (`DwmSetWindowAttribute`) |
| **Exit Hook** | `WM_DELETE_WINDOW` | Calls `on_window_close`: safely unmounts filesystem and purges OAuth credentials from RAM |

---

## 2. Layout Structure

The app window has two main vertical sections:
```text
+-------------------------------------------------------------+
| Top Bar Frame (Drive path, "Change Drive", "⚙️ Dev")         |
+-------------------------------------------------------------+
| Content Container Frame (Dynamically swapped per state)      |
|                                                             |
|   [State 1: Initial Setup / Vault Creation]                 |
|      -- OR --                                               |
|   [State 2: Vault Locked]                                   |
|      -- OR --                                               |
|   [State 3: Vault Unlocked]                                 |
|                                                             |
+-------------------------------------------------------------+
```

### A. Top Bar (`top_frame`)
- `top_frame = ctk.CTkFrame(self, corner_radius=10)`
- `pack(fill="x", padx=15, pady=10)`
- **Widgets inside `top_frame`**:
  1. `lbl_path`:
     - `text=f"Drive: {self.drive_path}"`
     - `font=ctk.CTkFont(size=13, weight="bold")`
     - `pack(side="left", padx=15, pady=10, expand=True, fill="x")`
  2. `btn_select_drive`:
     - `text="Change Drive"`, `width=100`, `height=30`
     - `command=self.change_drive`
     - `pack(side="right", padx=(5, 10), pady=10)`
  3. `btn_dev`:
     - `text="⚙️ Dev"`, `width=65`, `height=30`, `fg_color="#34495e"`
     - `command=self.open_dev_settings`
     - `pack(side="right", padx=5, pady=10)`

### B. Content Container (`content_container`)
- `content_container = ctk.CTkFrame(self, corner_radius=10)`
- `pack(fill="both", expand=True, padx=15, pady=(0, 15))`
- Cleared and re-rendered on every state transition via `refresh_state()`.

---

## 3. The Three Dynamic Views

### View 1: Initial Setup / Vault Creation (`render_init_view`)
*Shown when the selected directory does NOT have a `.crypton/vault.header`.*
1. **Title**: `"Create Encrypted Vault"`, `font=ctk.CTkFont(size=18, weight="bold")`, `pady=(20, 5)`.
2. **Subtitle**: `"Choose a strong master password to secure this drive."`, `font=ctk.CTkFont(size=12)`, `text_color="gray70"`, `pady=(0, 15)`.
3. **Password Input**: `entry_init_pwd`, `placeholder_text="Enter Master Password"`, `show="*"`, `width=280`, `height=38`, `pady=6`.
4. **Confirm Input**: `entry_init_confirm`, `placeholder_text="Confirm Master Password"`, `show="*"`, `width=280`, `height=38`, `pady=6`.
5. **Status Label**: `lbl_init_status`, `font=ctk.CTkFont(size=11)`, `pady=4`.
6. **Primary Button**: `btn_init`, `text="Initialize Secure Vault"`, `width=280`, `height=42`, `font=ctk.CTkFont(weight="bold")`, `pady=10`.
7. **Cloud Restore Link**: `btn_cloud_restore`, `text="☁️ Or restore existing vault from Google Drive"`, `fg_color="transparent"`, `text_color="#3498db"`, `font=ctk.CTkFont(size=12)`.

---

### View 2: Vault Locked (`render_locked_view`)
*Shown when `.crypton/vault.header` exists, but the vault has not been unlocked (`mvk is None`).*
1. **Lock Icon**: `text="🔒"`, `font=ctk.CTkFont(size=36)`, `pady=(25, 5)`.
2. **Title**: `"Encrypted Vault Detected"`, `font=ctk.CTkFont(size=18, weight="bold")`, `pady=(0, 5)`.
3. **Subtitle**: `"Enter your master password to unlock and access files."`, `font=ctk.CTkFont(size=12)`, `text_color="gray70"`, `pady=(0, 15)`.
4. **Password Input**: `entry_unlock_pwd`, `placeholder_text="Master Password"`, `show="*"`, `width=280`, `height=38`, `pady=8`.
   - Binds `<Return>` to `handle_unlock()`.
5. **Status Label**: `lbl_unlock_status`, `font=ctk.CTkFont(size=11)`, `pady=2`.
6. **Primary Unlock Button**:
   - `btn_unlock`: `text="🔓 Unlock & Open Drive"`
   - `font=ctk.CTkFont(size=14, weight="bold")`, `width=280`, `height=44`
   - `command=self.handle_unlock`, `pady=10`.
7. **Cloud Backup Link**:
   - `btn_cloud`: `text="☁️ Cloud Backup & Restore"`
   - `fg_color="#2c3e50"`, `hover_color="#34495e"`, `width=240`, `height=34`, `font=ctk.CTkFont(size=12)`
   - `command=self.handle_gdrive_sync`, `pady=4`.

---

### View 3: Vault Unlocked (`render_unlocked_view`)
*Shown when master password is authenticated and virtual drive is mounted.*
1. **Status Bullet**:
   - `text="●"` (Unicode bullet U+25CF)
   - `font=ctk.CTkFont(size=40)`, `text_color="#2ecc71"` (Vibrant Green)
   - *Cross-Platform Note*: Avoid using `🟢` (emoji) as Windows renders it as a hatched gray circle. `●` renders crisply on both OSes.
2. **Title**: `"Vault Unlocked & Active"`, `font=ctk.CTkFont(size=20, weight="bold")`, `text_color="#2ecc71"`, `pady=(0, 6)`.
3. **Mounted Drive Subtitle**:
   - `text=f"Mounted: {self.mountpoint}"` (`Z:\` on Windows; `/Vault_Unlocked` on Linux)
   - `font=ctk.CTkFont(size=12)`, `text_color="gray70"`, `pady=(0, 15)`.
4. **Explanatory Tip**:
   - `text="✨ Use your normal file manager to drag & drop, view, or edit files.\nEverything is encrypted transparently on the fly."`
   - `font=ctk.CTkFont(size=12)`, `text_color="gray80"`, `justify="center"`, `pady=(0, 25)`.
5. **Primary Action 1 (Open Explorer)**:
   - `btn_open`: `text="📂 Open in File Manager"`
   - `font=ctk.CTkFont(size=14, weight="bold")`, `width=260`, `height=42`
   - Calls `os.startfile(self.mountpoint)` on Windows / `xdg-open` on Linux.
6. **Primary Action 2 (Lock & Safely Close)**:
   - `btn_lock`: `text="🔒 Lock & Safely Close"`
   - `fg_color="#e74c3c"`, `hover_color="#c0392b"` (Vibrant Red)
   - `font=ctk.CTkFont(size=14, weight="bold")`, `width=260`, `height=42`
   - Unmounts virtual drive, flushes dirty cache, and wipes MVK.
7. **Cloud Sync Action (Unlocked)**:
   - `btn_gdrive`: `text="☁️ Sync with Google Drive (Optional)"`
   - `fg_color="#2c3e50"`, `hover_color="#34495e"` (Dark Slate)
   - `font=ctk.CTkFont(size=12)`, `width=260`, `height=34`, `pady=(12, 10)`
   - Opens the GDriveSyncDialog.

---

## 4. Modal Dialogs

### Modal A: Developer & Performance Settings (`DeveloperSettingsDialog`)
- **Dimensions**: `490 x 420`, non-resizable, transient, `grab_set()`.
- **Title**: `"Developer & Performance Settings"`.
- **Header**: `"⚡ RAM Staging & Performance"`, `font=ctk.CTkFont(size=18, weight="bold")`.
- **Description**: 3 lines explaining RAM staging to bypass flash write penalties.
- **System Memory Box**:
  - `info_frame`: Corner radius 8, `fill="x"`, `padx=25`, `pady=5`.
  - Blue label (`#3498db`):
    - Windows: `🖥️ System RAM: X MB available` (from `GlobalMemoryStatusEx`).
    - Linux: `🖥️ PC Fast RAM Cache (/dev/shm): X MB free`.
- **Dropdown**:
  - Options: `["16 MB", "32 MB (Default)", "64 MB", "128 MB", "256 MB", "512 MB", "1024 MB (1 GB)"]`.
- **Save Button**:
  - `"Save Performance Settings"`, `fg_color="#27ae60"`, `hover_color="#219150"`, `width=220`, `height=38`.

---

### Modal B: Google Drive Cloud Sync (`GDriveSyncDialog`)
- **Dimensions**: `560 x 540`, non-resizable, transient, `grab_set()`.
- **Title**: `"Google Drive Cloud Sync"`.
- **Header**: `"☁️ Google Drive Zero-Knowledge Sync"`, `font=ctk.CTkFont(size=18, weight="bold")`.
- **Subtitle**: 2 lines noting zero-knowledge ciphertext and in-memory credentials.
- **Credentials Bar**:
  - Frame with status: `"✔ client_secrets.json loaded"` (`#2ecc71`) or `"⚠️ client_secrets.json needed"` (`#f39c12`).
  - Button: `"📂 Load client_secrets.json"`, `width=170`, `height=30`.
- **Sync Status Card (`status_frame`)**:
  - `lbl_local_info`: `💾 USB Pendrive: X chunks`
  - `lbl_cloud_info`: `☁️ Google Drive: Y chunks`
  - `lbl_delta_info`: `Pending: A to upload | B to download (C synced)`
  - Button: `🔄 Refresh Status`, `width=120`, `height=26`.
- **Progress Section**:
  - `progress_bar`: `ctk.CTkProgressBar(height=10, corner_radius=5)`.
  - `lbl_step`: Bold status text (e.g. `"Syncing with Local Data..."`).
  - `lbl_details`: Smaller gray detail text.
- **The Two Directional Sync Buttons (`action_frame`)**:
  - Horizontal side-by-side layout:
    ```text
    +--------------------------------+  +--------------------------------+
    |    💾 Sync with Local Data    |  |    ☁️ Sync with Cloud Data     |
    |  (USB Master - Push to Cloud)  |  |  (Cloud Master - Pull to USB)  |
    +--------------------------------+  +--------------------------------+
    ```
  - **Left Button (`btn_sync_local`)**:
    - Label: `text="💾 Sync with Local Data"`
    - Color: `fg_color="#2980b9"`, `hover_color="#1f618d"` (Deep Blue).
    - Role: USB is Master. Uploads new chunks; deletes deleted chunks from Google Drive.
  - **Right Button (`btn_sync_cloud`)**:
    - Label: `text="☁️ Sync with Cloud Data"`
    - Color: `fg_color="#27ae60"`, `hover_color="#219150"` (Vibrant Green).
    - Role: Cloud is Master. Pulls missing chunks to USB; prunes local obsolete chunks.
- **Bottom Button**:
  - `btn_close`: `text="Done"`, `width=120`, `height=32`, `fg_color="gray30"`.

---

## 5. Summary Palette Quick Reference

| Role | Color Hex | Hover Hex |
| :--- | :--- | :--- |
| **Accent / Focus Blue** | `#3498db` | `#2980b9` |
| **Local Sync Button (Blue)** | `#2980b9` | `#1f618d` |
| **Cloud Sync Button (Green)**| `#27ae60` | `#219150` |
| **Lock / Destructive (Red)** | `#e74c3c` | `#c0392b` |
| **Secondary / Subtle (Slate)**| `#2c3e50` | `#34495e` |
| **Status Bullet (Green)**    | `#2ecc71` | N/A |
| **Warning / Amber**          | `#f39c12` | N/A |
| **Subtext / Gray**           | `gray70` / `gray80` | N/A |
