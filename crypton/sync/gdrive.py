import os
import sys
import gc
import json
import io
from typing import Optional, Dict, Any, Callable, Tuple
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from googleapiclient.errors import HttpError

from crypton.core.vault import VaultManager, VaultError

# Least-privilege scope: access ONLY files created or opened by Crypton
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

# Root remote backup folder name in Google Drive
REMOTE_ROOT_FOLDER_NAME = "Crypton_Vault_Backups"
REMOTE_DATA_FOLDER_NAME = "data"

# Default Desktop Client credentials configuration template
# Users can provide their own credentials via client_secrets.json or environment variable
DEFAULT_CLIENT_CONFIG = {
    "installed": {
        "client_id": os.environ.get("CRYPTON_GDRIVE_CLIENT_ID", "108394857291-placeholder.apps.googleusercontent.com"),
        "client_secret": os.environ.get("CRYPTON_GDRIVE_CLIENT_SECRET", "GOCSPX-placeholder"),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "redirect_uris": ["http://localhost"],
    }
}


class GDriveAuthError(VaultError):
    """Raised when Google Drive authentication fails."""
    pass


class GDriveSyncError(VaultError):
    """Raised when Google Drive synchronization fails."""
    pass


class GDriveAuth:
    """Manages ephemeral in-memory OAuth2 lifecycle for Google Drive.
    
    Security Guarantee:
    Credentials tokens are kept strictly in RAM and are NEVER written to the
    USB drive or disk. When the session ends, credentials can be explicitly wiped.
    """

    def __init__(self, client_config: Optional[Dict[str, Any]] = None, drive_path: Optional[str] = None):
        self.drive_path = drive_path
        self.client_config = client_config or self._load_client_config(drive_path)
        self._creds: Optional[Credentials] = None

    @classmethod
    def find_client_config_file(cls, drive_path: Optional[str] = None) -> Optional[str]:
        """Automatically find client_secrets.json or downloaded credentials in common locations."""
        search_dirs = []
        if drive_path and os.path.isdir(drive_path):
            search_dirs.append(drive_path)
            search_dirs.append(os.path.join(drive_path, ".crypton"))

        search_dirs.extend([
            os.getcwd(),
            os.path.dirname(os.path.abspath(sys.argv[0])),
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~"),
        ])

        for d in search_dirs:
            if not os.path.isdir(d):
                continue
            # Check for client_secrets.json, credentials.json, or client_secret_*.json
            candidates = ["client_secrets.json", "credentials.json"]
            try:
                for fname in os.listdir(d):
                    if fname.startswith("client_secret") and fname.endswith(".json"):
                        candidates.insert(0, fname)
            except OSError:
                continue

            for c in candidates:
                full_path = os.path.join(d, c)
                if os.path.isfile(full_path):
                    try:
                        with open(full_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                            if "installed" in data or "web" in data:
                                return full_path
                    except Exception:
                        pass
        return None

    @classmethod
    def _load_client_config(cls, drive_path: Optional[str] = None) -> Dict[str, Any]:
        """Load client configuration from environment or discovered secrets file."""
        env_config = os.environ.get("CRYPTON_GDRIVE_CLIENT_CONFIG")
        if env_config:
            try:
                return json.loads(env_config)
            except Exception:
                pass

        found_file = cls.find_client_config_file(drive_path)
        if found_file:
            try:
                with open(found_file, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass

        return DEFAULT_CLIENT_CONFIG

    def has_valid_client_config(self) -> bool:
        """Return True if real client credentials are loaded (not placeholder)."""
        if not self.client_config:
            return False
        cfg = self.client_config.get("installed") or self.client_config.get("web") or {}
        client_id = cfg.get("client_id", "")
        return bool(client_id and "placeholder" not in client_id)

    def set_client_config_from_file(self, file_path: str) -> bool:
        """Load configuration from an explicit file chosen by user."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if "installed" in data or "web" in data:
                    self.client_config = data
                    return True
        except Exception:
            pass
        return False

    def authenticate(self, port: int = 0) -> Credentials:
        """Launch local browser consent flow and capture tokens strictly into RAM."""
        if not self.has_valid_client_config():
            raise GDriveAuthError(
                "Google OAuth credentials not configured.\n"
                "Please download your client_secrets.json from Google Cloud Console and load it."
            )

        if self._creds and self._creds.valid:
            return self._creds

        if self._creds and self._creds.expired and self._creds.refresh_token:
            try:
                self._creds.refresh(Request())
                return self._creds
            except Exception:
                self._creds = None

        try:
            flow = InstalledAppFlow.from_client_config(self.client_config, scopes=SCOPES)
            # Runs local loopback server to receive the authorization code
            self._creds = flow.run_local_server(port=port, prompt="consent")
            return self._creds
        except Exception as e:
            raise GDriveAuthError(f"Google Drive authentication failed: {e}")

    def get_credentials(self) -> Credentials:
        if not self._creds or not self._creds.valid:
            return self.authenticate()
        return self._creds

    def is_authenticated(self) -> bool:
        return self._creds is not None and self._creds.valid

    def wipe_credentials(self) -> None:
        """Immediately purge credentials from RAM."""
        self._creds = None
        gc.collect()


class GDriveSync:
    """Zero-Knowledge Cloud Backup Engine.
    
    Synchronizes encrypted vault chunks and headers to Google Drive.
    Google only ever sees scrambled AES-256-GCM ciphertext chunks.
    """

    def __init__(self, auth: Optional[GDriveAuth] = None):
        self.auth = auth or GDriveAuth()
        self._service = None
        self._remote_folder_cache: Dict[str, str] = {}

    def get_service(self):
        if not self._service:
            creds = self.auth.get_credentials()
            self._service = build("drive", "v3", credentials=creds, cache_discovery=False)
        return self._service

    def get_or_create_remote_folders(self) -> Tuple[str, str]:
        """Locate or create 'Crypton_Vault_Backups' and subfolder 'data' in Google Drive."""
        service = self.get_service()

        # 1. Find or create root folder
        query = (
            f"name = '{REMOTE_ROOT_FOLDER_NAME}' and "
            f"mimeType = 'application/vnd.google-apps.folder' and "
            f"trashed = false"
        )
        res = service.files().list(q=query, spaces="drive", fields="files(id, name)").execute()
        files = res.get("files", [])

        if files:
            root_id = files[0]["id"]
        else:
            meta = {
                "name": REMOTE_ROOT_FOLDER_NAME,
                "mimeType": "application/vnd.google-apps.folder",
            }
            folder = service.files().create(body=meta, fields="id").execute()
            root_id = folder["id"]

        # 2. Find or create 'data' subfolder inside root
        sub_query = (
            f"name = '{REMOTE_DATA_FOLDER_NAME}' and "
            f"'{root_id}' in parents and "
            f"mimeType = 'application/vnd.google-apps.folder' and "
            f"trashed = false"
        )
        sub_res = service.files().list(q=sub_query, spaces="drive", fields="files(id, name)").execute()
        sub_files = sub_res.get("files", [])

        if sub_files:
            data_id = sub_files[0]["id"]
        else:
            sub_meta = {
                "name": REMOTE_DATA_FOLDER_NAME,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [root_id],
            }
            data_folder = service.files().create(body=sub_meta, fields="id").execute()
            data_id = data_folder["id"]

        return root_id, data_id

    def get_or_create_remote_path(self, base_folder_id: str, rel_dir_path: str) -> str:
        """Ensure nested directory hierarchy exists in Google Drive and return leaf folder ID."""
        if not rel_dir_path:
            return base_folder_id

        current_parent = base_folder_id
        service = self.get_service()
        parts = [p for p in rel_dir_path.replace("\\", "/").strip("/").split("/") if p]

        for part in parts:
            cache_key = f"{current_parent}/{part}"
            if cache_key in self._remote_folder_cache:
                current_parent = self._remote_folder_cache[cache_key]
                continue

            safe_part = part.replace("'", "\\'")
            q = (
                f"name = '{safe_part}' and "
                f"'{current_parent}' in parents and "
                f"mimeType = 'application/vnd.google-apps.folder' and "
                f"trashed = false"
            )
            res = service.files().list(q=q, spaces="drive", fields="files(id)").execute()
            files = res.get("files", [])

            if files:
                folder_id = files[0]["id"]
            else:
                meta = {
                    "name": part,
                    "parents": [current_parent],
                    "mimeType": "application/vnd.google-apps.folder",
                }
                created = service.files().create(body=meta, fields="id").execute()
                folder_id = created["id"]

            self._remote_folder_cache[cache_key] = folder_id
            current_parent = folder_id

        return current_parent

    def clean_erroneous_flat_chunks(self, data_folder_id: str) -> int:
        """Delete any old flat files containing slashes directly under the data folder."""
        service = self.get_service()
        cleaned = 0
        page_token = None
        query = f"'{data_folder_id}' in parents and trashed = false"
        while True:
            res = service.files().list(
                q=query,
                spaces="drive",
                fields="nextPageToken, files(id, name, mimeType)",
                pageToken=page_token,
                pageSize=1000,
            ).execute()
            for f in res.get("files", []):
                if f.get("mimeType") != "application/vnd.google-apps.folder" and "/" in f.get("name", ""):
                    try:
                        service.files().delete(fileId=f["id"]).execute()
                        cleaned += 1
                    except Exception:
                        pass
            page_token = res.get("nextPageToken")
            if not page_token:
                break
        return cleaned

    def list_remote_chunks(self, data_folder_id: str) -> Dict[str, str]:
        """Recursively list all encrypted chunks in Google Drive data folder and subfolders.
        
        Returns:
            Dict mapping relative chunk path (e.g. 'fae30af0c2eab586/uuid') -> file_id
        """
        service = self.get_service()
        chunks = {}
        queue = [("", data_folder_id)]

        while queue:
            rel_dir, current_parent_id = queue.pop(0)
            page_token = None
            query = f"'{current_parent_id}' in parents and trashed = false"

            while True:
                res = service.files().list(
                    q=query,
                    spaces="drive",
                    fields="nextPageToken, files(id, name, mimeType)",
                    pageToken=page_token,
                    pageSize=1000,
                ).execute()

                for f in res.get("files", []):
                    is_folder = f.get("mimeType") == "application/vnd.google-apps.folder"
                    if is_folder:
                        sub_rel = f"{rel_dir}/{f['name']}".lstrip("/")
                        queue.append((sub_rel, f["id"]))
                    else:
                        if current_parent_id == data_folder_id and "/" in f["name"]:
                            continue
                        chunk_rel = f"{rel_dir}/{f['name']}".lstrip("/")
                        chunks[chunk_rel] = f["id"]

                page_token = res.get("nextPageToken")
                if not page_token:
                    break

        return chunks

    @classmethod
    def get_all_local_chunks(cls, local_data_dir: str) -> list[str]:
        """Recursively scan local_data_dir and return all relative chunk paths (POSIX slashes)."""
        chunks = []
        if not os.path.isdir(local_data_dir):
            return chunks
        for root, _, files in os.walk(local_data_dir):
            for f in files:
                full_path = os.path.join(root, f)
                rel = os.path.relpath(full_path, local_data_dir).replace("\\", "/")
                chunks.append(rel)
        return sorted(chunks)

    def download_file_by_id(self, file_id: str, dest_path: str) -> None:
        """Atomically download a Google Drive file to dest_path."""
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        tmp_path = dest_path + ".tmp"
        service = self.get_service()
        request = service.files().get_media(fileId=file_id)
        with open(tmp_path, "wb") as fh:
            downloader = MediaIoBaseDownload(fh, request)
            done = False
            while not done:
                _, done = downloader.next_chunk()
        os.replace(tmp_path, dest_path)

    def upload_or_update_file(
        self,
        local_path: str,
        filename: str,
        parent_id: str,
        existing_id: Optional[str] = None,
    ) -> str:
        """Upload a file to Google Drive folder, updating if it already exists."""
        service = self.get_service()
        file_size = os.path.getsize(local_path)
        resumable = file_size > 5 * 1024 * 1024
        media = MediaFileUpload(local_path, mimetype="application/octet-stream", resumable=resumable)

        if existing_id:
            updated = service.files().update(fileId=existing_id, media_body=media, fields="id").execute()
            return updated["id"]

        safe_name = filename.replace("'", "\\'")
        query = f"name = '{safe_name}' and '{parent_id}' in parents and trashed = false"
        res = service.files().list(q=query, spaces="drive", fields="files(id)").execute()
        existing = res.get("files", [])

        if existing:
            file_id = existing[0]["id"]
            updated = service.files().update(fileId=file_id, media_body=media, fields="id").execute()
            return updated["id"]
        else:
            meta = {"name": filename, "parents": [parent_id]}
            created = service.files().create(body=meta, media_body=media, fields="id").execute()
            return created["id"]

    def get_sync_status(self, drive_path: str) -> Dict[str, Any]:
        """Inspect local vault and Google Drive to report pending delta counts."""
        local_data_dir = VaultManager.get_data_dir(drive_path)
        local_chunks = set(self.get_all_local_chunks(local_data_dir))

        root_id, data_id = self.get_or_create_remote_folders()
        self.clean_erroneous_flat_chunks(data_id)
        remote_chunks = self.list_remote_chunks(data_id)
        remote_chunk_names = set(remote_chunks.keys())

        to_upload = local_chunks - remote_chunk_names
        to_download = remote_chunk_names - local_chunks
        synced = local_chunks & remote_chunk_names

        return {
            "local_chunks": len(local_chunks),
            "cloud_chunks": len(remote_chunk_names),
            "pending_upload": len(to_upload),
            "pending_download": len(to_download),
            "in_sync": len(synced),
            "root_folder_id": root_id,
            "data_folder_id": data_id,
        }

    def clean_empty_remote_folders(self, data_folder_id: str) -> None:
        """Remove any subfolders under data_folder_id that contain 0 files."""
        service = self.get_service()
        q = f"'{data_folder_id}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
        res = service.files().list(q=q, spaces="drive", fields="files(id, name)").execute()
        for folder in res.get("files", []):
            f_id = folder["id"]
            child_q = f"'{f_id}' in parents and trashed = false"
            c_res = service.files().list(q=child_q, spaces="drive", fields="files(id)", pageSize=1).execute()
            if not c_res.get("files", []):
                try:
                    service.files().delete(fileId=f_id).execute()
                    self._remote_folder_cache.pop(f"{data_folder_id}/{folder['name']}", None)
                except Exception:
                    pass

    def sync_with_local(
        self,
        drive_path: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Sync with Local Data: Pendrive is Source of Truth.
        
        - Uploads new/modified local chunks to Google Drive.
        - Updates remote header and manifest to match local.
        - Deletes any remote chunks/folders that were deleted locally.
        """
        if not VaultManager.is_vault(drive_path):
            raise GDriveSyncError(f"No Crypton vault found at '{drive_path}'")

        header_path = VaultManager.get_header_path(drive_path)
        manifest_path = VaultManager.get_manifest_path(drive_path)
        local_data_dir = VaultManager.get_data_dir(drive_path)

        if progress_callback:
            progress_callback("Connecting to Google Drive...", 0, 100)

        root_id, data_id = self.get_or_create_remote_folders()
        self.clean_erroneous_flat_chunks(data_id)

        # 1. Upload Header and Manifest (Local is Master)
        if progress_callback:
            progress_callback("Syncing encrypted vault header...", 5, 100)
        self.upload_or_update_file(header_path, os.path.basename(header_path), root_id)

        if progress_callback:
            progress_callback("Syncing encrypted manifest...", 10, 100)
        self.upload_or_update_file(manifest_path, os.path.basename(manifest_path), root_id)

        # 2. Calculate Delta
        if progress_callback:
            progress_callback("Calculating differences between USB and Cloud...", 15, 100)

        remote_chunks = self.list_remote_chunks(data_id)
        local_chunks = self.get_all_local_chunks(local_data_dir)
        local_chunk_set = set(local_chunks)

        to_upload = [c for c in local_chunks if c not in remote_chunks]
        to_delete_remote = [c for c in remote_chunks if c not in local_chunk_set]

        total_ops = len(to_upload) + len(to_delete_remote)
        op_count = 0
        service = self.get_service()

        # 3. Upload Missing Local Chunks into Google Drive subfolders
        uploaded_count = 0
        for c in to_upload:
            op_count += 1
            pct = 20 + int((op_count / max(1, total_ops)) * 60)
            if progress_callback:
                progress_callback(
                    f"⬆️ Uploading chunk {uploaded_count + 1}/{len(to_upload)}: {os.path.basename(c)}...",
                    pct,
                    100,
                )

            chunk_path = os.path.join(local_data_dir, *c.split("/"))
            if not os.path.isfile(chunk_path):
                continue

            dir_part, file_name = os.path.split(c)
            target_parent_id = self.get_or_create_remote_path(data_id, dir_part)

            file_size = os.path.getsize(chunk_path)
            resumable = file_size > 5 * 1024 * 1024
            media = MediaFileUpload(chunk_path, mimetype="application/octet-stream", resumable=resumable)
            meta = {"name": file_name, "parents": [target_parent_id]}
            service.files().create(body=meta, media_body=media, fields="id").execute()
            uploaded_count += 1

        # 4. Delete Obsolete Remote Chunks (Cut down Google Drive to match pendrive)
        deleted_count = 0
        for c in to_delete_remote:
            op_count += 1
            pct = 20 + int((op_count / max(1, total_ops)) * 75)
            if progress_callback:
                progress_callback(
                    f"🗑️ Deleting obsolete cloud chunk {deleted_count + 1}/{len(to_delete_remote)}...",
                    pct,
                    100,
                )
            file_id = remote_chunks[c]
            try:
                service.files().delete(fileId=file_id).execute()
                deleted_count += 1
            except Exception:
                pass

        # 5. Clean up any empty remote subfolders
        if deleted_count > 0:
            self.clean_empty_remote_folders(data_id)

        if progress_callback:
            progress_callback("✔ Local sync complete! Google Drive updated to match USB.", 100, 100)

        return {
            "uploaded_chunks": uploaded_count,
            "deleted_remote_chunks": deleted_count,
            "already_synced": len(local_chunks) - len(to_upload),
            "total_local_chunks": len(local_chunks),
            "root_folder_id": root_id,
        }

    def sync_with_cloud(
        self,
        target_drive_path: str,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
    ) -> Dict[str, Any]:
        """Sync with Cloud Data: Google Drive is Source of Truth.
        
        - Downloads cloud header and manifest to pendrive.
        - Downloads missing cloud chunks into local subfolders.
        - Deletes any local chunks that were removed from the cloud.
        """
        service = self.get_service()

        if progress_callback:
            progress_callback("Connecting to Google Drive...", 0, 100)

        root_id, data_id = self.get_or_create_remote_folders()
        self.clean_erroneous_flat_chunks(data_id)

        crypton_dir = VaultManager.get_crypton_dir(target_drive_path)
        data_dir = VaultManager.get_data_dir(target_drive_path)
        os.makedirs(data_dir, exist_ok=True)

        # 1. Download Header and Manifest (Cloud is Master)
        for filename in [os.path.basename(VaultManager.get_header_path("")), os.path.basename(VaultManager.get_manifest_path(""))]:
            q = f"name = '{filename}' and '{root_id}' in parents and trashed = false"
            res = service.files().list(q=q, spaces="drive", fields="files(id)").execute()
            files = res.get("files", [])
            if not files:
                raise GDriveSyncError(f"Cloud backup is missing required file: {filename}")

            file_id = files[0]["id"]
            dest_path = os.path.join(crypton_dir, filename)
            self.download_file_by_id(file_id, dest_path)

        # 2. Calculate Delta
        remote_chunks = self.list_remote_chunks(data_id)
        remote_chunk_set = set(remote_chunks.keys())
        local_chunks = self.get_all_local_chunks(data_dir)
        local_chunk_set = set(local_chunks)

        to_download = {name: fid for name, fid in remote_chunks.items() if name not in local_chunk_set}
        to_delete_local = [c for c in local_chunks if c not in remote_chunk_set]

        total_ops = len(to_download) + len(to_delete_local)
        op_count = 0

        # 3. Download Missing Cloud Chunks into local subfolders
        downloaded_count = 0
        for chunk_name, file_id in to_download.items():
            op_count += 1
            pct = 15 + int((op_count / max(1, total_ops)) * 70)
            if progress_callback:
                progress_callback(
                    f"⬇️ Downloading chunk {downloaded_count + 1}/{len(to_download)}: {os.path.basename(chunk_name)}...",
                    pct,
                    100,
                )

            dest_path = os.path.join(data_dir, *chunk_name.split("/"))
            self.download_file_by_id(file_id, dest_path)
            downloaded_count += 1

        # 4. Delete Obsolete Local Chunks (Cut down USB to match Google Drive)
        deleted_count = 0
        for c in to_delete_local:
            op_count += 1
            pct = 15 + int((op_count / max(1, total_ops)) * 80)
            if progress_callback:
                progress_callback(
                    f"🗑️ Removing local extra chunk {deleted_count + 1}/{len(to_delete_local)}...",
                    pct,
                    100,
                )
            local_path = os.path.join(data_dir, *c.split("/"))
            if os.path.isfile(local_path):
                try:
                    os.remove(local_path)
                    deleted_count += 1
                except OSError:
                    pass

        # 5. Clean up any empty local subfolders
        if deleted_count > 0:
            VaultManager._clean_empty_dirs(data_dir)

        if progress_callback:
            progress_callback("✔ Cloud sync complete! USB updated to match Google Drive.", 100, 100)

        return {
            "downloaded_chunks": downloaded_count,
            "deleted_local_chunks": deleted_count,
            "already_present": len(remote_chunks) - downloaded_count,
            "total_remote_chunks": len(remote_chunks),
            "target_dir": target_drive_path,
        }

    # Backward-compatible aliases
    def sync_vault(self, drive_path: str, progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
        res = self.sync_with_local(drive_path, progress_callback)
        # Adapt keys for tests expecting uploaded_chunks
        return {
            "total_local_chunks": res.get("total_local_chunks", 0),
            "uploaded_chunks": res.get("uploaded_chunks", 0),
            "already_synced": res.get("already_synced", 0),
            "root_folder_id": res.get("root_folder_id", ""),
        }

    def restore_vault(self, target_drive_path: str, progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
        res = self.sync_with_cloud(target_drive_path, progress_callback)
        return {
            "restored_chunks": res.get("downloaded_chunks", 0),
            "already_present": res.get("already_present", 0),
            "total_remote_chunks": res.get("total_remote_chunks", 0),
            "target_dir": target_drive_path,
        }

    def two_way_sync(self, drive_path: str, progress_callback: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
        return self.sync_with_local(drive_path, progress_callback)


