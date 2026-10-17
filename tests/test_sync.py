import os
import tempfile
import pytest
from unittest.mock import MagicMock, patch

from crypton.core.vault import VaultManager
from crypton.sync.gdrive import GDriveAuth, GDriveSync, GDriveAuthError, GDriveSyncError


def test_gdrive_auth_ram_lifecycle():
    auth = GDriveAuth()
    assert not auth.is_authenticated()

    # Mock credentials object in RAM
    mock_creds = MagicMock()
    mock_creds.valid = True
    auth._creds = mock_creds

    assert auth.is_authenticated()
    assert auth.get_credentials() is mock_creds

    # Verify wipe_credentials immediately clears RAM
    auth.wipe_credentials()
    assert not auth.is_authenticated()
    assert auth._creds is None


def test_gdrive_sync_incremental_upload_and_delta():
    with tempfile.TemporaryDirectory() as td:
        # 1. Initialize a real Crypton vault
        VaultManager.init_vault(td, "SyncPassword123!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(td, "SyncPassword123!")

        # Add a couple of test files
        f1_path = os.path.join(td, "doc1.txt")
        with open(f1_path, "w") as f:
            f.write("Secret Document 1")
        VaultManager.add_file(td, mvk, f1_path, "doc1.txt")

        f2_path = os.path.join(td, "doc2.txt")
        with open(f2_path, "w") as f:
            f.write("Secret Document 2")
        VaultManager.add_file(td, mvk, f2_path, "doc2.txt")

        local_chunks = os.listdir(VaultManager.get_data_dir(td))
        assert len(local_chunks) >= 2

        # 2. Mock Google Drive API
        mock_auth = MagicMock(spec=GDriveAuth)
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_credentials.return_value = MagicMock(valid=True)

        mock_service = MagicMock()
        sync_engine = GDriveSync(auth=mock_auth)
        sync_engine._service = mock_service

        # Mock folder search & creation
        # First call: root folder search (returns empty -> creates root)
        # Second call: data folder search (returns empty -> creates data)
        # Subsequent calls: file listing
        mock_service.files().create().execute.side_effect = [
            {"id": "remote_root_123"},
            {"id": "remote_data_456"},
            {"id": "uploaded_header_id"},
            {"id": "uploaded_manifest_id"},
            {"id": "uploaded_chunk_1"},
            {"id": "uploaded_chunk_2"},
        ]

        # Simulate that chunk 0 is already in cloud, but chunk 1 is missing
        already_synced_chunk = local_chunks[0]
        missing_chunk = local_chunks[1]

        def mock_list_side_effect(**kwargs):
            q = kwargs.get("q", "")
            mock_res = MagicMock()
            if "name = 'Crypton_Vault_Backups'" in q:
                mock_res.execute.return_value = {"files": [{"id": "remote_root_123", "name": "Crypton_Vault_Backups"}]}
            elif "name = 'data'" in q:
                mock_res.execute.return_value = {"files": [{"id": "remote_data_456", "name": "data"}]}
            elif "'remote_data_456' in parents" in q:
                # Return 1 chunk as already in cloud
                mock_res.execute.return_value = {
                    "files": [{"id": "cloud_ch_1", "name": already_synced_chunk}],
                    "nextPageToken": None,
                }
            else:
                # Generic check for existing header/manifest
                mock_res.execute.return_value = {"files": []}
            return mock_res

        mock_service.files().list.side_effect = mock_list_side_effect

        # 3. Run sync_vault with progress tracking
        progress_calls = []
        def on_progress(msg, cur, total):
            progress_calls.append((msg, cur, total))

        stats = sync_engine.sync_vault(td, progress_callback=on_progress)

        # 4. Verify results
        assert stats["total_local_chunks"] == len(local_chunks)
        assert stats["uploaded_chunks"] == len(local_chunks) - 1
        assert stats["already_synced"] == 1
        assert len(progress_calls) > 0
        assert "complete!" in progress_calls[-1][0]


def test_gdrive_sync_recursive_nested_chunks():
    with tempfile.TemporaryDirectory() as td:
        VaultManager.init_vault(td, "Pass12345!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(td, "Pass12345!")

        # Create nested file
        f_nested = os.path.join(td, "nested.txt")
        with open(f_nested, "w") as f:
            f.write("Nested content")
        VaultManager.add_file(td, mvk, f_nested, "subfolder/level2/nested.txt")

        data_dir = VaultManager.get_data_dir(td)
        chunks = GDriveSync.get_all_local_chunks(data_dir)
        assert len(chunks) == 1
        # The relative path should contain forward slashes (e.g. hash/hash/id)
        assert "/" in chunks[0]


def test_gdrive_sync_with_local():
    with tempfile.TemporaryDirectory() as td:
        VaultManager.init_vault(td, "Pass12345!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(td, "Pass12345!")

        f1 = os.path.join(td, "file1.txt")
        with open(f1, "w") as f:
            f.write("Local file to upload")
        VaultManager.add_file(td, mvk, f1, "file1.txt")

        mock_auth = MagicMock(spec=GDriveAuth)
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_credentials.return_value = MagicMock(valid=True)

        mock_service = MagicMock()
        sync_engine = GDriveSync(auth=mock_auth)
        sync_engine._service = mock_service

        mock_service.files().create().execute.side_effect = [
            {"id": "root_id"},
            {"id": "data_id"},
            {"id": "uploaded_chunk_id"},
            {"id": "hdr_id"},
            {"id": "man_id"},
        ]

        def mock_list_side_effect(**kwargs):
            q = kwargs.get("q", "")
            mock_res = MagicMock()
            if "mimeType = 'application/vnd.google-apps.folder'" in q and "'data_id' in parents" in q:
                mock_res.execute.return_value = {"files": []}
            elif "name = 'Crypton_Vault_Backups'" in q:
                mock_res.execute.return_value = {"files": [{"id": "root_id"}]}
            elif "name = 'data'" in q:
                mock_res.execute.return_value = {"files": [{"id": "data_id"}]}
            elif "'data_id' in parents" in q:
                mock_res.execute.return_value = {
                    "files": [{"id": "remote_ch_1", "name": "cloud_only_chunk"}],
                    "nextPageToken": None,
                }
            else:
                mock_res.execute.return_value = {"files": []}
            return mock_res

        mock_service.files().list.side_effect = mock_list_side_effect

        stats = sync_engine.sync_with_local(td)
        assert stats["uploaded_chunks"] == 1
        assert stats["deleted_remote_chunks"] == 1
        mock_service.files().delete.assert_called_once_with(fileId="remote_ch_1")


def test_gdrive_sync_with_cloud():
    with tempfile.TemporaryDirectory() as td:
        VaultManager.init_vault(td, "Pass12345!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(td, "Pass12345!")

        # Create an obsolete local chunk that doesn't exist in the cloud
        data_dir = VaultManager.get_data_dir(td)
        sub_dir = os.path.join(data_dir, "testdir")
        os.makedirs(sub_dir, exist_ok=True)
        obsolete_chunk = os.path.join(sub_dir, "obsolete_chunk.dat")
        with open(obsolete_chunk, "wb") as f:
            f.write(b"local only obsolete data")

        mock_auth = MagicMock(spec=GDriveAuth)
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_credentials.return_value = MagicMock(valid=True)

        mock_service = MagicMock()
        sync_engine = GDriveSync(auth=mock_auth)
        sync_engine._service = mock_service

        def mock_list_side_effect(**kwargs):
            q = kwargs.get("q", "")
            mock_res = MagicMock()
            if "name = 'Crypton_Vault_Backups'" in q:
                mock_res.execute.return_value = {"files": [{"id": "root_id"}]}
            elif "name = 'data'" in q:
                mock_res.execute.return_value = {"files": [{"id": "data_id"}]}
            elif "name = 'vault.header'" in q:
                mock_res.execute.return_value = {"files": [{"id": "hdr_id"}]}
            elif "name = 'manifest.enc'" in q:
                mock_res.execute.return_value = {"files": [{"id": "man_id"}]}
            elif "'data_id' in parents" in q and "application/vnd.google-apps.folder" not in q:
                mock_res.execute.return_value = {
                    "files": [{"id": "chunk_id_cloud", "name": "cloud_chunk.dat"}],
                    "nextPageToken": None,
                }
            else:
                mock_res.execute.return_value = {"files": []}
            return mock_res

        mock_service.files().list.side_effect = mock_list_side_effect

        with patch.object(sync_engine, "download_file_by_id") as mock_dl:
            stats = sync_engine.sync_with_cloud(td)
            assert stats["downloaded_chunks"] == 1
            assert stats["deleted_local_chunks"] == 1
            assert not os.path.exists(obsolete_chunk)
            assert mock_dl.call_count == 3  # header, manifest, and 1 chunk


def test_gdrive_sync_creates_remote_subfolder():
    mock_auth = MagicMock(spec=GDriveAuth)
    mock_auth.is_authenticated.return_value = True
    sync_engine = GDriveSync(auth=mock_auth)
    mock_service = MagicMock()
    sync_engine._service = mock_service

    # First lookup returns empty -> triggers folder creation
    mock_service.files().list().execute.return_value = {"files": []}
    mock_service.files().create().execute.return_value = {"id": "subfolder_id_789"}

    # 1. Test get_or_create_remote_path
    sub_id = sync_engine.get_or_create_remote_path("base_data_id", "fae30af0c2eab586")
    assert sub_id == "subfolder_id_789"

    # Verify folder creation call arguments
    create_call = mock_service.files().create.call_args[1]
    assert create_call["body"]["name"] == "fae30af0c2eab586"
    assert create_call["body"]["mimeType"] == "application/vnd.google-apps.folder"
    assert create_call["body"]["parents"] == ["base_data_id"]

    # 2. Verify cache hit (should not call create again)
    mock_service.files().create.reset_mock()
    cached_id = sync_engine.get_or_create_remote_path("base_data_id", "fae30af0c2eab586")
    assert cached_id == "subfolder_id_789"
    mock_service.files().create.assert_not_called()


def test_gdrive_sync_non_vault_raises():
    with tempfile.TemporaryDirectory() as td:
        sync_engine = GDriveSync()
        with pytest.raises(GDriveSyncError):
            sync_engine.sync_vault(td)


