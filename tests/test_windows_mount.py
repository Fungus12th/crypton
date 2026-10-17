import os
import sys
import time
import tempfile
import pytest

from crypton.core.vault import VaultManager
from crypton.core.windows_mount import WindowsVaultMountService, get_available_drive_letter


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only test")
def test_windows_virtual_drive_mount_and_io():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "usb_drive")
        os.makedirs(vault_dir)

        # 1. Initialize vault
        password = "SecureWindowsPassword123!"
        VaultManager.init_vault(vault_dir, password, time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, password)

        # 2. Mount virtual drive
        drive_letter = get_available_drive_letter()
        mountpoint, _ = WindowsVaultMountService.mount(vault_dir, mvk, drive_letter)
        time.sleep(0.5)

        try:
            assert os.path.exists(mountpoint)

            # 3. Write a file into the mounted drive
            test_file = os.path.join(mountpoint, "document.txt")
            with open(test_file, "w") as f:
                f.write("Windows Virtual Drive Works!")

            # 4. Create nested folder and file
            folder = os.path.join(mountpoint, "Secrets", "2026")
            os.makedirs(folder, exist_ok=True)
            nested_file = os.path.join(folder, "plan.txt")
            with open(nested_file, "w") as f:
                f.write("Plan Payload Data")

            # Allow sync worker to pick up changes
            time.sleep(1.5)

            # 5. Read back files from the mounted drive
            with open(test_file, "r") as f:
                assert f.read() == "Windows Virtual Drive Works!"

            with open(nested_file, "r") as f:
                assert f.read() == "Plan Payload Data"

        finally:
            # 6. Unmount cleanly
            WindowsVaultMountService.unmount(mountpoint)
            time.sleep(0.5)
            assert not os.path.exists(mountpoint)

        # 7. Verify internal encrypted vault manifest has the files
        manifest = VaultManager._load_manifest(vault_dir, mvk)
        assert "document.txt" in manifest
        assert "Secrets/2026/plan.txt" in manifest

        # 8. Extract file from vault to verify full decryption
        extracted_doc = os.path.join(tmpdir, "extracted.txt")
        VaultManager.extract_file(vault_dir, mvk, "document.txt", extracted_doc)
        with open(extracted_doc, "r") as f:
            assert f.read() == "Windows Virtual Drive Works!"

        extracted_plan = os.path.join(tmpdir, "extracted_plan.txt")
        VaultManager.extract_file(vault_dir, mvk, "Secrets/2026/plan.txt", extracted_plan)
        with open(extracted_plan, "r") as f:
            assert f.read() == "Plan Payload Data"


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only test")
def test_windows_default_mount_is_virtual_drive():
    """Verify default mount on Windows uses available drive letter with blazing speed SSD caching."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "usb_stick_default")
        os.makedirs(vault_dir)

        password = "DefaultMountPassword123!"
        VaultManager.init_vault(vault_dir, password, time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, password)

        mountpoint, _ = WindowsVaultMountService.mount(vault_dir, mvk)
        try:
            assert mountpoint.endswith(":\\") or mountpoint.endswith(":")
            assert os.path.exists(mountpoint)
        finally:
            WindowsVaultMountService.unmount(mountpoint)
            time.sleep(0.5)
            assert not os.path.exists(mountpoint)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows only test")
def test_windows_vault_unlocked_directory_mount():
    """Verify Windows also supports direct directory mounting if explicitly requested."""
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "usb_stick")
        os.makedirs(vault_dir)

        # 1. Initialize vault
        password = "FolderMountPassword123!"
        VaultManager.init_vault(vault_dir, password, time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, password)

        # 2. Mount explicit Vault_Unlocked directory
        target_dir = os.path.join(vault_dir, "Vault_Unlocked")
        mountpoint, _ = WindowsVaultMountService.mount(vault_dir, mvk, mountpoint=target_dir)
        assert mountpoint == target_dir
        assert os.path.isdir(mountpoint)

        try:
            # 3. Create a test file
            f_path = os.path.join(mountpoint, "finance.csv")
            with open(f_path, "w") as f:
                f.write("id,amount\n1,500\n")

            time.sleep(1.5)

            # Read back
            with open(f_path, "r") as f:
                assert f.read() == "id,amount\n1,500\n"
        finally:
            # 4. Unmount cleanly
            WindowsVaultMountService.unmount(mountpoint)
            time.sleep(0.5)
            # Folder should be cleaned up upon locking
            assert not os.path.exists(mountpoint)

        # 5. Verify encrypted file exists in vault
        manifest = VaultManager._load_manifest(vault_dir, mvk)
        assert "finance.csv" in manifest
