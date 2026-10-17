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
