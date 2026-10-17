import os
import time
import tempfile
import pytest

from crypton.core.vault import VaultManager
from crypton.core.fuse_vault import VaultMountService, FUSE


@pytest.mark.skipif(FUSE is None, reason="FUSE not installed")
def test_fuse_mount_and_transparent_io():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "usb")
        mount_dir = os.path.join(tmpdir, "unlocked_vault")
        os.makedirs(vault_dir)

        # 1. Initialize vault
        VaultManager.init_vault(vault_dir, "SecretPass123!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, "SecretPass123!")

        # 2. Mount FUSE filesystem
        mountpoint, thread = VaultMountService.mount(vault_dir, mvk, mount_dir)
        time.sleep(0.5)

        try:
            assert os.path.ismount(mountpoint)

            # 3. Write a file directly into the mountpoint
            test_file = os.path.join(mountpoint, "test_doc.txt")
            with open(test_file, "w") as f:
                f.write("FUSE Transparent Encryption Works!")

            # 4. Read back the file from the mountpoint
            with open(test_file, "r") as f:
                content = f.read()
            assert content == "FUSE Transparent Encryption Works!"

            # 5. Create a folder and file inside
            sub_folder = os.path.join(mountpoint, "MyFolder")
            os.makedirs(sub_folder, exist_ok=True)
            nested_file = os.path.join(sub_folder, "nested.txt")
            with open(nested_file, "w") as f:
                f.write("Nested file content")

            with open(nested_file, "r") as f:
                assert f.read() == "Nested file content"

        finally:
            # 6. Unmount cleanly
            VaultMountService.unmount(mountpoint)
            time.sleep(0.5)
            assert not os.path.ismount(mountpoint)

        # 7. Verify the vault's internal encrypted manifest records the new files
        manifest = VaultManager._load_manifest(vault_dir, mvk)
        assert "test_doc.txt" in manifest
        assert "MyFolder/nested.txt" in manifest


def test_ram_limit_settings():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "usb")
        os.makedirs(vault_dir)

        # 1. Defaults
        defaults = VaultManager.get_settings(vault_dir)
        assert defaults["ram_limit_mb"] == 32

        # 2. Save custom setting
        VaultManager.save_settings(vault_dir, {"ram_limit_mb": 128})
        loaded = VaultManager.get_settings(vault_dir)
        assert loaded["ram_limit_mb"] == 128

        # 3. CryptonFS initialization respects saved setting
        VaultManager.init_vault(vault_dir, "SecretPass123!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, "SecretPass123!")

        from crypton.core.fuse_vault import CryptonFS
        fs = CryptonFS(vault_dir, mvk)
        assert fs.ram_limit == 128 * 1024 * 1024

        # 4. Dynamic update
        fs.update_ram_limit(256)
        assert fs.ram_limit == 256 * 1024 * 1024
