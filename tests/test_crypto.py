import os
import shutil
import tempfile
import pytest
from cryptography.exceptions import InvalidTag

from crypton.core.crypto import (
    derive_kek,
    wrap_key,
    unwrap_key,
    derive_file_key,
    encrypt_file,
    decrypt_file,
    KEY_LEN,
    SALT_LEN,
)
from crypton.core.vault import VaultManager, InvalidPasswordError


def test_key_derivation_and_wrapping():
    password = "SuperSecretPassword123!"
    salt = os.urandom(SALT_LEN)
    kek = derive_kek(password, salt, time_cost=2, memory_cost=32768, parallelism=2)
    assert len(kek) == KEY_LEN

    mvk = os.urandom(KEY_LEN)
    nonce, wrapped = wrap_key(mvk, kek)

    # Correct unwrap
    unwrapped = unwrap_key(nonce, wrapped, kek)
    assert unwrapped == mvk

    # Wrong password unwrap fails
    wrong_kek = derive_kek("WrongPassword!", salt, time_cost=2, memory_cost=32768, parallelism=2)
    with pytest.raises(InvalidTag):
        unwrap_key(nonce, wrapped, wrong_kek)


def test_chunked_file_encryption_and_tamper():
    with tempfile.TemporaryDirectory() as tmpdir:
        src = os.path.join(tmpdir, "plain.bin")
        enc = os.path.join(tmpdir, "plain.enc")
        dec = os.path.join(tmpdir, "plain.dec")

        # 200 KB payload (spans multiple 64 KB chunks)
        test_payload = os.urandom(200 * 1024)
        with open(src, "wb") as f:
            f.write(test_payload)

        file_key = os.urandom(KEY_LEN)
        encrypt_file(src, enc, file_key)

        # Verify decryption matches
        decrypt_file(enc, dec, file_key)
        with open(dec, "rb") as f:
            assert f.read() == test_payload

        # Tamper detection: modify one byte in ciphertext
        with open(enc, "r+b") as f:
            f.seek(50)
            orig_byte = f.read(1)
            tampered = bytes([(orig_byte[0] ^ 0xFF)])
            f.seek(50)
            f.write(tampered)

        tampered_dec = os.path.join(tmpdir, "tampered.dec")
        with pytest.raises(Exception):
            decrypt_file(enc, tampered_dec, file_key)


def test_vault_lifecycle_and_password_change():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "my_usb")
        os.makedirs(vault_dir)

        initial_password = "VaultPassword999!"
        new_password = "UpdatedVaultPassword888!"

        # 1. Initialize vault
        VaultManager.init_vault(
            vault_dir,
            initial_password,
            time_cost=2,
            memory_cost=32768,
            parallelism=2,
        )
        assert VaultManager.is_vault(vault_dir)

        # 2. Unlock with correct password
        mvk = VaultManager.unlock_vault(vault_dir, initial_password)
        assert len(mvk) == KEY_LEN

        # 3. Unlock with wrong password raises InvalidPasswordError
        with pytest.raises(InvalidPasswordError):
            VaultManager.unlock_vault(vault_dir, "WrongPassword!")

        # 4. Add a file to the vault
        sample_file = os.path.join(tmpdir, "secret_doc.txt")
        with open(sample_file, "w") as f:
            f.write("Classified Crypton Data!")

        record = VaultManager.add_file(vault_dir, mvk, sample_file, "docs/secret.txt")
        assert record["rel_path"] == "docs/secret.txt"

        # 5. List files
        files = VaultManager.list_files(vault_dir, mvk)
        assert len(files) == 1
        assert files[0]["rel_path"] == "docs/secret.txt"

        # 6. Extract file
        extracted_file = os.path.join(tmpdir, "extracted.txt")
        VaultManager.extract_file(vault_dir, mvk, "docs/secret.txt", extracted_file)
        with open(extracted_file, "r") as f:
            assert f.read() == "Classified Crypton Data!"

        # 7. Change password instantly (< 100ms)
        VaultManager.change_password(vault_dir, initial_password, new_password)

        # 8. Verify old password no longer works
        with pytest.raises(InvalidPasswordError):
            VaultManager.unlock_vault(vault_dir, initial_password)

        # 9. Verify new password unlocks and file is still accessible
        new_mvk = VaultManager.unlock_vault(vault_dir, new_password)
        assert new_mvk == mvk  # MVK remains identical!

        extracted_after_pw_change = os.path.join(tmpdir, "extracted2.txt")
        VaultManager.extract_file(vault_dir, new_mvk, "docs/secret.txt", extracted_after_pw_change)
        with open(extracted_after_pw_change, "r") as f:
            assert f.read() == "Classified Crypton Data!"


def test_recursive_folder_encryption_and_extraction():
    with tempfile.TemporaryDirectory() as tmpdir:
        vault_dir = os.path.join(tmpdir, "vault")
        os.makedirs(vault_dir)

        # 1. Create a nested source folder structure
        src_folder = os.path.join(tmpdir, "MyPhotos")
        sub_folder = os.path.join(src_folder, "Camera", "2026")
        os.makedirs(sub_folder)

        with open(os.path.join(src_folder, "root.jpg"), "w") as f:
            f.write("Root Photo Data")
        with open(os.path.join(sub_folder, "snap.jpg"), "w") as f:
            f.write("Snap Photo Data")

        # 2. Init vault and add folder
        mvk = VaultManager.init_vault(vault_dir, "Password123!", time_cost=2, memory_cost=32768, parallelism=2)
        mvk = VaultManager.unlock_vault(vault_dir, "Password123!")

        records = VaultManager.add_folder(vault_dir, mvk, src_folder)
        assert len(records) == 2

        # Verify on-disk storage is organized into obfuscated subdirectories, not a flat dump
        data_dir = VaultManager.get_data_dir(vault_dir)
        subdirs = [d for d in os.listdir(data_dir) if os.path.isdir(os.path.join(data_dir, d))]
        assert len(subdirs) >= 1  # Confirms subdirectories exist!

        # 3. Extract entire folder tree
        dest_dir = os.path.join(tmpdir, "Extracted")
        os.makedirs(dest_dir)
        extracted_count, missing = VaultManager.extract_path(vault_dir, mvk, "MyPhotos", dest_dir)
        assert extracted_count == 2
        assert len(missing) == 0

        # 4. Verify extracted files content and directory structure
        with open(os.path.join(dest_dir, "MyPhotos", "root.jpg"), "r") as f:
            assert f.read() == "Root Photo Data"
        with open(os.path.join(dest_dir, "MyPhotos", "Camera", "2026", "snap.jpg"), "r") as f:
            assert f.read() == "Snap Photo Data"

