#  Copyright © 2021-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


import random
import hashlib

import pytest

import fast_file_encryption as ffe
from fast_file_encryption import Encryptor, Decryptor


class TestMetadata:
    METADATA = {  # Predefined metadata
        "empty": "",
        "one": "1",
        "list": [1, 2, 3],
        "data": "deTdImOpmo91MrVyiJgbiw4y5i7-W5rWwRt5paHwgVH8uqb_juAVqxBT8fh5w8ehbpL5ygsd42-aD7tfdPJBjXBZJfcPHl-MoDe9B"
        "zEbViHLVUrXcnezZqrUIEc-ey3EbslVMvTOcBNUM9BrCi_7bSnjicowrv7A1dIL827LGjw",
    }

    METADATA_4K = {  # File metadata
        "file_path": "/Users/tobias/Documents/Source/fast-file-encryption/tests/data/4k-random.data",
        "file_name": "4k-random.data",
        "file_size": 4000,
        "created": "2022-01-06T10:46:44.219334",
        "modified": "2022-01-06T10:46:44.219476",
    }

    def test_read_metadata(self, private_key, data_dir):
        """
        Test if we can read metadata from a prepared file.
        """
        path = data_dir / "4k-random.ffe"
        decryptor = Decryptor(private_key=private_key)
        meta = decryptor.read_metadata(path)
        expected_meta = self.METADATA.copy()
        expected_meta.update(self.METADATA_4K)
        assert meta == expected_meta

    def test_encrypt_decrypt_empty_data(self, tmp_path, public_key, private_key):
        """
        Test if we can write/read metadata repeatedly.
        """
        stored_file_path = tmp_path / "empty.data"
        encryptor = Encryptor(public_key=public_key)
        decryptor = Decryptor(private_key=private_key)
        random.seed(750)
        for _ in range(50):
            meta = self.METADATA.copy()
            meta["random"] = random.randbytes(128).hex()
            encryptor.save_encrypted(source_data=random.randbytes(200), destination=stored_file_path, meta=meta)
            read_meta = decryptor.read_metadata(source=stored_file_path)
            stored_file_path.unlink()
            assert meta == read_meta

    def test_invalid_metadata(self, tmp_path, public_key):
        """
        Test if invalid metadata is detected.
        """
        stored_file_path = tmp_path / "empty.data"
        encryptor = Encryptor(public_key=public_key)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            encryptor.save_encrypted(source_data=bytes(), destination=stored_file_path, meta=12)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            encryptor.save_encrypted(source_data=bytes(), destination=stored_file_path, meta="text")
        with pytest.raises(ValueError):
            meta = {"too_long": "x" * 200000}
            encryptor.save_encrypted(source_data=bytes(), destination=stored_file_path, meta=meta)

    def test_metadata_json_error(self, tmp_path, public_key, private_key, monkeypatch):
        """
        Ensure invalid JSON in metadata raises :class:`IntegrityError`.
        """
        encryptor = Encryptor(public_key=public_key)
        decryptor = Decryptor(private_key=private_key)
        stored_file_path = tmp_path / "file.ffe"
        encryptor.save_encrypted(source_data=b"data", destination=stored_file_path, meta={"a": 1})

        original = decryptor._read_encrypted_block

        def fake_read_encrypted_block(
            self, expected_type: bytes, maximum_size: int = 100_000, user_limit: bool = False
        ):
            if expected_type == b"META":
                return b"{invalid json"
            if expected_type == b"MDHA":
                return hashlib.sha3_512(b"{invalid json").digest()
            return original(expected_type, maximum_size, user_limit)

        monkeypatch.setattr(decryptor, "_read_encrypted_block", fake_read_encrypted_block.__get__(decryptor, Decryptor))

        with pytest.raises(ffe.IntegrityError):
            decryptor.read_metadata(stored_file_path)
