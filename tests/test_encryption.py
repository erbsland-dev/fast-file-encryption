#  Copyright © 2021-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


import itertools
import random

import pytest

from fast_file_encryption import Encryptor, Decryptor, IntegrityError, DataTooLargeError


class TestEncryption:

    def test_decrypt_empty_data(self, private_key, data_dir):
        """
        Test if a prepared empty file can be decrypted.
        """
        decryptor = Decryptor(private_key=private_key)
        decrypted_data = decryptor.load_decrypted(source=data_dir / "empty.ffe")
        assert len(decrypted_data) == 0

    def test_decrypt_empty_data_into_file(self, private_key, data_dir, tmp_path):
        """
        Test if a prepared empty file can be decrypted.
        """
        decryptor = Decryptor(private_key=private_key)
        target_path = tmp_path / "target.data"
        decryptor.copy_decrypted(source=data_dir / "empty.ffe", destination=target_path)
        decrypted_data = target_path.read_bytes()
        assert len(decrypted_data) == 0

    def test_decrypt_zero_data(self, private_key, data_dir):
        """
        Test if a prepared file can be decrypted.
        """
        decryptor = Decryptor(private_key=private_key)
        decrypted_data = decryptor.load_decrypted(source=data_dir / "10k-zero.ffe")
        assert len(decrypted_data) == 10000
        assert decrypted_data == bytes(10000)

    def test_decrypt_zero_data_into_file(self, private_key, data_dir, tmp_path):
        """
        Test if a prepared file can be decrypted.
        """
        decryptor = Decryptor(private_key=private_key)
        target_path = tmp_path / "target.data"
        decryptor.copy_decrypted(source=data_dir / "10k-zero.ffe", destination=target_path)
        decrypted_data = target_path.read_bytes()
        assert len(decrypted_data) == 10000
        assert decrypted_data == bytes(10000)

    def test_decrypt_random_data(self, private_key, data_dir):
        """
        Test if a prepared file can be decrypted.
        """
        original_data = (data_dir / "8k-random.data").read_bytes()
        decryptor = Decryptor(private_key=private_key)
        decrypted_data = decryptor.load_decrypted(source=data_dir / "8k-random.ffe")
        assert len(decrypted_data) == 8000
        assert decrypted_data == original_data

    def test_decrypt_random_data_into_file(self, private_key, data_dir, tmp_path):
        """
        Test if a prepared file can be decrypted into a file
        """
        original_data = (data_dir / "8k-random.data").read_bytes()
        decryptor = Decryptor(private_key=private_key)
        target_path = tmp_path / "target.data"
        decryptor.copy_decrypted(source=data_dir / "8k-random.ffe", destination=target_path)
        decrypted_data = target_path.read_bytes()
        assert len(decrypted_data) == 8000
        assert decrypted_data == original_data

    def test_encrypt_decrypt_empty_data(self, tmp_path, public_key, private_key):
        """
        Test if an empty file is correctly encrypted and decrypted.
        """
        stored_file_path = tmp_path / "empty.data"
        encryptor = Encryptor(public_key=public_key)
        encryptor.save_encrypted(source_data=bytes(), destination=stored_file_path)
        decryptor = Decryptor(private_key=private_key)
        decrypted_data = decryptor.load_decrypted(source=stored_file_path)
        assert len(decrypted_data) == 0

    def test_encrypt_decrypt_random_data(self, tmp_path, public_key, private_key):
        """
        Encrypt and decrypt a batch of random data blocks using the same instances.
        """
        encryptor = Encryptor(public_key=public_key)
        decryptor = Decryptor(private_key=private_key)
        stored_file_path = tmp_path / "data.ffe"
        data_file_path = tmp_path / "random.data"
        random.seed(600)  # Use a fixed seed to make this test repeatable
        for _ in range(50):
            data = random.randbytes(random.randint(1, 10000))
            encryptor.save_encrypted(source_data=data, destination=stored_file_path)
            decrypted_data = decryptor.load_decrypted(source=stored_file_path)
            assert len(decrypted_data) == len(data)
            assert decrypted_data == data
            stored_file_path.unlink(missing_ok=True)
            data_file_path.write_bytes(data)
            meta = {"test": "metadata"}
            encryptor.copy_encrypted(
                source=data_file_path, destination=stored_file_path, meta=meta, add_source_metadata=True
            )
            decrypted_data = decryptor.load_decrypted(source=stored_file_path)
            assert len(decrypted_data) == len(data)
            assert decrypted_data == data
            data_file_path.unlink(missing_ok=True)

    def test_bit_flips(self, tmp_path, private_key, data_dir):
        """
        Test if single bit flips are detected.
        """
        decryptor = Decryptor(private_key=private_key)
        file_path = tmp_path / "data.ffe"
        decrypted_file = tmp_path / "decrypted.data"
        random_file_data = (data_dir / "8k-random.ffe").read_bytes()
        for i in range(0x200):
            data = bytearray(random_file_data)
            pos = i // 8
            bit_mask = 1 << (i % 8)
            data[pos] ^= bit_mask
            file_path.write_bytes(data)
            with pytest.raises(IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)
        random.seed(900)
        for _ in range(50):
            data = bytearray(random_file_data)
            pos = random.randint(0, len(data))
            bit_mask = 1 << (random.randint(0, 7))
            data[pos] ^= bit_mask
            file_path.write_bytes(data)
            with pytest.raises(IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)

    def test_incomplete_files(self, private_key, tmp_path, data_dir):
        decryptor = Decryptor(private_key=private_key)
        file_path = tmp_path / "data.ffe"
        decrypted_file = tmp_path / "decrypted.data"
        random_file_data = (data_dir / "8k-random.ffe").read_bytes()
        for i in range(0x100, 0x300):  # files shorter than 256 bytes are handled specially, test critical range
            data = bytearray(random_file_data[:i])
            file_path.write_bytes(data)
            with pytest.raises(IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)
        random.seed(900)
        for _ in range(50):  # Test a number of random sizes cover more cases
            data = bytearray(random_file_data[: random.randint(1, len(random_file_data) - 1)])
            file_path.write_bytes(data)
            with pytest.raises(IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)

    def test_maximum_size(self, private_key, data_dir):
        """
        Test is the maximum size for load data is respected.
        """
        decryptor = Decryptor(private_key=private_key)
        random_file = data_dir / "8k-random.ffe"
        with pytest.raises(DataTooLargeError):
            decryptor.load_decrypted(source=random_file, maximum_size=(8000 - 128))
        with pytest.raises(DataTooLargeError):
            decryptor.load_decrypted(source=random_file, maximum_size=100)

    def test_wrong_block_order(self, private_key, data_dir, tmp_path):
        """
        Test if a wrong block order is detected.
        """
        decryptor = Decryptor(private_key=private_key)
        random_file_data = (data_dir / "8k-random.ffe").read_bytes()
        file_path = tmp_path / "data.ffe"
        decrypted_file = tmp_path / "decrypted.data"
        # Split the file into its blocks.
        pos = 8
        magic = random_file_data[:pos]
        blocks = []
        while pos < len(random_file_data):
            block_size = int.from_bytes(random_file_data[pos + 4 : pos + 12], byteorder="big", signed=False)
            blocks.append(random_file_data[pos : pos + 12 + block_size])
            pos += 12 + block_size
        # Make sure our test is working properly.
        with file_path.open("wb") as f:
            f.write(magic)
            for d in blocks:
                f.write(d)
        decryptor.load_decrypted(source=file_path)
        # Randomly swap blocks in the file.
        random.seed(1200)
        for a, b in itertools.combinations(list(range(len(blocks))), 2):
            swapped = blocks.copy()
            swapped[a], swapped[b] = swapped[b], swapped[a]
            with file_path.open("wb") as f:
                f.write(magic)
                for d in swapped:
                    f.write(d)
            with pytest.raises(IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink()

    def test_wrong_key(self, private_key, data_dir, tmp_path):
        """
        Test if we can decrypt a file which was encrypted with the wrong key.
        """
        decryptor = Decryptor(private_key=private_key)
        decrypted_file = tmp_path / "decrypted.data"
        with pytest.raises(IntegrityError):
            decryptor.load_decrypted(source=data_dir / "8k-random-2nd-key.ffe")
        with pytest.raises(IntegrityError):
            decryptor.copy_decrypted(source=data_dir / "8k-random-2nd-key.ffe", destination=decrypted_file)

    def test_source_file_size_limit(self, tmp_path, public_key, monkeypatch):
        """
        Test copy_encrypted respects FILE_SIZE_LIMIT.
        """
        source_path = tmp_path / "source.data"
        destination_path = tmp_path / "destination.ffe"
        source_path.write_bytes(b"x" * 200)
        limit = 100
        monkeypatch.setattr("fast_file_encryption.encryptor.FILE_SIZE_LIMIT", limit)
        monkeypatch.setattr("fast_file_encryption.internals.FILE_SIZE_LIMIT", limit)
        encryptor = Encryptor(public_key=public_key)
        with pytest.raises(DataTooLargeError):
            encryptor.copy_encrypted(source=source_path, destination=destination_path)
