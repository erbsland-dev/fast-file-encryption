# Copyright 2021 by Tobias Erbsland / EducateIT GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import io
import random

import fast_file_encryption as ffe
from shared import *


class TestStream:

    def test_known_8k_data(self, data_dir, tmp_path, private_key):
        """
        Test if known 8k data, encrypted from a stream can be decrypted.
        """
        decryptor = ffe.Decryptor(private_key)
        original_path = data_dir / '8k-random.data'
        encrypted_path = data_dir / '8k-random-chunked.ffe'
        decrypted_path = tmp_path / 'decrypted.data'
        original_data = original_path.read_bytes()
        decrypted_data = decryptor.load_decrypted(encrypted_path)
        assert decrypted_data == original_data
        # Also test the copy_decrypted, as it used a different implementation.
        decryptor.copy_decrypted(encrypted_path, decrypted_path)
        decrypted_data = decrypted_path.read_bytes()
        assert decrypted_data == original_data

    def test_streaming(self, data_dir, tmp_path, public_key, private_key):
        """
        Test if streaming encryption works as expected.
        """
        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        source_path = data_dir / '8k-random.data'
        destination_path = tmp_path / 'encrypted.ffe'
        decrypted_path = tmp_path / 'decrypted.data'
        with source_path.open('rb') as source_io, destination_path.open('wb') as destination_io:
            encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
        assert destination_path.is_file()
        assert destination_path.stat().st_size > 200
        decrypted_data = decryptor.load_decrypted(destination_path)
        original_data = source_path.read_bytes()
        assert decrypted_data == original_data
        # Also test the copy_decrypted, as it used a different implementation.
        decryptor.copy_decrypted(destination_path, decrypted_path)
        decrypted_data = decrypted_path.read_bytes()
        assert decrypted_data == original_data

    def test_empty_stream(self, tmp_path, public_key, private_key):
        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        source_io = io.BytesIO(bytes())
        destination_path = tmp_path / 'encrypted.ffe'
        decrypted_path = tmp_path / 'decrypted.data'
        with destination_path.open('wb') as destination_io:
            encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
        assert destination_path.is_file()
        assert destination_path.stat().st_size > 100
        decrypted_data = decryptor.load_decrypted(destination_path)
        assert decrypted_data == bytes()
        # Also test the copy_decrypted, as it used a different implementation.
        decryptor.copy_decrypted(destination_path, decrypted_path)
        decrypted_data = decrypted_path.read_bytes()
        assert decrypted_data == bytes()

    def test_random_length_streams(self, tmp_path, public_key, private_key):
        random.seed(9287)
        lengths = [
            1, 2, 3, 4, 8, 10, 12,  # Problematic short
            16, 20, 24, 32, 64, 101, 128, 256,  # Alignment problems?
            4095, 4096, 4097, 4096 * 2,  # Alignment problems?
            0xfffe, 0xffff, 0x10000,  # Chunked data problems?
            0x24001  # Multiple blocks.
        ]
        for length in lengths:
            encryptor = ffe.Encryptor(public_key)
            decryptor = ffe.Decryptor(private_key)
            original_data = random.randbytes(length)
            source_io = io.BytesIO(original_data)
            destination_path = tmp_path / 'encrypted.ffe'
            decrypted_path = tmp_path / 'decrypted.data'
            with destination_path.open('wb') as destination_io:
                encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
            assert destination_path.is_file()
            assert destination_path.stat().st_size > 100
            decrypted_data = decryptor.load_decrypted(destination_path)
            assert decrypted_data == original_data
            # Also test the copy_decrypted, as it used a different implementation.
            decryptor.copy_decrypted(destination_path, decrypted_path)
            decrypted_data = decrypted_path.read_bytes()
            assert decrypted_data == original_data

    def test_bit_flips(self, tmp_path, private_key, data_dir):
        """
        Test if single bit flips are detected.
        """
        decryptor = ffe.Decryptor(private_key=private_key)
        file_path = tmp_path / 'data.ffe'
        decrypted_file = tmp_path / 'decrypted.data'
        random_file_data = (data_dir / '8k-random-chunked.ffe').read_bytes()
        random.seed(39283)
        for _ in range(100):
            data = bytearray(random_file_data)
            pos = random.randint(0, len(data))
            bit_mask = 1 << (random.randint(0, 7))
            data[pos] ^= bit_mask
            file_path.write_bytes(data)
            with pytest.raises(ffe.IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(ffe.IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)

    def test_incomplete_files(self, private_key, tmp_path, data_dir):
        decryptor = ffe.Decryptor(private_key=private_key)
        file_path = tmp_path / 'data.ffe'
        decrypted_file = tmp_path / 'decrypted.data'
        random_file_data = (data_dir / '8k-random-chunked.ffe').read_bytes()
        random.seed(29839)
        for _ in range(100):  # Test a number of random sizes cover more cases
            data = bytearray(random_file_data[:random.randint(1, len(random_file_data) - 1)])
            file_path.write_bytes(data)
            with pytest.raises(ffe.IntegrityError):
                decryptor.load_decrypted(source=file_path)
            with pytest.raises(ffe.IntegrityError):
                decryptor.copy_decrypted(source=file_path, destination=decrypted_file)
            file_path.unlink(missing_ok=True)

    def test_stream_decryption(self, private_key, data_dir, tmp_path):
        decryptor = ffe.Decryptor(private_key=private_key)
        random_file = data_dir / '8k-random.ffe'
        original_data = data_dir / '8k-random.data'
        decrypted_file = tmp_path / 'decrypted.data'
        with random_file.open('rb') as source_io, decrypted_file.open('wb') as destination_io:
            decryptor.stream_decrypted(source_io, destination_io)
        assert original_data.read_bytes() == decrypted_file.read_bytes()

    def test_stream_features(self, public_key, private_key, data_dir, tmp_path):
        class MinimalReader(io.BufferedIOBase):
            def __init__(self):
                self.buffer = bytes()

            def writable(self) -> bool:
                return False

            def readable(self) -> bool:
                return True

            def seekable(self) -> bool:
                return False

            def read(self, size: int) -> bytes:
                if not self.buffer:
                    return b''
                b = min(size, len(self.buffer))
                result = bytes(self.buffer[:b])
                del self.buffer[:b]
                return result

            def read1(self, size: int) -> bytes:
                return self.read(size)

        class MinimalWriter(io.BufferedIOBase):
            def __init__(self):
                self.buffer = bytearray()

            def writable(self) -> bool:
                return True

            def readable(self) -> bool:
                return False

            def seekable(self) -> bool:
                return False

            def write(self, buffer: bytes) -> int:
                self.buffer.extend(buffer)
                return len(buffer)

            def flush(self) -> None:
                raise ValueError('Do not use flush.')

        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        original_data = b'data' + bytes(1_000_000) + b'data'
        minimal_reader = MinimalReader()
        minimal_writer = MinimalWriter()
        minimal_reader.buffer = bytearray(original_data)
        encryptor.stream_encrypted(source_io=minimal_reader, destination_io=minimal_writer)
        minimal_reader.buffer = minimal_writer.buffer.copy()
        minimal_writer.buffer = bytearray()
        decryptor.stream_decrypted(minimal_reader, minimal_writer)
        assert original_data == minimal_writer.buffer
