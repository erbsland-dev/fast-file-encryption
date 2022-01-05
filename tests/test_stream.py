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

import fast_file_encryption as ffe


class TestStream:

    def test_streaming(self, data_dir, tmp_path, public_key, private_key):
        """
        Test if streaming encryption works as expected.
        """
        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        source_path = data_dir / '8k-random.data'
        destination_path = tmp_path / 'encrypted.ffe'
        with source_path.open('rb') as source_io, destination_path.open('wb') as destination_io:
            encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
        assert destination_path.is_file()
        assert destination_path.stat().st_size > 200
        decrypted_data = decryptor.load_decrypted(destination_path)
        assert decrypted_data == source_path.read_bytes()

    def test_empty_stream(self, tmp_path, public_key, private_key):
        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        source_io = io.BytesIO(bytes())
        destination_path = tmp_path / 'encrypted.ffe'
        with destination_path.open('wb') as destination_io:
            encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
        assert destination_path.is_file()
        assert destination_path.stat().st_size > 100
        decrypted_data = decryptor.load_decrypted(destination_path)
        assert decrypted_data == bytes()

    def test_short_stream(self, tmp_path, public_key, private_key):
        encryptor = ffe.Encryptor(public_key)
        decryptor = ffe.Decryptor(private_key)
        source_io = io.BytesIO(bytes(1000))
        destination_path = tmp_path / 'encrypted.ffe'
        with destination_path.open('wb') as destination_io:
            encryptor.stream_encrypted(source_io=source_io, destination_io=destination_io)
        assert destination_path.is_file()
        assert destination_path.stat().st_size > 100
        decrypted_data = decryptor.load_decrypted(destination_path)
        assert decrypted_data == bytes(1000)
