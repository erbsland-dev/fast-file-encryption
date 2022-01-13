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


import hashlib
import io
import json
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import IntegrityError, DataTooLargeError
from .internals import AES_BLOCK_SIZE_BYTES, \
    FILE_CONFIG_TEXT, FILE_MAGIC, KNOWN_BLOCK_TYPES, FILE_SIZE_LIMIT, WORKING_BLOCK_SIZE, AES_IV_LENGTH_BYTES, \
    SIZE_ENDIANNESS, SIZE_VALUE_LENGTH, AES_KEY_LENGTH_BYTES, ENCRYPTION_DATA_GAIN, CHUNK_SIZE_LENGTH, \
    CHUNKED_BLOCK_SIZE_VALUE, MAXIMUM_BLOCK_SIZE_VALUE


class Decryptor:
    """
    The encryptor provides methods to encrypt files.
    """

    def __init__(self, private_key: RSAPrivateKey):
        """
        Create a new decryptor object.

        :param private_key: The private key to use for decryption.
        """
        self.private_key = private_key  # The public key for the encryption.
        self.source_file_handle: Optional[io.BufferedIOBase] = None  # The current source file handle.
        self.algorithm: Optional[algorithms.CipherAlgorithm] = None  # The encryption algorithm which is used.
        # Generate the hash for the given public key of the private key.
        self.public_key_hash = hashlib.sha3_512(self.private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)).digest()
        # Cache for chunked reads
        self._current_chunk_size = 0

    def _verify_magic(self):
        """
        Verify the magic of the file.
        """
        file_magic = self.source_file_handle.read(len(FILE_MAGIC))
        if file_magic != FILE_MAGIC:
            raise IntegrityError('File magic does not match.')

    def _read_block_type(self) -> bytes:
        """
        Read the block type.

        :return: The block type.
        """
        block_type = self.source_file_handle.read(4)
        if len(block_type) < 4:
            raise IntegrityError('File is not complete.')
        if block_type not in KNOWN_BLOCK_TYPES:
            raise IntegrityError('Read unknown block type.')
        return block_type

    def _read_block_size(self) -> int:
        """
        Read the block size.

        :raises IntegrityError: If there is not enough data for the size.
        :return: The block size.
        """
        size_data = self.source_file_handle.read(SIZE_VALUE_LENGTH)
        if len(size_data) < SIZE_VALUE_LENGTH:
            raise IntegrityError('File is not complete.')
        return int.from_bytes(size_data, byteorder=SIZE_ENDIANNESS, signed=False)

    def _read_chunk_size(self) -> int:
        """
        Read and expect a chunk size.

        :raises IntegrityError: If there is not enough data for the size.
        :return: The chunk size.
        """
        size_data = self.source_file_handle.read(CHUNK_SIZE_LENGTH)
        if len(size_data) < CHUNK_SIZE_LENGTH:
            raise IntegrityError('File is not complete.')
        return int.from_bytes(size_data, byteorder=SIZE_ENDIANNESS, signed=False)

    def _read_iv(self) -> bytes:
        """
        Read an IV from the file.

        :return: The IV
        """
        iv = self.source_file_handle.read(AES_IV_LENGTH_BYTES)
        if len(iv) != AES_IV_LENGTH_BYTES:
            raise IntegrityError('File is not complete.')
        return iv

    def _start_reading_chunked_data(self):
        """
        Start reading chunked data from the current source.
        """
        self._current_chunk_size = self._read_chunk_size()

    def _read_chunked_data(self, maximum_bytes_to_read: int):
        """
        Read data from a chunked section of the stream.

        :param maximum_bytes_to_read: The maximum number of bytes to read.
        :return: A block with bytes, or empty bytes block if the end of the chunked section is reached.
        """
        if maximum_bytes_to_read <= 0:
            raise ValueError('Maximum bytes to read must be greater than zero.')
        if self._current_chunk_size == 0:  # Set the block to zero if we reached the end.
            return b''
        if maximum_bytes_to_read < self._current_chunk_size:
            block = self.source_file_handle.read(maximum_bytes_to_read)
            if len(block) < maximum_bytes_to_read:
                raise IntegrityError('File is not complete.')
            self._current_chunk_size -= len(block)
        else:
            block = bytearray(self.source_file_handle.read(self._current_chunk_size))
            if len(block) < self._current_chunk_size:
                raise IntegrityError('File is not complete.')
            self._current_chunk_size = self._read_chunk_size()
            maximum_bytes_to_read -= len(block)
            while self._current_chunk_size > 0 and maximum_bytes_to_read > 0:
                bytes_to_read = min(self._current_chunk_size, maximum_bytes_to_read)
                data = self.source_file_handle.read(bytes_to_read)
                if len(data) < bytes_to_read:
                    raise IntegrityError('File is not complete.')
                self._current_chunk_size -= bytes_to_read
                if self._current_chunk_size == 0:
                    self._current_chunk_size = self._read_chunk_size()
                maximum_bytes_to_read -= len(data)
                block.extend(data)
        return block

    def _read_chunked_block_data(self, maximum_size: int, user_limit: bool) -> bytes:
        """
        Read a block with chunked data.

        :param maximum_size: The maximum size for the data
        :param user_limit: If the limit is set by the user, which causes a `DataTooLargeError` exception.
        :return: The read data.
        """
        data = bytearray()
        while chunk_size := self._read_chunk_size():
            if len(data) + chunk_size > maximum_size:
                if user_limit:
                    raise DataTooLargeError('The data exceeds the requested limit.')
                raise IntegrityError('A block exceeds the size limit.')
            data_chunk = self.source_file_handle.read(chunk_size)
            if len(data_chunk) < chunk_size:
                raise IntegrityError('File is not complete.')
            data.extend(data_chunk)
        return data

    def _read_static_block_data(self, block_size: int, maximum_size: int, user_limit: bool) -> bytes:
        """
        Read a static data block.

        :param block_size: The read block size.
        :param maximum_size: The maximum size for the data.
        :param user_limit: If the limit is set by the user, which causes a `DataTooLargeError` exception.
        :return: The read data.
        """
        if block_size > maximum_size:
            if user_limit:
                raise DataTooLargeError('The data exceeds the requested limit.')
            raise IntegrityError('A block exceeds the size limit.')
        block_data = self.source_file_handle.read(block_size)
        if len(block_data) < block_size:
            raise IntegrityError('File is not complete.')
        return block_data

    def _read_block_header(self) -> Tuple[bytes, int]:
        """
        Read the header of the next block.

        :return: The block type and the block size.
        """
        block_type = self._read_block_type()
        block_size = self._read_block_size()
        return block_type, block_size

    def _read_block(self, maximum_size: int = 100_000, user_limit: bool = False,
                    allow_chunked: bool = False) -> Tuple[bytes, bytes]:
        """
        Read the next data block in the file.

        :param maximum_size: The maximum size for this block.
        :param user_limit: If the limit is set by the user, which causes a `DataTooLargeError` exception.
        :param allow_chunked: If chunked data is allowed when reading this block.
        :return: The block type, the data in the block.
        """
        block_type, block_size = self._read_block_header()
        chunked_data = False
        if block_size == 0:
            return block_type, b''
        if block_size == CHUNKED_BLOCK_SIZE_VALUE:
            if not allow_chunked:
                raise IntegrityError('A block has chunked data where no chunked data is allowed.')
            chunked_data = True
            block_type += b'c'  # Mark the block type as chunked.
        elif block_size >= MAXIMUM_BLOCK_SIZE_VALUE:
            raise IntegrityError('A block has an invalid block size.')
        if chunked_data:
            block_data = self._read_chunked_block_data(maximum_size, user_limit)
        else:
            block_data = self._read_static_block_data(block_size, maximum_size, user_limit)
        return block_type, block_data

    def _verify_configuration(self):
        """
        Read the file configuration and verify it.
        """
        block_type, block_data = self._read_block(maximum_size=128)
        if block_type != b'CONF':
            raise IntegrityError('Expecting `CONF` block, but found another.')
        if block_data != FILE_CONFIG_TEXT:
            raise IntegrityError('File configuration does not match expectations.')

    def _verify_public_key_hash(self):
        """
        Read and verify the public key hash.
        """
        block_type, block_data = self._read_block(maximum_size=64)
        if block_type != b'EPUB':
            raise IntegrityError('Expecting `EPUB` block, but found another.')
        if block_data != self.public_key_hash:
            raise IntegrityError('The key used to encrypt this file does not match the decryption key.')

    def _read_and_decrypt_key(self):
        """
        Read and decrypt the symmetric AES key.
        """
        block_type, block_data = self._read_block(maximum_size=1000)
        if block_type != b'ESYM':
            raise IntegrityError('Expecting `ESYM` block, but found another.')
        try:
            encryption_key = self.private_key.decrypt(
                block_data,
                OAEP(mgf=MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None))
        except ValueError as e:
            raise IntegrityError(f'Failed to read the symmetric key from the file. Error: {e}')
        if len(encryption_key) != AES_KEY_LENGTH_BYTES:
            raise IntegrityError('The decrypted key has an unexpected length.')
        self.algorithm = algorithms.AES(encryption_key)

    def _read_encrypted_block(self, expected_type: bytes, maximum_size: int = 100_000,
                              user_limit: bool = False) -> bytes:
        """
        Read and decrypt a block of data.

        :param expected_type: The expected type for the block.
        :param maximum_size: The maximum size of the decrypted data in the block.
        :param user_limit: If the maximum size is a limit set by the user.
        :return: The decrypted data from the block.
        """
        allow_chunked = (expected_type == b'DATA')
        block_type, block_data = self._read_block(maximum_size=maximum_size + ENCRYPTION_DATA_GAIN,
                                                  user_limit=user_limit,
                                                  allow_chunked=allow_chunked)
        is_chunked = False
        if block_type.endswith(b'c'):
            block_type = block_type[:4]
            is_chunked = True
        if block_type != expected_type:
            raise IntegrityError(f'Expecting `{expected_type.decode("utf-8")}` block, but found another.')
        if len(block_data) == 0:
            return b''
        if not is_chunked:
            if len(block_data) <= (SIZE_VALUE_LENGTH + AES_IV_LENGTH_BYTES):
                raise IntegrityError('The encrypted data is too short to be valid.')
            decrypted_size = int.from_bytes(block_data[:SIZE_VALUE_LENGTH], byteorder=SIZE_ENDIANNESS, signed=False)
            encrypted_size = len(block_data) - SIZE_VALUE_LENGTH - AES_IV_LENGTH_BYTES
            if decrypted_size > encrypted_size:
                raise IntegrityError(f'Decrypted size ({decrypted_size}) is larger than the actual block '
                                     f'size ({encrypted_size}).')
            if decrypted_size < 1:
                raise IntegrityError('The decrypted size is zero, which is not allowed at this point.')
            if encrypted_size % AES_BLOCK_SIZE_BYTES != 0:
                raise IntegrityError('The encrypted data does not align with the AES block size.')
            iv = block_data[SIZE_VALUE_LENGTH:AES_IV_LENGTH_BYTES + SIZE_VALUE_LENGTH]
            cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
            cipher_context = cipher.decryptor()
            data = cipher_context.update(block_data[AES_IV_LENGTH_BYTES + SIZE_VALUE_LENGTH:])
            data += cipher_context.finalize()
        else:  # Decrypt the chunked format.
            if len(block_data) <= AES_IV_LENGTH_BYTES:
                raise IntegrityError('The encrypted data is too short to be valid.')
            iv = block_data[:AES_IV_LENGTH_BYTES]
            encrypted_size = len(block_data) - AES_IV_LENGTH_BYTES
            if encrypted_size % AES_BLOCK_SIZE_BYTES != 0:
                raise IntegrityError('The encrypted data does not align with the AES block size.')
            cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
            cipher_context = cipher.decryptor()
            data = cipher_context.update(block_data[AES_IV_LENGTH_BYTES:])
            data += cipher_context.finalize()
            # Check the padding.
            try:
                index = data.rindex(b'\x80')
            except ValueError:
                raise IntegrityError('Invalid padding of the encrypted data: Missing padding mark.')
            if len(data) - index > AES_BLOCK_SIZE_BYTES:
                raise IntegrityError('Invalid padding of the encrypted data: Padding too large.')
            decrypted_size = index
        return data[:decrypted_size]

    def _read_and_verify_file_header(self):
        """
        Read and verify the initial portion of the file and read the encryption key.
        """
        self._verify_magic()
        self._verify_configuration()
        self._verify_public_key_hash()
        self._read_and_decrypt_key()

    def _read_metadata_block(self) -> Dict[str, Any]:
        """
        Read the metadata block and verify the checksum.
        """
        metadata_raw = self._read_encrypted_block(b'META', maximum_size=10_000)
        metadata_digest = self._read_encrypted_block(b'MDHA', maximum_size=1000)
        if len(metadata_raw) == 0:
            if len(metadata_digest) != 0:
                raise IntegrityError('The digest of the metadata block does not match.')
            return {}
        metadata_raw_digest = hashlib.sha3_512(metadata_raw).digest()
        if metadata_digest != metadata_raw_digest:
            raise IntegrityError('The digest of the metadata block does not match.')
        metadata = json.loads(metadata_raw)
        if not isinstance(metadata, dict):
            raise IntegrityError('The received metadata block was no object.')
        return metadata

    def _skip_block(self, expected_type: bytes):
        """
        Skip a block

        :param expected_type: The block type to skip.
        """
        block_type, _ = self._read_block()
        if block_type != expected_type:
            raise IntegrityError(f'Expecting `{expected_type.decode("utf-8")}` block, but found another.')

    def read_metadata(self, source: Path) -> Dict[str, Any]:
        """
        Only decrypt and read the metadata from a file.

        :param source: The file to read the metadata.
        :return: The dictionary with the metadata.
        """
        if (file_size := source.stat().st_size) < 256:
            raise IntegrityError(f'File is too short to be valid. (size={file_size})')
        with source.open('rb') as source_file_handle:
            self.source_file_handle = source_file_handle
            self._read_and_verify_file_header()
            metadata = self._read_metadata_block()
            # Stop at this point and ignore the rest of the file.
        return metadata

    def load_decrypted(self, source: Path, maximum_size: int = 10_000_000) -> bytes:
        """
        Load and decrypt the given source file.

        :param source: Load and decrypt the given source file.
        :param maximum_size: The maximum size of the decrypted data.
            This is no exact limit, because it is tested using the size of the encrypted data.
            The returned data may be up to 127 bytes larger than the given limit.
        :return: The decrypted data.
        :raises DataTooLargeError: If the maximum size would be exceeded.
        :raises IntegrityError: On any file integrity problem.
        """
        if (file_size := source.stat().st_size) < 256:
            raise IntegrityError(f'File is too short to be valid. (size={file_size})')
        with source.open('rb') as source_file_handle:
            self.source_file_handle = source_file_handle
            self._read_and_verify_file_header()
            self._skip_block(b'META')
            self._skip_block(b'MDHA')
            decrypted_data = self._read_encrypted_block(b'DATA',
                                                        maximum_size=maximum_size + AES_BLOCK_SIZE_BYTES,
                                                        user_limit=True)
            file_digest = self._read_encrypted_block(b'DTHA')
        if not decrypted_data:  # Zero file?
            if file_digest:
                raise IntegrityError('The digest of the data block does not match.')
            return b''
        decrypted_data_digest = hashlib.sha3_512(decrypted_data).digest()
        if file_digest != decrypted_data_digest:
            raise IntegrityError('The digest of the data block does not match.')
        return decrypted_data

    def _decrypt_chunked_block(self, destination: io.BufferedIOBase) -> bytes:
        """
        Read an encrypted chunked block from the current source.

        :param destination: The destination stream to write the decrypted data.
        :return: The digest of the decrypted data.
        """
        block_hash_context = hashlib.sha3_512()
        total_size = 0
        self._start_reading_chunked_data()
        iv = self._read_chunked_data(AES_IV_LENGTH_BYTES)
        if len(iv) != AES_IV_LENGTH_BYTES:
            raise IntegrityError('File is not complete.')
        cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
        cipher_context = cipher.decryptor()
        decrypted_data = b''
        while encrypted_data := self._read_chunked_data(WORKING_BLOCK_SIZE):
            # Delay writing of the decrypted data, because we need to handle the padding at the end of the file.
            if decrypted_data:
                destination.write(decrypted_data)
                block_hash_context.update(decrypted_data)
                total_size += len(decrypted_data)
            # The encrypted data must be aligned the with the working block size.
            if len(encrypted_data) % AES_BLOCK_SIZE_BYTES != 0:
                raise IntegrityError('File is not complete: Misaligned encrypted data.')
            decrypted_data = cipher_context.update(encrypted_data)
        decrypted_data += cipher_context.finalize()  # This should not add any additional data.
        # At this point, we have the last decrypted block.
        if not decrypted_data:
            raise IntegrityError('Unexpected end of encrypted data stream.')
        if len(decrypted_data) % AES_BLOCK_SIZE_BYTES != 0:
            raise IntegrityError('Decrypted data does not align with the encryption block size.')
        try:
            index = decrypted_data.rindex(b'\x80')
        except ValueError:
            raise IntegrityError('Invalid padding of the encrypted stream: Missing padding mark.')
        if len(decrypted_data) - index > AES_BLOCK_SIZE_BYTES:
            raise IntegrityError('Invalid padding of the encrypted stream: Padding too large.')
        decrypted_data = decrypted_data[:index]  # crop the last block.
        if decrypted_data:
            destination.write(decrypted_data)
            block_hash_context.update(decrypted_data)
            total_size += len(decrypted_data)
        return block_hash_context.digest()

    def _decrypt_static_block(self, encrypted_block_size: int, destination: io.BufferedIOBase) -> bytes:
        """
        Read an encrypted static block from the current source.

        :param encrypted_block_size: The size of the encrypted block.
        :param destination: The destination stream to write the decrypted data.
        :return: The digest of the decrypted data.
        """
        if encrypted_block_size > (FILE_SIZE_LIMIT + 1000):  # > 10TB?
            raise IntegrityError('The file size is larger than 10TB, which is not supported.')
        if encrypted_block_size == 0:
            return b''  # Empty data requires an empty digest.
        block_hash_context = hashlib.sha3_512()
        encrypted_size = encrypted_block_size - SIZE_VALUE_LENGTH - AES_IV_LENGTH_BYTES
        decrypted_size = self._read_block_size()
        if decrypted_size > encrypted_size:
            raise IntegrityError('The decrypted data size is larger than the encrypted data.')
        iv = self._read_iv()
        cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
        cipher_context = cipher.decryptor()
        encrypted_data_left = encrypted_size
        decrypted_data_left = decrypted_size
        while encrypted_data_left > 0:
            data_to_read = min(WORKING_BLOCK_SIZE, encrypted_data_left)
            encrypted_data = self.source_file_handle.read(data_to_read)
            if len(encrypted_data) < data_to_read:
                raise IntegrityError('File is not complete.')
            decrypted_data = cipher_context.update(encrypted_data)
            if decrypted_data_left < len(decrypted_data):
                decrypted_data = decrypted_data[:decrypted_data_left]
            destination.write(decrypted_data)
            block_hash_context.update(decrypted_data)
            encrypted_data_left -= len(encrypted_data)
            decrypted_data_left -= len(decrypted_data)
        # For the AES/CBC cipher, there is usually no data generated with finalize, because the data
        # is decrypted block wise. The following code is in place, in case the cipher is changed.
        decrypted_data = cipher_context.finalize()
        if decrypted_data and decrypted_data_left > 0:
            decrypted_data = decrypted_data[:decrypted_data_left]
            destination.write(decrypted_data)
            block_hash_context.update(decrypted_data)
        # At this point the decrypted data has its final length. Return the digest.
        return block_hash_context.digest()

    def _decrypt_stream(self, source_io: io.BufferedIOBase, destination_io: io.BufferedIOBase):
        """
        Decrypt a file from a source stream and write the decrypted data into the target stream.

        :param source_io: The source stream to use for decryption.
        :param destination_io: The destination stream to write the decrypted data into
        """
        self.source_file_handle = source_io
        self._read_and_verify_file_header()
        self._skip_block(b'META')
        self._skip_block(b'MDHA')
        block_type, encrypted_block_size = self._read_block_header()
        if block_type != b'DATA':
            raise IntegrityError('Expected `DATA` block, but found another one.')
        if encrypted_block_size == CHUNKED_BLOCK_SIZE_VALUE:
            data_digest = self._decrypt_chunked_block(destination_io)
        elif encrypted_block_size >= MAXIMUM_BLOCK_SIZE_VALUE:
            raise IntegrityError('The block has an invalid size value.')
        else:
            data_digest = self._decrypt_static_block(encrypted_block_size, destination_io)
        file_digest = self._read_encrypted_block(b'DTHA')
        if file_digest != data_digest:
            raise IntegrityError('The digest of the data block does not match.')

    def copy_decrypted(self, source: Path, destination: Path):
        """
        Copy an encrypted file decrypted at the destination.

        :param source: The path to the encrypted source file.
        :param destination: The path to the decrypted destination file.
        :raises IntegrityError: On any file integrity problem.
        """
        if not source:
            raise ValueError('Missing parameter `source`')
        if not destination:
            raise ValueError('Missing parameter `destination`')
        if not isinstance(source, Path):
            raise ValueError('Parameter `source` has to be a `Path` from `pathlib`.')
        if not isinstance(destination, Path):
            raise ValueError('Parameter `destination` has to be a `Path` from `pathlib`.')
        if (file_size := source.stat().st_size) < 256:
            raise IntegrityError(f'File is too short to be valid. (size={file_size})')
        try:
            with source.open('rb') as source_io, destination.open('wb') as destination_io:
                self._decrypt_stream(source_io, destination_io)
        except IntegrityError:
            destination.unlink(missing_ok=True)
            raise

    def stream_decrypted(self, source_io: io.BufferedIOBase, destination_io: io.BufferedIOBase):
        """
        Decrypt the data from the source stream and write it to the destination stream.

        Both streams have to be open and need to be readable/writable. The implementation only
        uses the `read` method on the source stream and the `write` method on the destination stream.

        :param source_io: The open source stream.
        :param destination_io: The open destination stream.
        """
        if not source_io:
            raise ValueError('Missing parameter `source_io`')
        if not destination_io:
            raise ValueError('Missing parameter `destination_io`')
        if not isinstance(source_io, io.BufferedIOBase):
            raise ValueError('The parameter `source_io` has to be a subclass of `io.BufferedIOBase`')
        if not isinstance(destination_io, io.BufferedIOBase):
            raise ValueError('The parameter `destination_io` has to be a subclass of `io.BufferedIOBase`')
        self._decrypt_stream(source_io, destination_io)
