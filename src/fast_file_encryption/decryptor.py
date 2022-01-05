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
import json
from pathlib import Path
from typing import BinaryIO, Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import IntegrityError, DataTooLargeError
from .internals import AES_BLOCK_SIZE_BYTES, \
    FILE_CONFIG_TEXT, FILE_MAGIC, KNOWN_BLOCK_TYPES, FILE_SIZE_LIMIT, WORKING_BLOCK_SIZE, AES_IV_LENGTH_BYTES, \
    SIZE_ENDIANNESS, SIZE_VALUE_LENGTH, AES_KEY_LENGTH_BYTES, ENCRYPTION_DATA_GAIN


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
        self.source_file_handle: Optional[BinaryIO] = None  # The current source file handle.
        self.algorithm: Optional[algorithms.CipherAlgorithm] = None  # The encryption algorithm which is used.
        # Generate the hash for the given public key of the private key.
        self.public_key_hash = hashlib.sha3_512(self.private_key.public_key().public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)).digest()

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

        :return: The block size.
        """
        size_data = self.source_file_handle.read(SIZE_VALUE_LENGTH)
        if len(size_data) < SIZE_VALUE_LENGTH:
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

    def _read_block(self, maximum_size: int = 100_000, user_limit: bool = False) -> Tuple[bytes, bytes]:
        """
        Read the next data block in the file.

        :param maximum_size: The maximum size for this block.
        :param user_limit: If the limit is set by the user, which causes a `DataTooLargeError` exception.
        :return: The block type, the data in the block.
        """
        block_type = self._read_block_type()
        block_size = self._read_block_size()
        if block_size == 0:
            return block_type, b''
        if block_size > maximum_size:
            if user_limit:
                raise DataTooLargeError('The data exceeds the requested limit.')
            raise IntegrityError('A block exceeds the size limit.')
        block_data = self.source_file_handle.read(block_size)
        if len(block_data) < block_size:
            raise IntegrityError('File is not complete.')
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
        block_type, block_data = self._read_block(maximum_size=maximum_size + ENCRYPTION_DATA_GAIN,
                                                  user_limit=user_limit)
        if block_type != expected_type:
            raise IntegrityError(f'Expecting `{expected_type.decode("utf-8")}` block, but found another.')
        if len(block_data) == 0:
            return b''
        if len(block_data) <= (SIZE_VALUE_LENGTH + AES_IV_LENGTH_BYTES):
            raise IntegrityError('The encrypted data is too short to be valid.')
        decrypted_size = int.from_bytes(block_data[:SIZE_VALUE_LENGTH], byteorder=SIZE_ENDIANNESS, signed=False)
        encrypted_size = len(block_data) - SIZE_VALUE_LENGTH - AES_BLOCK_SIZE_BYTES
        if decrypted_size > encrypted_size:
            raise IntegrityError(f'Decrypted size ({decrypted_size}) is larger than the actual block '
                                 f'size ({encrypted_size}).')
        if decrypted_size < 1:
            raise IntegrityError(f'The decrypted size is zero, which is not allowed at this point.')
        iv = block_data[SIZE_VALUE_LENGTH:AES_BLOCK_SIZE_BYTES + SIZE_VALUE_LENGTH]
        cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
        cipher_context = cipher.decryptor()
        data = cipher_context.update(block_data[AES_BLOCK_SIZE_BYTES + SIZE_VALUE_LENGTH:])
        data += cipher_context.finalize()
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

    def copy_decrypted(self, source: Path, destination: Path):
        """
        Copy a encrypted file decrypted at the destination.

        :param source: The path to the encrypted source file.
        :param destination: The path to the unencrypted destination file.
        :raises IntegrityError: On any file integrity problem.
        """
        if (file_size := source.stat().st_size) < 256:
            raise IntegrityError(f'File is too short to be valid. (size={file_size})')
        with source.open('rb') as source_file_handle:
            self.source_file_handle = source_file_handle
            self._read_and_verify_file_header()
            self._skip_block(b'META')
            self._skip_block(b'MDHA')
            block_type = self._read_block_type()
            if block_type != b'DATA':
                raise IntegrityError('Expected `DATA` block, but found another one.')
            encrypted_block_size = self._read_block_size()
            if encrypted_block_size > (FILE_SIZE_LIMIT + 1000):  # > 1TB?
                raise IntegrityError('The file size is larger than 1TB, which is not supported.')
            if encrypted_block_size == 0:
                block_data = self._read_encrypted_block(b'DTHA', maximum_size=1000)
                if block_data:
                    raise IntegrityError('The digest of the data block does not match.')
                # "Overwrite" previous file with a zero file in the fastest way possible.
                with destination.open('wb') as _:
                    pass
                return  # done
            block_hash_context = hashlib.sha3_512()
            with destination.open('wb') as destination_file_handle:
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
                    encrypted_data = source_file_handle.read(data_to_read)
                    if len(encrypted_data) < data_to_read:
                        raise IntegrityError('File is not complete.')
                    decrypted_data = cipher_context.update(encrypted_data)
                    if decrypted_data_left < len(decrypted_data):
                        decrypted_data = decrypted_data[:decrypted_data_left]
                    destination_file_handle.write(decrypted_data)
                    block_hash_context.update(decrypted_data)
                    encrypted_data_left -= len(encrypted_data)
                    decrypted_data_left -= len(decrypted_data)
                # For the AES/CBC cipher, there is usually no data generated with finalize, because the data
                # is decrypted block wise. The following code is in place, in case the cipher is changed.
                decrypted_data = cipher_context.finalize()
                if decrypted_data and decrypted_data_left > 0:
                    decrypted_data = decrypted_data[:decrypted_data_left]
                    destination_file_handle.write(decrypted_data)
                    block_hash_context.update(decrypted_data)
                # At this point the decrypted has its final length.
            file_digest = self._read_encrypted_block(b'DTHA')
            decrypted_file_digest = block_hash_context.digest()
            if file_digest != decrypted_file_digest:
                # Delete the corrupted file.
                destination.unlink()
                raise IntegrityError('The digest of the data block does not match.')
        # Successfully decrypted the file.
