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
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher, CipherContext
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .errors import DataTooLargeError
from .internals import AES_BLOCK_SIZE_BYTES, \
    FILE_CONFIG_TEXT, FILE_MAGIC, KNOWN_BLOCK_TYPES, FILE_SIZE_LIMIT, WORKING_BLOCK_SIZE, SIZE_ENDIANNESS, \
    SIZE_VALUE_LENGTH, AES_KEY_LENGTH_BYTES, CHUNK_SIZE_LENGTH, MAXIMUM_CHUNK_SIZE, CHUNKED_BLOCK_SIZE_VALUE


class Encryptor:
    """
    The encryptor provides methods to encrypt files.
    """

    def __init__(self, public_key: RSAPublicKey):
        """
        Create a new encryptor object.

        :param public_key: The public key to use for encryption.
        """
        self.public_key = public_key  # The public key for the encryption.
        self.destination_file_digest = None  # The overall file digest to use.
        self.destination_file_handle: Optional[io.BufferedIOBase] = None  # The current target file handle.
        self.algorithm: Optional[algorithms.CipherAlgorithm] = None  # The encryption algorithm which is used.
        # Generate the hash for the given public key.
        self.public_key_hash = hashlib.sha3_512(self.public_key.public_bytes(
            encoding=Encoding.DER, format=PublicFormat.SubjectPublicKeyInfo)).digest()
        self._chunked_buffer = bytearray()  # A buffer to write chunked data more efficient.

    def _write_with_digest(self, data: bytes):
        """
        Write to the destination file and add to the digest.

        :param data: The data block to write.
        """
        self.destination_file_handle.write(data)
        if self.destination_file_digest:
            self.destination_file_digest.update(data)

    def _write_magic(self):
        """
        Write the magic header to the file.
        """
        self._write_with_digest(FILE_MAGIC)

    def _write_block(self, block_type: bytes, data: bytes):
        """
        Write a data block to the file handle.

        :param block_type: The block type.
        :param data: The data for the block.
        """
        if len(block_type) != 4:
            raise ValueError('Block type must be 4 bytes')
        if len(data) > 100_000:
            raise ValueError('Block data exceeds 100k')
        if block_type not in KNOWN_BLOCK_TYPES:
            raise ValueError('Block type is not known.')
        self._write_with_digest(block_type)
        size_data = len(data).to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False)
        self._write_with_digest(size_data)
        self._write_with_digest(data)

    def _write_chunked_block_header(self, block_type: bytes):
        """
        Write the header for a chunked block.

        :param block_type: The block type.
        """
        if len(block_type) != 4:
            raise ValueError('Block type must be 4 bytes')
        if block_type != b'DATA':
            raise ValueError('Only `DATA` blocks can use the chunked data format.')
        self._write_with_digest(block_type)
        size_data = CHUNKED_BLOCK_SIZE_VALUE.to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False)
        self._write_with_digest(size_data)

    def _write_configuration(self):
        """
        Write the block with the encryption configuration.
        """
        self._write_block(b'CONF', FILE_CONFIG_TEXT)

    def _write_public_key_hash(self):
        """
        Write the hash of the public key
        """
        self._write_block(b'EPUB', self.public_key_hash)

    def _create_and_write_encryption_key(self):
        """
        Create the encryption key and encrypt it.
        """
        # Generate the random encryption key for this file.
        encryption_key = os.urandom(AES_KEY_LENGTH_BYTES)
        # Encrypt the encryption key and store it in the file.
        encrypted_encryption_key = self.public_key.encrypt(
            encryption_key,
            OAEP(
                mgf=MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        # Write the encrypted encryption key.
        self._write_block(b'ESYM', encrypted_encryption_key)
        self.algorithm = algorithms.AES(encryption_key)

    def _prepare_encryption(self) -> Tuple[CipherContext, bytes]:
        """
        Prepare the encryption.

        Creates a new cipher context and a random initialization vector.

        :return: The cipher context, IV
        """
        iv = os.urandom(AES_BLOCK_SIZE_BYTES)  # Create a random IV
        cipher = Cipher(self.algorithm, modes.CBC(iv))  # Create the cipher context
        cipher_context = cipher.encryptor()
        return cipher_context, iv

    def _write_encrypted_block(self, block_type: bytes, data: bytes):
        """
        Write a block of encrypted data.

        :param block_type: The four letter block type.
        :param data: The data of the block.
        """
        cipher_context, iv = self._prepare_encryption()
        encrypted_data = len(data).to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False)
        encrypted_data += iv
        padding = b''
        if (last_short_block := len(data) % AES_BLOCK_SIZE_BYTES) > 0:
            padding = os.urandom(AES_BLOCK_SIZE_BYTES - last_short_block)
        encrypted_data += cipher_context.update(data + padding)
        encrypted_data += cipher_context.finalize()
        self._write_block(block_type, encrypted_data)

    def _write_file_header(self):
        """
        Write the initial portion of the file.
        """
        self._write_magic()
        self._write_configuration()
        self._write_public_key_hash()
        self._create_and_write_encryption_key()

    def _write_meta_data(self, meta: Dict[str, Any]):
        """
        Write the meta data to the file.

        :param meta: The dictionary with the meta data.
        """
        if not meta:
            self._write_block(b'META', b'')
            self._write_block(b'MDHA', b'')
            return
        meta_data = json.dumps(meta).encode('utf-8')
        self._write_encrypted_block(b'META', meta_data)
        # Write the hash of the metadata.
        self._write_encrypted_block(b'MDHA', hashlib.sha3_512(meta_data).digest())

    def _write_bytes_data(self, source_data: bytes):
        """
        Write the bytes data encrypted to the destination

        :param source_data: The bytes object with the data to write.
        """
        source_size = len(source_data)
        if source_size == 0:
            # Write two empty blocks for empty files. This is safer than writing encryption data.
            self._write_block(b'DATA', b'')
            self._write_block(b'DTHA', b'')
            return
        self._write_encrypted_block(b'DATA', source_data)
        self._write_encrypted_block(b'DTHA', hashlib.sha3_512(source_data).digest())

    def _write_file_data(self, source_size: int, sf: io.BufferedIOBase):
        """
        Write the  file data encrypted to the destination.

        :param source_size: The size of the source file.
        :param sf: The open source file handle.
        """
        if source_size == 0:
            # Write two empty blocks for empty files. This is safer than writing encryption data.
            self._write_block(b'DATA', b'')
            self._write_block(b'DTHA', b'')
            return
        encryptor, iv = self._prepare_encryption()
        self._write_with_digest(b'DATA')  # Write the block type.
        # Calculate and write the size of the encrypted data.
        padding = b''
        if (last_short_block := source_size % AES_BLOCK_SIZE_BYTES) > 0:
            padding = os.urandom(AES_BLOCK_SIZE_BYTES - last_short_block)
        encrypted_data_size = SIZE_VALUE_LENGTH + len(iv) + source_size + len(padding)
        self._write_with_digest(
            encrypted_data_size.to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False))
        # Write the unencrypted size.
        self._write_with_digest(source_size.to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False))
        # Write the IV
        self._write_with_digest(iv)
        # Encrypt and write the actual data.
        block_hash_context = hashlib.sha3_512()
        while block := sf.read(WORKING_BLOCK_SIZE):
            block_hash_context.update(block)
            if len(block) < WORKING_BLOCK_SIZE:
                block += padding
            self._write_with_digest(encryptor.update(block))
        self._write_with_digest(encryptor.finalize())
        # Write the hash of the original data.
        self._write_encrypted_block(b'DTHA', block_hash_context.digest())

    def _write_data_chunk(self, data: bytes):
        """
        Write a single data chunk to the target stream

        :param data: The data to write.
        """
        self._write_with_digest(len(data).to_bytes(CHUNK_SIZE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False))
        if data:
            self._write_with_digest(data)

    def _write_chunked_data(self, data: bytes):
        """
        Write data in chunked format.

        :param data: The data block to write in the chunked format.
        """
        if not data:
            return
        self._chunked_buffer.extend(data)
        if len(self._chunked_buffer) >= MAXIMUM_CHUNK_SIZE:
            self._write_data_chunk(self._chunked_buffer[:MAXIMUM_CHUNK_SIZE])
            del self._chunked_buffer[:MAXIMUM_CHUNK_SIZE]

    def _flush_chunked_data(self):
        """
        Make sure any remaining chunked data is written.
        """
        if len(self._chunked_buffer) > 0:
            self._write_data_chunk(self._chunked_buffer)
        self._write_data_chunk(bytes())
        self._chunked_buffer.clear()

    def _stream_data(self, source_file_handle: io.BufferedIOBase):
        """
        Stream the encrypted data to the target stream.

        :param source_file_handle: The open source stream.
        """
        block = source_file_handle.read(WORKING_BLOCK_SIZE)
        if len(block) == 0:
            # Write two empty blocks for empty files. This is safer than writing encryption data.
            self._write_block(b'DATA', b'')
            self._write_block(b'DTHA', b'')
            return
        elif len(block) < WORKING_BLOCK_SIZE:
            self._write_encrypted_block(b'DATA', block)
            self._write_encrypted_block(b'DTHA', hashlib.sha3_512(block).digest())
            return
        encryptor, iv = self._prepare_encryption()
        self._write_chunked_block_header(b'DATA')
        # Write the IV
        self._write_chunked_data(iv)
        # Encrypt the first block
        block_hash_context = hashlib.sha3_512()
        block_hash_context.update(block)
        self._write_chunked_data(encryptor.update(block))
        # Encrypt all following blocks
        last_block = b''
        while block := source_file_handle.read(WORKING_BLOCK_SIZE):
            if last_block:
                self._write_chunked_data(encryptor.update(last_block))
            block_hash_context.update(block)
            last_block = block
        # At this point, we always get the last read block which was not encrypted yet.
        # Always apply ISO/IEC 9797-1 padding method 2 to the last block (even it is empty)
        last_block += b'\x80'
        misalignment = len(last_block) % AES_BLOCK_SIZE_BYTES
        if misalignment:
            last_block += bytes(AES_BLOCK_SIZE_BYTES - misalignment)
        self._write_chunked_data(encryptor.update(last_block))
        self._write_chunked_data(encryptor.finalize())
        # End the chunked data stream
        self._flush_chunked_data()
        # Write the hash of the original data.
        self._write_encrypted_block(b'DTHA', block_hash_context.digest())

    def _write_end_with_hash(self):
        """
        Write the end mark with the file hash.
        """
        self.destination_file_handle.write(b'ENDH')
        file_digest = self.destination_file_digest.digest()
        self.destination_file_handle.write(
            len(file_digest).to_bytes(SIZE_VALUE_LENGTH, byteorder=SIZE_ENDIANNESS, signed=False))
        self.destination_file_handle.write(file_digest)
        self.destination_file_handle.flush()

    def _clean_up(self):
        """
        Remove information not needed after encryption.
        """
        self.destination_file_handle = None
        self.destination_file_digest = None
        self.algorithm = None
        self._chunked_buffer.clear()

    @staticmethod
    def _verify_metadata(meta: Dict[str, Any]):
        """
        Check if the metadata has the right format.

        :param meta: An existing metadata dictionary or `None`.
        """
        if meta:
            if not isinstance(meta, dict):
                raise ValueError('Metadata has to be a dictionary.')
            for key in meta.keys():
                if not isinstance(key, str):
                    raise ValueError('Metadata keys have to be strings.')

    @staticmethod
    def _add_source_metadata(source: Path, meta: Dict[str, Any]) -> Dict[str, Any]:
        """
        Add the metadata from the source file.

        :param source: The source file.
        :param meta: The existing metadata.
        :return: The new metadata.
        """
        if not meta:
            meta = {}
        else:
            meta = meta.copy()
        if 'file_path' not in meta:
            meta['file_path'] = str(source.absolute())
        if 'file_name' not in meta:
            meta['file_name'] = str(source.name)
        if 'file_size' not in meta:
            meta['file_size'] = source.stat().st_size
        if 'created' not in meta:
            meta['created'] = datetime.utcfromtimestamp(source.stat().st_birthtime).isoformat()
        if 'modified' not in meta:
            meta['modified'] = datetime.utcfromtimestamp(source.stat().st_mtime).isoformat()
        return meta

    def save_encrypted(self, source_data: bytes, destination: Path, meta: Dict[str, Any] = None):
        """
        Save small (!) amounts of data encrypted at the destination.

        :param source_data: The data to encrypt and save.
        :param destination: The path to the destination file.
            Use the suffix `.fonfenc` to the target files for best compatibility.
        :param meta: A dictionary with metadata for this file.
        """
        if not isinstance(source_data, bytes):
            raise ValueError('`source_data` has to be a bytes object.')
        if not isinstance(destination, Path):
            raise ValueError('`destination` has to be a `Path` from pathlib.')
        self._verify_metadata(meta)
        with destination.open('wb') as destination_file_handle:
            self.destination_file_digest = hashlib.sha3_512()
            self.destination_file_handle = destination_file_handle
            self._write_file_header()
            self._write_meta_data(meta)
            self._write_bytes_data(source_data)
            self._write_end_with_hash()
        self._clean_up()

    def copy_encrypted(self, source: Path, destination: Path, meta: Dict[str, Any] = None,
                       add_source_metadata=False):
        """
        Copy a file, and store it encrypted at the destination.

        :param source: The path to the source file.
        :param destination: The path to the destination file.
            Use the suffix `.ffe` for files encrypted with this library.
        :param meta: A dictionary with metadata for this file.
        :param add_source_metadata: Include the metadata for the given source file.
            This includes the fields `file_path`, `file_name`, `file_size`, `created`, `modified`.
            Only missing fields are added to the metadata.
        :raises DataTooLargeError: If the source file exceeds the maximum file size limit of 10 TB.
        """
        if not isinstance(source, Path):
            raise ValueError('`source` has to be a `Path` from pathlib.')
        if not isinstance(destination, Path):
            raise ValueError('`destination` has to be a `Path` from pathlib.')
        if not isinstance(add_source_metadata, bool):
            raise ValueError('`add_source_metadata` has to be a boolean value.')
        self._verify_metadata(meta)
        source_file_size = source.stat().st_size
        if source_file_size > FILE_SIZE_LIMIT:
            raise DataTooLargeError('File sizes larger than 1TB are not supported.')
        with source.open('rb') as source_file_handle, destination.open('wb') as destination_file_handle:
            self.destination_file_digest = hashlib.sha3_512()
            self.destination_file_handle = destination_file_handle
            self._write_file_header()
            if add_source_metadata:
                meta = self._add_source_metadata(source, meta)
            self._write_meta_data(meta)
            self._write_file_data(source_file_size, source_file_handle)
            self._write_end_with_hash()
        self._clean_up()

    def stream_encrypted(self, source_io: io.BufferedIOBase, destination_io: io.BufferedIOBase,
                         meta: Dict[str, Any] = None):
        """
        Read data from a stream and write it encrypted into another stream.

        For short streams, smaller than `WORKING_BLOCK_SIZE` this will write the destination stream
        on the fly. Larger streams will write be written in a chunked data format.

        :param source_io: The **open** source stream, compatible with io.BufferedIOBase.
        :param destination_io: The **open** destination stream, compatible with io.BufferedIOBase.
        :param meta: A dictionary with metadata for this file.
        """
        if not isinstance(source_io, io.BufferedIOBase):
            raise ValueError('`source_io` has to be a subclass of `io.BufferedIOBase`.')
        if not source_io.readable():
            raise ValueError('The source stream has to be readable.')
        if not isinstance(destination_io, io.BufferedIOBase):
            raise ValueError('`destination_io` has to be a subclass of `io.BufferedIOBase`.')
        if not destination_io.writable():
            raise ValueError('The destination stream has to be writeable.')
        if not destination_io.seekable():
            raise ValueError('The destination stream has to be seekable.')
        self._verify_metadata(meta)
        self.destination_file_digest = hashlib.sha3_512()
        self.destination_file_handle = destination_io
        self._write_file_header()
        self._write_meta_data(meta)
        self._stream_data(source_io)
        self._write_end_with_hash()
        self._clean_up()
