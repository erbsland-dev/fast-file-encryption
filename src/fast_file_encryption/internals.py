#  Copyright © 2022-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


"""
This module contains the shared values for the encryption, decryption and key generation.
Do not change these values!
"""

RSA_KEY_SIZE = 4096  # The used key size. Do not change this value!

AES_KEY_LENGTH_BITS = 256  # The used key length. Do not change this value!
AES_KEY_LENGTH_BYTES = AES_KEY_LENGTH_BITS // 8  # The key length on bytes
AES_BLOCK_SIZE_BITS = 128  # The block size for the encryption. Do not change this value!
AES_BLOCK_SIZE_BYTES = AES_BLOCK_SIZE_BITS // 8  # The block size in bytes.
AES_IV_LENGTH_BYTES = 16  # The length of the IV for the cipher in bytes.

WORKING_BLOCK_SIZE = 4096  # The block size to read/write data from a file. Has to align with AES block size!
MAXIMUM_CHUNK_SIZE = 0xFFFF  # The maximum size of a block in the chunked format.
SIZE_VALUE_LENGTH = 8  # Use 8 bytes to store the size values.
CHUNK_SIZE_LENGTH = 2  # Use 2 bytes to store the chunk size values.
SIZE_ENDIANNESS = "big"  # The endianness of the size values.

MAXIMUM_BLOCK_SIZE_VALUE = 0xFFFF_0000_0000_0000  # The maximum valid block size
CHUNKED_BLOCK_SIZE_VALUE = 0xFFFF_8000_0000_0000  # The special value indicating a block uses chunked data.

ENCRYPTION_DATA_GAIN = SIZE_VALUE_LENGTH + AES_IV_LENGTH_BYTES + AES_BLOCK_SIZE_BYTES

FILE_MAGIC = b"\xfeFFE\x0d\x0a\x1a\x0a"
FILE_CONFIG_TEXT = b"k:RSA-4096,e:AES-256,b:CBC,h:SHA3-512,v:1"
FILE_SIZE_LIMIT = 10_000_000_000_000

KNOWN_BLOCK_TYPES = [b"CONF", b"EPUB", b"ESYM", b"META", b"MDHA", b"DATA", b"DTHA", b"ENDH"]  # All known block types.
