***************
The File Format
***************

The *Fast File Encryption* format is a strict, block-oriented binary format—conceptually similar to formats like PNG.

Each file begins with a magic header, followed by a defined sequence of binary blocks. Every block is identified by a 4-byte type and accompanied by a size field. Blocks are either of a **static size** or follow a **chunked format** designed for stream-like data.

Although the underlying structure could technically allow for flexible block order and composition, this format deliberately enforces a **strict sequence and fixed structure**. This decision improves performance during verification and parsing and significantly reduces the attack surface for tampered or malformed files.

Overall Structure
=================

Each encrypted file consists of:

* A fixed 8-byte magic header: ``0xfe``, ``FFE``, ``0x0d``, ``0x0a``, ``0x1a``, ``0x0a``
* A defined sequence of one or more **blocks**, structured as described below

Static Blocks
-------------

Static blocks are the default and most efficient representation for metadata and small binary payloads, especially on random-access storage media.

Block layout:
~~~~~~~~~~~~~

.. list-table::
    :width: 100%

    * - 4 bytes
      - Block type (ASCII-encoded, e.g. ``DATA``, ``CONF``)
    * - 8 bytes
      - Block size (unsigned 64-bit big-endian)
    * - n bytes
      - Block content, as defined by the declared size

.. note::

    * A block size of ``0`` indicates the block is empty—no data bytes follow.
    * The size must be strictly **less than** ``0xffff_0000_0000_0000``. Larger values are reserved for future format extensions and are **not valid** under this specification.

Chunked Blocks
--------------

For large or streamed data, the format supports a specialized *chunked block* structure.

This format uses a size field set to ``0xffff800000000000`` to signal that the content will be defined by a sequence of smaller data chunks rather than a fixed-size payload.

Chunked blocks are currently **only supported for the `DATA` block**.

Block layout:
~~~~~~~~~~~~~

.. list-table::
    :width: 100%

    * - 4 bytes
      - Block type (must be ``DATA``)
    * - 8 bytes
      - Special marker: ``0xffff800000000000`` to indicate chunked format
    * - n chunks
      - Stream of data chunks (see below)

Data chunk sequence:
~~~~~~~~~~~~~~~~~~~~

- Each chunk begins with a 2-byte big-endian unsigned integer specifying its size.
- Followed by the number of bytes declared by the chunk size.
- A chunk size of ``0`` indicates the end of the stream.

Chunking guidelines:
~~~~~~~~~~~~~~~~~~~~

* All chunks **should** use the maximum size of ``0xffff`` bytes, except the final chunk.
* Decryptors **may** enforce this convention and reject files that use irregular or inconsistent chunk sizes.


Block Types and Correct Order
=============================

Each encrypted file must follow a strict block sequence. The format does not permit reordering, omitting, or introducing unknown block types. The following describes each block, its purpose, expected content, and size limitations.

``CONF`` – Encryption Configuration (maximum size: 128 bytes)
-------------------------------------------------------------

Contains a concise, human-readable summary of the encryption configuration:

.. code-block:: text

    k:RSA-4096,e:AES-256,b:CBC,h:SHA3-512,v:1

The configuration string uses a comma-separated format of key–value pairs (``<key>:<value>``), encoded as ASCII. Allowed characters match this regular expression: ``[-_,:A-Za-z0-9]+``.

Field definitions:

* ``k`` – Key algorithm (e.g., RSA-4096)
* ``e`` – Encryption algorithm (e.g., AES-256)
* ``b`` – Block cipher mode (e.g., CBC)
* ``h`` – Hash algorithm (e.g., SHA3-512)
* ``v`` – File format version

This field ensures future readability of encrypted files. If the value does not match the exact expected string, decoding should fail immediately.

``EPUB`` – Public Key Hash (maximum size: 1 KB)
-----------------------------------------------

Stores a SHA3-512 hash of the RSA public key used to encrypt the file’s symmetric key. The key is first serialized using DER encoding in the `SubjectPublicKeyInfo` format.

This hash allows a decryptor to quickly identify whether a given private key matches the file—without attempting decryption via trial and error. The hash is required for decryption.

``ESYM`` – Encrypted Symmetric Key (maximum size: 1 KB)
--------------------------------------------------------

Contains the symmetric AES-256 key encrypted using RSA-OAEP (Optimal Asymmetric Encryption Padding), following PKCS#1 and RFC 3447 standards. The padding uses SHA-256 as both the main hash and the mask generation function (MGF1), and includes no label.

.. code-block:: python

    encryption_key = os.urandom(AES_KEY_LENGTH_BYTES)
    encrypted_encryption_key = public_key.encrypt(
        encryption_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

The symmetric key in this block is used to encrypt all content blocks (e.g., `META`, `DATA`), each with a unique initialization vector (IV). See the section *Encrypted File Format* for more details.

``META`` – Encrypted Metadata (maximum size: 10 KB)
---------------------------------------------------

Contains user-defined metadata, encrypted with the symmetric key. If no metadata is provided, this block and its hash (`MDHA`) are empty.

See the section *Metadata Format* for structure and validation rules.

``MDHA`` – Metadata Hash (maximum size: 1 KB)
---------------------------------------------

Contains an encrypted hash of the decrypted metadata for integrity verification.

``DATA`` – Encrypted File Data (no maximum size)
------------------------------------------------

Contains the encrypted file payload. For empty input files, this block and its associated hash (`DTHA`) are omitted.

See the section *Encrypted Data Block Format* for the binary layout.

``DTHA`` – Data Hash
--------------------

Contains an encrypted SHA3-512 hash of the decrypted file content.

``ENDH`` – End of File with Final Hash
--------------------------------------

Marks the end of the encrypted file and contains a SHA3-512 hash of the complete file content *up to this block*.

The final block has a fixed size of 64 bytes. Its size field is always encoded as:

.. code-block:: text

    0x40, 0, 0, 0, 0, 0, 0, 0

This hash is used to quickly verify the file's overall integrity. To validate it:

#. Calculate the hash of the file content up to `file_size - 76` bytes.
#. Skip 12 bytes (block type + size).
#. Compare your hash to the following 64 bytes.

Block Order
-----------

The blocks **must appear in the following fixed order**:

#. ``CONF`` – Configuration header
#. ``EPUB`` – Public key hash
#. ``ESYM`` – Encrypted symmetric key
#. ``META`` – Encrypted metadata (optional)
#. ``MDHA`` – Metadata hash (optional)
#. ``DATA`` – Encrypted data
#. ``DTHA`` – Data hash
#. ``ENDH`` – Final file hash

Any deviation from this block sequence is considered invalid and must cause decoding to fail.


Encrypted Data Block Format
===========================

Encrypted data is stored in one of two formats depending on the block type: **static** or **streamed**. Both formats use AES-256 in CBC mode with a unique initialization vector (IV).

Static Blocks
-------------

This format is used when the total size of the decrypted data is known ahead of time.

Block layout:
~~~~~~~~~~~~~

.. list-table::
    :width: 100%

    * - 8 bytes
      - **Decrypted Size** – Big-endian, unsigned 64-bit integer representing the length of the original (plaintext) data.
    * - 16 bytes
      - **Initialization Vector (IV)** used for AES-256/CBC encryption.
    * - n bytes
      - **Encrypted Data**, aligned to the cipher block size.

.. note::

    If the encrypted data is empty this block is empty (no size and IV).

Size Handling
~~~~~~~~~~~~~

* If the block is empty, the size of the decrypted data is zero.
* A size value greater than zero represents the number of **decrypted** bytes.
* The decrypted size is always non-zero if this block is not empty.

Streamed Blocks
---------------

When the decrypted size is unknown in advance, the streamed (chunked) data block format is used instead.

Block layout:
~~~~~~~~~~~~~

.. list-table::
    :width: 100%

    * - 16 bytes
      - **Initialization Vector (IV)** for AES-256/CBC encryption.
    * - n bytes
      - **Encrypted Data**, padded using ISO/IEC 9797-1 padding method 2.

Padding
~~~~~~~

This padding method appends a single byte `0x80` followed by zero or more bytes of `0x00` to align the data to the cipher block size.


Metadata Format
===============

Each encrypted file may include a custom metadata block.

* Metadata is encoded as a UTF-8 JSON object.
* The JSON must be compact (no indentation or line breaks).
* It must represent a **top-level object** (no arrays or scalar values at the root).

Example:
~~~~~~~~

.. code-block:: json

    {"attribute1":"data1","attribute2":"data2","attribute3":"data3"}

* The structure of attributes is user-defined and may include nested objects or arrays.
* The total size of the encrypted metadata must not exceed **100 KB**.
* Field names must:
  - Use only lowercase letters and underscores
  - Be shorter than 64 characters

Predefined Metadata Fields
--------------------------

The following field names are predefined and may be included in the metadata block:

* ``file_path`` – Original absolute path of the encrypted file
* ``file_name`` – Original file name
* ``file_size`` – Size of the original (unencrypted) file
* ``created`` – UTC creation timestamp in ISO format (`yyyy-mm-ddThh:mm:ss`)
* ``modified`` – UTC modification timestamp in ISO format (`yyyy-mm-ddThh:mm:ss`)
* ``mime_type`` – MIME type of the original file content
* ``version`` – File version, free format
* ``encryptor`` – Name of the application that performed the encryption


Error Handling on Decoding
==========================

If a decoding error occurs, processing must be halted immediately. **Do not attempt to recover or continue.**

The following conditions must result in an immediate failure:

* The file is smaller than 256 bytes – the file is invalid and must not be processed.
* An unknown block type is encountered – decoding must stop.
* An expected block is missing – decoding must stop.
* A block's actual content exceeds the declared size – decoding must stop.
* The ``CONF`` block does not match the expected encryption specification exactly – decoding must stop.
* A hash does not match the corresponding decoded content – decoding must stop.

