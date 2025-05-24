Encrypting Data
===============

Encrypting data with *Fast File Encryption* is straightforward and secure.
All encryption operations are performed using a **public RSA key**, allowing you to share the encrypted files without exposing any private secrets.

You can encrypt:

* Entire files and store them at a new destination
* Raw in-memory data (`bytes`)
* Streams (e.g., file-like objects or sockets)

Below is a quick example demonstrating how to encrypt a file:

.. code-block:: pycon

    >>> import fast_file_encryption as ffe
    >>> from pathlib import Path
    >>> original_file = Path('original_file.txt')
    >>> original_file.write_text('Hello world!')
    >>> encryptor = ffe.Encryptor(ffe.read_public_key(Path('public.pem')))
    >>> encrypted_file = Path('encrypted_file.ffe')
    >>> encryptor.copy_encrypted(
    ...     original_file,
    ...     encrypted_file,
    ...     meta={'my-meta': 1},
    ...     add_source_metadata=True
    ... )

.. tip::
    When encrypting multiple files, reuse the same `Encryptor` instance.
    Internally, it caches the public key hash to avoid recalculating it for each file.

.. currentmodule:: fast_file_encryption

.. class:: Encryptor(public_key)

    The `Encryptor` class provides all core methods to securely encrypt byte sequences, files, and data streams.

    :param public_key: The RSA public key used for encryption.
    :type public_key: `RSAPublicKey`

    .. method:: save_encrypted(source_data, destination, meta=None)

        Encrypt a small byte buffer and store the result in a file.

        :param bytes source_data: The in-memory data to encrypt.
        :param pathlib.Path destination: Target path for the encrypted file. It is recommended to use the `.ffe` suffix.
        :param meta: Optional metadata dictionary stored alongside the encrypted data.
        :type meta: dict[str, any]

    .. method:: copy_encrypted(source, destination, meta=None, add_source_metadata=False)

        Encrypt a file and write the result to a new location.

        :param pathlib.Path source: Path to the unencrypted input file.
        :param pathlib.Path destination: Path to the output file (typically ending in `.ffe`).
        :param meta: Optional dictionary with custom metadata.
        :type meta: dict[str, any]
        :param bool add_source_metadata: If set to `True`, the following metadata will be added automatically unless overridden:

            - ``file_path``
            - ``file_name``
            - ``file_size``
            - ``created``
            - ``modified``

        :raises DataTooLargeError: Raised if the file size exceeds 10 TB.

    .. method:: stream_encrypted(source_io, destination_io, meta=None)

        Encrypt data read from a stream and write it to another stream.

        For small streams (less than ~4 KiB), the encryption is performed inline. Larger streams are encrypted using a chunked format.

        :param io.BufferedIOBase source_io: Open input stream (must implement `read()`).
        :param io.BufferedIOBase destination_io: Open output stream (must implement `write()`).
        :param meta: Optional metadata dictionary.
        :type meta: dict[str, any]


.. button-ref:: decryptor
    :ref-type: doc
    :color: primary
    :align: center
    :expand:
    :class: sd-mt-5 sd-mb-5 sd-fs-5 sd-font-weight-bold sd-p-3

    Decrypting Data →

