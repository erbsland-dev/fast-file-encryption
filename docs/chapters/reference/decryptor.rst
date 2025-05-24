Decrypting Data
===============

To decrypt data, you must use the *private key* that corresponds to the public key used during encryption.

*Fast File Encryption* supports several decryption workflows:
you can decrypt a file to memory, write decrypted content directly to another file, or use stream-based decryption for more advanced scenarios.

The example below shows how to decrypt a file and read its metadata:

.. code-block:: pycon

    >>> import fast_file_encryption as ffe
    >>> from pathlib import Path
    >>> encrypted_file = Path('encrypted_file.ffe')
    >>> decryptor = ffe.Decryptor(ffe.read_private_key(Path('private.pem')))
    >>> decryptor.load_decrypted(encrypted_file)
    b'Hello world!'
    >>> decryptor.read_metadata(encrypted_file)
    {'my-meta': 1, 'file_path': '.../original_file.txt', ...}

.. currentmodule:: fast_file_encryption

.. class:: Decryptor(private_key)

    The `Decryptor` class provides all the core functionality required to decrypt files, data buffers, and streams.

    :param private_key: The private RSA key used for decryption.
    :type private_key: `RSAPrivateKey`

    .. method:: read_metadata(source)

        Extract and return the metadata stored in an encrypted file without decrypting its contents.

        :param pathlib.Path source: The encrypted file to inspect.
        :return: A dictionary containing the file’s metadata.
        :rtype: dict[str, Any]

    .. method:: load_decrypted(self, source, maximum_size=10_000_000)

        Load and decrypt the entire content of a file into memory.

        :param pathlib.Path source: The encrypted input file.
        :param int maximum_size: Soft limit on the expected size of the decrypted data (in bytes). The actual decrypted size may exceed this limit by up to 127 bytes. Default is 10 MB.
        :return: The decrypted file content.
        :rtype: bytes
        :raises DataTooLargeError: If the decrypted data would exceed the allowed size.
        :raises IntegrityError: If integrity validation fails.

    .. method:: copy_decrypted(self, source, destination)

        Decrypt a file and write its plain content to a new file.

        :param pathlib.Path source: Path to the encrypted input file.
        :param pathlib.Path destination: Path to the output file where the decrypted data will be saved.
        :raises IntegrityError: If integrity validation fails.

    .. method:: stream_decrypted(self, source_io, destination_io)

        Decrypt data from a readable stream and write the decrypted content to a writable stream.

        This method supports any file-like objects (e.g. `io.BytesIO`, sockets, or file handles). It uses only the `read()` method on the source and `write()` on the destination.

        :param io.BufferedIOBase source_io: An open stream supporting `read()`.
        :param io.BufferedIOBase destination_io: An open stream supporting `write()`.
        :raises IntegrityError: If integrity validation fails.

.. button-ref:: errors
    :ref-type: doc
    :color: primary
    :align: center
    :expand:
    :class: sd-mt-5 sd-mb-5 sd-fs-5 sd-font-weight-bold sd-p-3

    About Errors →
