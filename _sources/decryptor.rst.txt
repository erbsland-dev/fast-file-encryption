Decrypting Data
===============

Decrypting data requires the matching *private key* of the public key which was used to encrypt the data. You can load and decrypt a file into a `bytes` object, copy the decrypted data into a new file or decrypt data from a data stream into another.

The following example shows how to decrypt a file and read its metadata:

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

    The decryptor provides all required methods to decrypt data, files and streams.

    :param private_key: The private key to use for the decryption.
    :type private_key: `RSAPrivateKey`

    .. method:: read_metadata(source)

        Only decrypt and read the metadata from a file.

        :param pathlib.Path source: The file to read the metadata.
        :return: The dictionary with the metadata.
        :rtype: dict[str, Any]

    .. method:: load_decrypted(self, source, maximum_size=10_000_000)

        Load and decrypt the given source file.

        :param pathlib.Path source: Load and decrypt the given source file.
        :param int maximum_size: The maximum size of the decrypted data. This is no exact limit, because it is tested using the size of the encrypted data. The returned data may be up to 127 bytes larger than the given limit. Defaults to 10_000_000.
        :return: The decrypted data.
        :rtype: bytes
        :raises DataTooLargeError: If the maximum size would be exceeded.
        :raises IntegrityError: On any file integrity problem.

    .. method:: copy_decrypted(self, source, destination):

        Copy an decrypt the `source` file to the given `destination`.

        :param pathlib.Path source: The path to the encrypted source file.
        :param pathlib.Path destination: The path to the decrypted destination file.
        :raises IntegrityError: On any file integrity problem.

    .. method:: stream_decrypted(self, source_io, destination_io)

        Decrypt the data from the source stream and write it to the destination stream.

        Both streams have to be open and need to be readable/writable. The implementation only
        uses the `read` method on the source stream and the `write` method on the destination stream.

        :param io.BufferedIOBase source_io: The open source stream.
        :param io.BufferedIOBase destination_io: The open destination stream.
        :raises IntegrityError: On any file integrity problem.

