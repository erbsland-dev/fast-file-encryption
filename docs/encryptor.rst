Encrypting Data
===============

Encrypting data uses a *public key*. You can either encrypt a file and write it encrypted to a different location, directly encrypt byte data or use data streams for the encryption.

The following example shows how you encrypt a file:

.. code-block:: pycon

    >>> import fast_file_encryption as ffe
    >>> from pathlib import Path
    >>> original_file = Path('original_file.txt')
    >>> original_file.write_text('Hello world!')
    >>> encryptor = ffe.Encryptor(ffe.read_public_key(Path('public.pem')))
    >>> encrypted_file = Path('encrypted_file.ffe')
    >>> encryptor.copy_encrypted(original_file, encrypted_file, meta={'my-meta': 1}, add_source_metadata=True)

If you encrypt multiple files, make sure to reuse the `Encryptor` object. When initialized, it will calculate the hash of the used public key.

.. currentmodule:: fast_file_encryption

.. class:: Encryptor(public_key)

    The encryptor provides all required methods to encrypt data, files and streams.

    :param public_key: The public key to use for the encryption.
    :type public_key: `RSAPublicKey`

    .. method:: save_encrypted(source_data, destination, meta=None)

        Encrypt a small amount of data and store it in the file at `destination`.

        :param bytes source_data: The data you like to encrypt.
        :param pathlib.Path destination: The path to the encrypted file. Use the suffix `.ffe` for files encrypted with this library.
        :param meta: An optional dictionary with metadata.
        :type meta: dict[str, any]

    .. method:: copy_encrypted(source, destination, meta=None, add_source_metadata=False)

        Read the file `source` and store it encrypted at `destination`.

        :param pathlib.Path source: The path to the source file.
        :param pathlib.Path destination: The path to the destination file. Use the suffix `.ffe` for files encrypted with this library.
        :param meta: An optional dictionary with metadata.
        :type meta: dict[str, any]
        :param bool add_source_metadata: If you set this parameter to `True`, metadata from the source file will be automatically added. This includes the fields ``file_path``, ``file_name``, ``file_size``, ``created``, ``modified``. Yet, only fields not already specified with `meta` are added.
        :raises DataTooLargeError: If the source file exceeds the maximum file size limit of 10 TB.

    .. method:: stream_encrypted(source_io, destination_io, meta=None)

        Read data from a stream and write it encrypted into another stream.

        For short streams, smaller than ~4k this will write the destination stream on the fly. Larger streams will write be written in a chunked data format.

        :param io.BufferedIOBase source_io: The **open** source stream, only the `read` method is used.
        :param io.BufferedIOBase destination_io: The **open** destination stream, only the `write` method is used.
        :param meta: An optional dictionary with metadata.
        :type meta: dict[str, any]



