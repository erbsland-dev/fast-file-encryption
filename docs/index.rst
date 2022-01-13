Welcome to Fast File Encryption
===============================

The *Fast File Encryption* is an open, very simple and well-designed file encryption solution for medium and large
files (up to terabytes). It uses asymmetric RSA keys to encrypt and decrypt the files, in order to store the public key
for encryption on the server, with no worries.

Quickstart
----------

Create a new key pair:

.. code-block:: pycon

    >>> import fast_file_encryption as ffe
    >>> from pathlib import Path
    >>> ffe.save_key_pair(public_key=Path('public.pem'), private_key=Path('private.pem'))

Encrypt a file:

.. code-block:: pycon

    >>> original_file = Path('original_file.txt')
    >>> original_file.write_text('Hello world!')
    >>> encryptor = ffe.Encryptor(ffe.read_public_key(Path('public.pem')))
    >>> encrypted_file = Path('encrypted_file.ffe')
    >>> encryptor.copy_encrypted(original_file, encrypted_file, meta={'my-meta': 1}, add_source_metadata=True)

Decrypt a file and read its meta data:

.. code-block:: pycon

    >>> decryptor = ffe.Decryptor(ffe.read_private_key(Path('private.pem')))
    >>> decryptor.load_decrypted(encrypted_file)
    b'Hello world!'
    >>> decryptor.read_metadata(encrypted_file)
    {'my-meta': 1, 'file_path': '.../original_file.txt', ...}

Installation
------------

Install *Fast File Encryption* using ``pip``:

.. code-block:: console

    $ pip install fast_file_encryption

Reference Documentation
-----------------------

.. toctree::
    :maxdepth: 2
    :caption: API Reference

    encryptor
    decryptor
    errors
    tools

.. toctree::
    :maxdepth: 2
    :caption: About the Library

    design
    format

Indices and tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
