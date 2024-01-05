Fast File Encryption
======================

The *Fast File Encryption* is an open, very simple and well-designed file encryption solution for medium and large files (up to terabytes). It uses asymmetric RSA keys to encrypt and decrypt the files, in order to store the public key for encryption on the server, with no worries.

Quick Usage Overview
--------------------

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

Documentation
-------------

You find all details about the library, it's design and file format in the `documentation`_.


License
-------

Copyright © 2021-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/

According to the copyright terms specified in the file "COPYRIGHT.md".

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.


.. _`documentation`: https://erbsland-dev.github.io/fast-file-encryption/


