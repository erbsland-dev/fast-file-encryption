Getting Started
===============

**Welcome! Let's begin encrypting files with confidence.**

This quickstart guide will walk you through the essentials:
installation, key generation, and file encryption/decryption—
all in just a few steps.

Before you begin, make sure you have:

* A working Python 3.11+ environment set up
* A terminal or your preferred development tools

While this guide uses command-line examples, you're welcome to follow along in any environment you're comfortable with.

Installation
------------

We recommend creating a virtual environment to keep dependencies isolated:

.. code-block:: console

    $ python -m venv venv
    $ source venv/bin/activate

Next, install *Fast File Encryption* from PyPI:

.. code-block:: console

    $ pip install fast_file_encryption

Generate a Key Pair
-------------------

To encrypt and decrypt files, you'll first need a key pair.

By default, the generated private key is **not password-protected**, as the tool is designed for automated environments. If your use case requires additional security, you may generate or wrap your keys using other tools (e.g. ``openssl``).

Start a Python shell:

.. code-block:: console

    $ python3
    >>> █

Now generate and store your key pair:

.. code-block:: pycon

    >>> import fast_file_encryption as ffe
    >>> from pathlib import Path
    >>> ffe.save_key_pair(public_key=Path('public.pem'), private_key=Path('private.pem'))

Encrypt a File
--------------

To encrypt a file:

.. code-block:: pycon

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

Decrypt a File
--------------

To decrypt the file and inspect the metadata:

.. code-block:: pycon

    >>> decryptor = ffe.Decryptor(ffe.read_private_key(Path('private.pem')))
    >>> decryptor.load_decrypted(encrypted_file)
    b'Hello world!'
    >>> decryptor.read_metadata(encrypted_file)
    {'my-meta': 1, 'file_path': '.../original_file.txt', ...}

All Set!
--------

🎉 You've successfully encrypted and decrypted your first file.

Next steps:
Explore the :doc:`reference documentation<reference/index>` for detailed APIs,
or review the :doc:`file format<format>` if you're integrating with other systems.

.. button-ref:: reference/index
    :ref-type: doc
    :color: light
    :shadow:
    :align: center
    :class: sd-font-weight-bold

    Reference Manual →

.. button-ref:: format
    :ref-type: doc
    :color: light
    :shadow:
    :align: center
    :class: sd-font-weight-bold

    File Format →
