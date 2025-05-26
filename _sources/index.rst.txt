Welcome to the Fast File Encryption Documentation!
==================================================

Welcome! This documentation will guide you through using **Fast File Encryption**, a lightweight, robust, and developer-friendly solution for encrypting large files—ranging from a few megabytes up to several terabytes—safe and easy.

Fast File Encryption is ideal for environments that need:

* Minimal runtime dependencies
* Strong security using asymmetric RSA encryption
* High performance for both small and large files

Whether you're new to the project or returning to explore specific implementation details, you're in the right place.

.. grid:: 2

    .. grid-item-card:: Minimal Dependencies
        :class-card: sd-text-center sd-p-3 sd-mb-3

        Requires only Python ≥ 3.11 and the ``cryptography`` package.

    .. grid-item-card:: Reliable RSA Encryption
        :class-card: sd-text-center sd-p-3 sd-mb-3

        Securely encrypts and decrypts files using public/private RSA key pairs.

    .. grid-item-card:: Server-Side Public Key Support
        :class-card: sd-text-center sd-p-3 sd-mb-3

        Store only the public key on the server—no private key exposure needed.

    .. grid-item-card:: Built for Large Files
        :class-card: sd-text-center sd-p-3 sd-mb-3

        Efficiently handles files of virtually any size—from kilobytes to terabytes.

.. button-ref:: chapters/get-started
    :ref-type: doc
    :color: success
    :align: center
    :expand:
    :class: sd-fs-2 sd-font-weight-bold sd-p-3

    Get Started →

Already familiar? Dive directly into key areas of the library:

.. toctree::
    :maxdepth: 2
    :caption: About the Library

    chapters/get-started
    chapters/reference/index
    chapters/format
    chapters/design
    chapters/goals
    chapters/used-algorithms
    chapters/file-sizes
    chapters/contributing
    chapters/code-of-conduct
    chapters/license

Indices and Tables
------------------

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
