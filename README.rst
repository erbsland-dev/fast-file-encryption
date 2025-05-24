Fast File Encryption
====================

**Fast File Encryption** is a lightweight, robust, and developer-friendly solution for encrypting large files—ranging from a few megabytes to several terabytes—securely and efficiently.

Ideal for environments that require:

- Minimal runtime dependencies
- Strong asymmetric encryption using RSA
- High performance for both small and large files

Features
--------

- Requires only Python ≥ 3.11 and the ``cryptography`` package
- Securely encrypts and decrypts files using RSA public/private key pairs
- Only the **public key** is needed on the server—no private key exposure
- Supports streaming and large file encryption (up to 10 TB and beyond)

Getting Started 🚀
------------------

New to the project? Start with our step-by-step **Getting Started Guide**. It walks you through installation, key generation, and your first file encryption.

▶️ `Getting Started <https://erbsland-dev.github.io/fast-file-encryption/chapters/get-started.html>`_

Documentation 📚
----------------

Explore the full documentation:

* In-depth reference for encryption and decryption classes
* Key management tools and utilities
* Technical details of the file format

▶️ `Reference Manual <https://erbsland-dev.github.io/fast-file-encryption/chapters/reference/>`_

▶️ `File Format Specification <https://erbsland-dev.github.io/fast-file-encryption/format.html>`_

Requirements
------------

* Python ≥ 3.11
* `cryptography` package (based on OpenSSL)

Project Goals
-------------

**Fast File Encryption** is built with the following principles:

* **Archive Data** — Designed to securely archive files.
* **Secure by Default** — No configurable options that weaken encryption.
* **Large File Support** — Optimized for files up to several terabytes.
* **Metadata Block** — Clean separation of encrypted metadata.
* **No Key = No Access** — Data remains safe even if a server is compromised.
* **Corruption Detection** — Built-in checksums detect silent corruption.

▶️ `More about our design goals <https://erbsland-dev.github.io/fast-file-encryption/goals.html>`_

Bug Reports & Feature Requests
------------------------------

Have feedback or ideas? Found a bug? We'd love to hear from you.

▶️ `Submit an Issue <https://github.com/erbsland-dev/fast-file-encryption/issues>`_

License
-------

Copyright © 2021–2024
Tobias Erbsland – https://erbsland.dev/
EducateIT GmbH – https://educateit.ch/

Licensed under the **Apache License, Version 2.0**.

You may obtain a copy of the license at:

http://www.apache.org/licenses/LICENSE-2.0

Distributed on an “AS IS” basis, without warranties or conditions of any kind. See the LICENSE file for details.
