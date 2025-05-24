
**********
File Sizes
**********

This format is designed for files ranging from several megabytes to **multiple terabytes**.

.. note::

    Encrypting large numbers of small files introduces overhead. In such cases, it is recommended to **bundle small files into a container format** (e.g. ZIP) before encryption.

Files up to **10 TB** can be encrypted efficiently. AES-256/CBC is fast and handles such volumes without issue.

An **arbitrary upper limit** of 10 TB is enforced to maintain reasonable bounds for integrity checking. Technically, the theoretical limit is **18 exabytes**, as sizes are stored in 64-bit fields.

