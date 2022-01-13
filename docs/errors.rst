Exceptions
==========

.. currentmodule:: fast_file_encryption

.. class:: IntegrityError

    This exception is thrown if there is any integrity problem with an encrypted file.

    - Wrong file magic.
    - File to short.
    - Checksum mismatch.
    - Corrupt data.
    - ...

.. class:: DataTooLargeError

    This exception is thrown, if you set a maximum size and it would be exceeded.

