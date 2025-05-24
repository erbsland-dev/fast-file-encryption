Exceptions
==========

.. currentmodule:: fast_file_encryption

This section documents the custom exceptions raised by the *Fast File Encryption* library.

These exceptions are designed to help you detect and handle issues related to data integrity and size limits during encryption and decryption operations.

.. class:: IntegrityError

    Raised when an encrypted file fails integrity validation.

    This exception may occur in the following cases:

    - Invalid or missing file magic (not recognized as a valid `.ffe` file)
    - File is unexpectedly short or truncated
    - Checksum mismatch during validation
    - Corrupt or malformed data segments
    - Unsupported or unknown version markers

    Use this exception to alert users or stop processing when a file cannot be trusted.

.. class:: DataTooLargeError

    Raised when the decrypted or encrypted data exceeds a specified maximum size limit.

    This is commonly triggered if:

    - You set a `maximum_size` limit and the decrypted data would go beyond it
    - The file size exceeds the maximum allowed for encryption (e.g. 10 TB limit)

    This exception helps safeguard systems against memory exhaustion or unintentional processing of oversized files.

.. button-ref:: tools
    :ref-type: doc
    :color: primary
    :align: center
    :expand:
    :class: sd-mt-5 sd-mb-5 sd-fs-5 sd-font-weight-bold sd-p-3

    Tools →
