Tools
=====

This module provides utility functions to simplify key management.

We strongly recommend using these functions for reading and generating keys to ensure forward compatibility with future versions of the library. These tools abstract away common pitfalls and offer a clean interface for both file-based and in-memory key handling.

.. currentmodule:: fast_file_encryption

.. function:: read_public_key(public_key)

    Load a PEM-encoded public RSA key.

    You can provide the key in multiple formats:

    * A `Path` object pointing to a PEM file
    * A `str` or `bytes` object containing the PEM-encoded key

    :param public_key: The input source for the public key.
    :type public_key: Union[pathlib.Path, str, bytes]
    :return: A parsed public key object for use in encryption operations.
    :rtype: RSAPublicKey

.. function:: read_private_key(private_key, password=None)

    Load a PEM-encoded private RSA key.

    Accepts file paths, strings, or bytes. If the key is password-protected, you can provide the password as a string or byte sequence.

    :param private_key: The input source for the private key.
    :type private_key: Union[pathlib.Path, str, bytes]
    :param password: Optional password to decrypt the key if it is protected.
    :type password: Optional[Union[str, bytes]]
    :return: A parsed private key object for use in decryption operations.
    :rtype: RSAPrivateKey

.. function:: save_key_pair(*, public_key, private_key)

    Generate and save a new RSA 4096-bit key pair.

    This function creates a new private and public key pair, and writes each to a separate file using the PEM format. This is the recommended way to create key material for this library.

    :param public_key: Path where the PEM-encoded public key will be written.
    :type public_key: pathlib.Path
    :param private_key: Path where the PEM-encoded private key will be written.
    :type private_key: pathlib.Path

    .. warning::

        For automation and scripting purposes, the generated private key is **not encrypted with a password**.
        Make sure you store it securely—ideally in a protected location such as a hardware security module (HSM) or secure key vault.

