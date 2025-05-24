#  Copyright © 2022-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


"""
This module contains useful tools to work with this library.
"""

from pathlib import Path
from typing import Optional, TypeAlias

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from .internals import RSA_KEY_SIZE


KeyInput: TypeAlias = Path | str | bytes


def _input_to_bytes(key_input: KeyInput) -> bytes:
    """Return the input converted to ``bytes``.

    :param key_input: The input as :class:`pathlib.Path`, ``str`` or ``bytes``.
    :raises ValueError: If the input type is not supported.
    """
    match key_input:
        case Path():
            return key_input.read_bytes()
        case str():
            return key_input.encode("utf-8")
        case bytes() as data:
            return data
        case _:
            raise ValueError("Key must be a `Path`, string or bytes object.")


def read_public_key(public_key: KeyInput) -> RSAPublicKey:
    """
    Read the public key from a file, bytes or string.

    :param public_key: The public key as :class:`pathlib.Path`, ``str`` or ``bytes`` object.
    :return: The public key as object to be used with the file encryption.
    """
    data = _input_to_bytes(public_key)
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, RSAPublicKey):
        raise ValueError("The data does not contain a public RSA key.")
    return key


def read_private_key(private_key: KeyInput, password: Optional[bytes] = None) -> RSAPrivateKey:
    """
    Read the private key from a file, bytes or string.

    :param private_key: The private key as :class:`pathlib.Path`, ``str`` or ``bytes`` object.
    :param password: An optional password to decrypt the key.
    :return: The private key usable for the file decryption.
    """
    data = _input_to_bytes(private_key)
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError("The data does not contain a private RSA key.")
    return key


def save_key_pair(*, public_key: Path, private_key: Path):
    """
    This method generates a new RSA 4096 key pair and stores the private and public key in two separate
    PEM encoded files.

    Warning! The private key is stored unencrypted and should be stored somewhere secure.

    :param public_key: The path to the public key file.
    :param private_key: The path to the private key file.
    """
    if not public_key:
        raise ValueError("Missing public key path")
    if not private_key:
        raise ValueError("Missing private key path")
    if not isinstance(public_key, Path):
        raise ValueError("`public_key` has to be a `Path` object.")
    if not isinstance(private_key, Path):
        raise ValueError("`private_key` has to be a `Path` object.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_key_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    private_key.write_bytes(private_key_data)
    public_key_data = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    public_key.write_bytes(public_key_data)
