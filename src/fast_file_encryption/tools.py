# Copyright 2021 by Tobias Erbsland / EducateIT GmbH
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


"""
This module contains useful tools to work with this library.
"""

from pathlib import Path
from typing import Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

from .internals import RSA_KEY_SIZE


def read_public_key(public_key: Union[Path, str, bytes]) -> RSAPublicKey:
    """
    Read the public key from a file.

    :param public_key: The public key as `Path`, string or bytes object.
    :return: The public key as object to be used with the file encryption.
    """
    if isinstance(public_key, Path):
        data = public_key.read_bytes()
    elif isinstance(public_key, str):
        data = public_key.encode('utf-8')
    elif isinstance(public_key, bytes):
        data = public_key
    else:
        raise ValueError('Public key has to be a `Path`, string or bytes object.')
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, RSAPublicKey):
        raise ValueError('The data does not contain a public RSA key.')
    return key


def read_private_key(private_key: Union[Path, str, bytes], password: Optional[bytes] = None) -> RSAPrivateKey:
    """
    Read the private key from a file or string.

    :param private_key: The private key as `Path`, string or bytes object.
    :param password: An optional password to decrypt the key.
    :return: The private key usable for the file decription.
    """
    if isinstance(private_key, Path):
        data = private_key.read_bytes()
    elif isinstance(private_key, str):
        data = private_key.encode('utf-8')
    elif isinstance(private_key, bytes):
        data = private_key
    else:
        raise ValueError('Private key has to be a `Path`, string or bytes object.')
    key = serialization.load_pem_private_key(data, password=password)
    if not isinstance(key, RSAPrivateKey):
        raise ValueError('The data does not contain a private RSA key.')
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
        raise ValueError('Missing public key path')
    if not private_key:
        raise ValueError('Missing private key path')
    if not isinstance(public_key, Path):
        raise ValueError('`public_key` has to be a `Path` object.')
    if not isinstance(private_key, Path):
        raise ValueError('`private_key` has to be a `Path` object.')
    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    private_key_data = key.private_bytes(encoding=serialization.Encoding.PEM,
                                         format=serialization.PrivateFormat.PKCS8,
                                         encryption_algorithm=serialization.NoEncryption())
    private_key.write_bytes(private_key_data)
    public_key_data = key.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    public_key.write_bytes(public_key_data)
