Tools
=====

There are a number of tool functions to simplify the key handling. I recommend using these functions to read and generate the keys in order to maintain compatibility with future versions of the library.

.. currentmodule:: fast_file_encryption

.. function:: read_public_key(public_key)

    Read a PEM encoded public key from a file.

    If you specify a `Path` from `pathlib`, the key is loaded from this file. If you pass a `str` and `bytes`, the parameter must contain the PEM encoded key.

    :param public_key: The public key as `Path`, string or bytes object.
    :type public_key: Union[pathlib.Path, str, bytes]
    :return: The public key as object to be used with the data encryption.
    :rtype: `RSAPublicKey`

.. function:: read_private_key(private_key, password=None)

    Read the PEM encoded private key from a file or string.

    If you specify a `Path` from `pathlib`, the key is loaded from this file. If you pass a `str` and `bytes`, the parameter must contain the PEM encoded key.

    :param private_key: The private key as `Path`, string or bytes object.
    :type private_key: Union[pathlib.Path, str, bytes]
    :param password: An optional password to decrypt the key, defaults to None.
    :return: The private key as object to be used with the data decryption.
    :rtype: `RSAPrivateKey`

.. function:: save_key_pair(*, public_key, private_key):

    This method generates a new RSA 4096 key pair and stores the private and public key in two separate
    PEM encoded files.

    :param pathlib.Path public_key: The path to the public key file.
    :param pathlib.Path private_key: The path to the private key file.

    .. warning::

        Because this library is designed to be used in an automated environment, the private key is not protected with a password and should be stored somewhere safe (e.g. HSM).

