#  Copyright © 2021-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey

import fast_file_encryption as ffe
from shared import *


class TestTools:

    def test_read_public_key(self, keys_dir):
        path = keys_dir / 'test_public_key.pem'
        ffe.read_public_key(path)
        b = path.read_bytes()
        ffe.read_public_key(b)
        s = b.decode('utf-8')
        ffe.read_public_key(s)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.read_public_key(10)
        with pytest.raises(ValueError):
            ffe.read_public_key('''-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+R08BghrJHOeb5tjy6yntbcM2x6z
GXz2vjptQeJne4L+5X1qZuI7NB7D2ZCXtSnwhyVEjoBLhLRzgiJIKVvQBA==
-----END PUBLIC KEY-----''')

    def test_read_private_key(self, keys_dir):
        path = keys_dir / 'test_private_key.pem'
        ffe.read_private_key(path)
        b = path.read_bytes()
        ffe.read_private_key(b)
        s = b.decode('utf-8')
        ffe.read_private_key(s)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.read_private_key(10)
        with pytest.raises(ValueError):
            ffe.read_private_key('''-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKBrKq/wWvsDKhD9nWlrfBZnMutErcGzJZj+HysFchIZoAoGCCqGSM49
AwEHoUQDQgAE+R08BghrJHOeb5tjy6yntbcM2x6zGXz2vjptQeJne4L+5X1qZuI7
NB7D2ZCXtSnwhyVEjoBLhLRzgiJIKVvQBA==
-----END EC PRIVATE KEY-----''')

    def test_save_keypair(self, tmp_path):
        public_key = tmp_path / 'public_key.pem'
        private_key = tmp_path / 'private_key.pem'
        ffe.save_key_pair(public_key=public_key, private_key=private_key)
        assert public_key.is_file()
        assert private_key.is_file()
        public_key_data = public_key.read_bytes()
        assert len(public_key_data) > 200
        key = serialization.load_pem_public_key(public_key_data)
        assert isinstance(key, RSAPublicKey)
        assert key.key_size == 4096
        public_numbers = key.public_numbers()
        assert public_numbers.e == 65537
        private_key_data = private_key.read_bytes()
        assert len(private_key_data) > 200
        key = serialization.load_pem_private_key(private_key_data, password=None)
        assert isinstance(key, RSAPrivateKey)
        assert key.key_size == 4096
        # Test if this is a matching key pair
        private_numbers = key.private_numbers()
        assert private_numbers.public_numbers.e == 65537
        assert private_numbers.public_numbers.n == public_numbers.n
        # Test if random keys are created
        ffe.save_key_pair(public_key=public_key, private_key=private_key)
        assert public_key.read_bytes() != public_key_data
        assert private_key.read_bytes() != private_key_data
        # Test invalid parameters
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.save_key_pair(public_key=None, private_key=private_key)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.save_key_pair(public_key='path', private_key=private_key)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.save_key_pair(public_key=public_key, private_key=None)
        with pytest.raises(ValueError):
            # noinspection PyTypeChecker
            ffe.save_key_pair(public_key=public_key, private_key='path')
