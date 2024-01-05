#  Copyright © 2021-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


from pathlib import Path

import pytest

from fast_file_encryption import read_public_key, read_private_key

test_public_key = None  # Cache the public key to speedup tests
test_private_key = None  # Cache the private key to speedup tests


@pytest.fixture(scope="module")
def public_key():
    return read_public_key(Path(__file__).parent / 'keys' / 'test_public_key.pem')


@pytest.fixture(scope="module")
def private_key():
    return read_private_key(Path(__file__).parent / 'keys' / 'test_private_key.pem')


@pytest.fixture(scope="module")
def data_dir():
    return Path(__file__).parent / 'data'


@pytest.fixture(scope="module")
def keys_dir():
    return Path(__file__).parent / 'keys'
