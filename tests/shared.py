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
