#  Copyright © 2022-2024 Tobias Erbsland https://erbsland.dev/ and EducateIT GmbH https://educateit.ch/
#  According to the copyright terms specified in the file "COPYRIGHT.md".
#  SPDX-License-Identifier: Apache-2.0


class IntegrityError(Exception):
    """
    This exception is thrown if there is any integrity problem with the encrypted file.

    - Wrong file magic.
    - File to short.
    - Checksum mismatch.
    - Corrupt data.
    """

    pass


class DataTooLargeError(Exception):
    """
    This exception is thrown if you set a maximum size, and it would be exceeded.
    """

    pass
