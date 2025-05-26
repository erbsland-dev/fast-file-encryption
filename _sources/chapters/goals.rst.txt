************
Design Goals
************

Goals
=====

Archive Data
------------

This file encryption format was designed to securely archive data on servers where a potential breach cannot be confidently excluded. It enables automated systems to efficiently encrypt and store incoming files using a locally stored public key.

Ease of Use
-----------

Proper encryption is notoriously difficult and often implemented incorrectly. This format deliberately simplifies usage by offering **no configuration options** for encryption strength, algorithms, or key sizes. It is designed to be **secure by default** and to prevent accidental weakening of encryption through misconfiguration.

If vulnerabilities are discovered in the currently used algorithms, the format can be updated to use improved alternatives while maintaining **backward compatibility for decryption**.

Minimal Dependencies
--------------------

To reduce external risk and simplify installation, this library depends only on the widely-used and well-maintained ``cryptography`` package, which is based on OpenSSL.

Large Files
-----------

The format is optimized for efficiently encrypting large files when their size is known. The block structure is designed to allow hashing and encryption to be performed in a **single pass**, avoiding the need to read the same data multiple times.

It also supports **streaming encryption**, enabling data to be encrypted in memory as it is received—e.g. over a network—and streamed directly to persistent storage.

Separate Metadata Block
-----------------------

A dedicated metadata block allows storing detailed information about the original file, as well as any contextual data. Because metadata is stored separately, it can be quickly extracted without processing the full file.

Prevention of Data Loss/Theft on Breach
---------------------------------------

If the server that performs encryption is compromised, the already-encrypted files remain safe—even if the public key is exposed. The private key needed to decrypt the data is stored **outside the server environment**, typically in a secure hardware module (HSM), and is not accessible to an attacker.

Each file includes a hash of the public key used for encryption. This makes it possible to rotate key pairs over time or per file. For example, a new key pair could be generated monthly, with older private keys archived securely offline. This approach minimizes exposure in the event of a data breach, where an attacker may copy encrypted files in hopes of accessing them later.

Protection from Data Corruption
-------------------------------

SHA3-512 checksums are generated for the metadata, the file content, and the entire file. These checksums enable reliable detection of data corruption.

* The checksums for metadata and file content are encrypted.
* The overall file checksum is stored **unencrypted**, allowing quick file integrity checks without decryption.

Non-Goals
=========

Multiple Keys / Trust Networks
------------------------------

This library and format are not intended as replacements for tools like PGP/GPG, which support encryption with multiple public keys. It is designed for **automated server-side encryption**, where a single recipient (or system) is the target.

Protection from Malicious Manipulation
--------------------------------------

While file integrity is protected by checksums, those checksums are **not digitally signed**. This means there is a small risk that a file could be maliciously altered in a way that remains undetected.

If an attacker gains access to a server, they also gain access to the public key and can encrypt arbitrary files—making it possible to **replace existing encrypted files** without detection.

To prevent insight into encrypted contents, the checksums for metadata and file data are encrypted using the same symmetric key. This also helps detect **bit-flip attacks** on AES-CBC encrypted data, although such tampering will only be detected **after decryption**.


