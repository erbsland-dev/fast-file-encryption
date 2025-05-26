
**************************
Used Algorithms and Hashes
**************************

The encryption technologies used are strong, open, and industry-proven:

* RSA 4096-bit keys for asymmetric encryption
* OAEP (Optimal Asymmetric Encryption Padding) using MGF1 with SHA-256
* AES-256 in CBC mode for data encryption, using random keys and IVs
* SHA3-512 digests for verifying metadata, file content, and overall file integrity
* All digests, metadata, and file data are encrypted with individual random IVs
* The file-level checksum is **not encrypted** to allow fast integrity checks
