************
Design Notes
************

Use Case: Crash Reports
=======================

The original motivation for this encryption format was to securely store crash reports that might contain sensitive customer data. These reports were collected by an internet-connected system, which made **data exposure prevention a design requirement**.

Due to performance and availability constraints, encryption needed to occur *during* file reception, as crash reports could be large and streamed over time.

Once transferred to a secure server inside the company network, the reports were decrypted using a private RSA key stored in a hardware security module (HSM). From there, they were parsed and archived in a database for further analysis.

Use Case: User Data Encryption
==============================

Another key use case is the secure storage of user-related data.

For each user, an RSA key pair is generated. The **private key is kept in the HSM**, while the **public key is stored in the server’s database**. Any incoming user data is encrypted immediately using the public key before it is written to disk.

This architecture ensures that, in the event of a data breach, only encrypted data can be accessed. The private keys—being stored securely in the HSM—are never exposed, preventing offline decryption.

Accessing the data would require executing custom code on the server with access to the HSM. While this is not impossible, it is significantly harder to achieve without detection.

Furthermore, attempts to scan or decrypt large volumes of data on the processing servers would trigger alerts. Although slowing such operations might help an attacker stay unnoticed, it would also degrade performance and is therefore impractical for large-scale exfiltration.

