import pytest
import fast_file_encryption as ffe


def test_optional_end_block_verification(private_key, data_dir, tmp_path):
    original_file = data_dir / "8k-random.ffe"
    original_data = (data_dir / "8k-random.data").read_bytes()

    # Verification enabled on intact file
    decryptor = ffe.Decryptor(private_key=private_key, verify_file_digest=True)
    assert decryptor.load_decrypted(original_file) == original_data

    # Create a file with a modified ENDH digest
    tampered = tmp_path / "tampered.ffe"
    file_bytes = bytearray(original_file.read_bytes())
    file_bytes[-1] ^= 0xFF
    tampered.write_bytes(file_bytes)

    decryptor_no_verify = ffe.Decryptor(private_key=private_key)
    assert decryptor_no_verify.load_decrypted(tampered) == original_data

    decryptor_verify = ffe.Decryptor(private_key=private_key, verify_file_digest=True)
    with pytest.raises(ffe.IntegrityError):
        decryptor_verify.load_decrypted(tampered)

    # Create a file with a modified byte in the middle
    file_bytes = bytearray(original_file.read_bytes())
    file_bytes[4293] ^= 0xFF
    tampered.write_bytes(file_bytes)  # overwrite tampered file.

    decryptor_verify = ffe.Decryptor(private_key=private_key, verify_file_digest=True)
    with pytest.raises(ffe.IntegrityError):
        decryptor_verify.load_decrypted(tampered)
