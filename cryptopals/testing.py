# -*- coding: utf-8 -*-
from cryptography.hazmat.primitives.ciphers import Cipher as ReferenceCipher

from cryptopals import Cipher


def check_cipher_interoperability(
    cipher: Cipher,
    reference: ReferenceCipher,
    plaintext: bytes,
) -> bool:
    assert isinstance(cipher, Cipher)
    assert isinstance(reference, ReferenceCipher)

    # Assuming both ciphers were initialized with the same parameters,
    # encrypting the same plaintext with each should produce identical
    # ciphertexts
    ct = cipher.encrypt(plaintext)
    encryptor = reference.encryptor()
    reference_ct = encryptor.update(plaintext) + encryptor.finalize()
    assert ct == reference_ct

    # Each cipher should be able to decrypt the other's ciphertext and get back
    # the original plaintext
    assert cipher.decrypt(reference_ct) == plaintext
    decryptor = reference.decryptor()
    assert decryptor.update(ct) + decryptor.finalize() == plaintext
