# -*- coding: utf-8 -*-
from cryptography.hazmat.backends import default_backend           # type: ignore
from cryptography.hazmat.primitives.ciphers import Cipher          # type: ignore
from cryptography.hazmat.primitives.ciphers.algorithms import AES  # type: ignore
from cryptography.hazmat.primitives.ciphers.modes import ECB       # type: ignore

from cryptopals.set1 import Bytes


def aes_ecb_decrypt(ciphertext: Bytes, key: Bytes) -> bytes:
    """https://cryptopals.com/sets/1/challenges/7
    """
    backend = default_backend()
    cipher = Cipher(AES(key), ECB(), backend)
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.strip(b'\x00\x04')  # Remove padding, if any
