# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/7
"""
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import ECB


class AESECB:

    def __init__(self, key: bytes):
        self.cipher = Cipher(AES(key), ECB(), default_backend())

    def decrypt(self, ciphertext: bytes) -> bytes:
        decryptor = self.cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext

    def encrypt(self, plaintext: bytes) -> bytes:
        encryptor = self.cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext
