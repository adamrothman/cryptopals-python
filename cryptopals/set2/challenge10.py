# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/2/challenges/10
"""
from cryptopals.set1.challenge2 import fixed_xor
from cryptopals.set1.challenge7 import AESECB
from cryptopals.utils import chunks


BLOCK_SIZE = 16  # AES blocks are 128 bits


class AESCBC:

    def __init__(self, key: bytes, iv: bytes):
        self.aes_ecb = AESECB(key)
        if len(iv) != BLOCK_SIZE:
            raise ValueError('Invalid IV size ({}) for AES'.format(len(iv) * 8))
        self.iv = iv

    def decrypt(self, ciphertext: bytes) -> bytes:
        previous = self.iv
        plaintext_bytes = []
        for block in chunks(ciphertext, BLOCK_SIZE):
            combined = self.aes_ecb.decrypt(block)
            plaintext_block = fixed_xor(combined, previous)
            previous = block
            plaintext_bytes.extend(plaintext_block)

        return bytes(plaintext_bytes)

    def encrypt(self, plaintext: bytes) -> bytes:
        previous = self.iv
        ciphertext_bytes = []
        for block in chunks(plaintext, BLOCK_SIZE):
            combined = fixed_xor(block, previous)
            ciphertext_block = self.aes_ecb.encrypt(combined)
            previous = ciphertext_block
            ciphertext_bytes.extend(ciphertext_block)

        return bytes(ciphertext_bytes)
