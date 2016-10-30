# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/2/challenges/10
"""
from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals import Cipher
from cryptopals.set1.challenge2 import fixed_xor
from cryptopals.set1.challenge7 import AESECB
from cryptopals.utils import chunks


class AESCBC(Cipher):

    def __init__(self, key: bytes, iv: bytes):
        self.aes_ecb = AESECB(key)
        if len(iv) != AES_BLOCK_SIZE_BYTES:
            raise ValueError(
                'Invalid IV size ({} bytes) for AES CBC'.format(len(iv))
            )
        self.iv = iv

    def decrypt(self, ciphertext: bytes) -> bytes:
        previous = self.iv
        plaintext_bytes = []
        for block in chunks(ciphertext, AES_BLOCK_SIZE_BYTES):
            combined = self.aes_ecb.decrypt(block)
            plaintext_block = fixed_xor(combined, previous)
            previous = block
            plaintext_bytes.extend(plaintext_block)

        return bytes(plaintext_bytes)

    def encrypt(self, plaintext: bytes) -> bytes:
        previous = self.iv
        ciphertext_bytes = []
        for block in chunks(plaintext, AES_BLOCK_SIZE_BYTES):
            combined = fixed_xor(block, previous)
            ciphertext_block = self.aes_ecb.encrypt(combined)
            previous = ciphertext_block
            ciphertext_bytes.extend(ciphertext_block)

        return bytes(ciphertext_bytes)
