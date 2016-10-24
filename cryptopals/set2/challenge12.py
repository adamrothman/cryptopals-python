# -*- coding: utf-8 -*-
from base64 import b64decode
from itertools import count
from typing import Callable

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set1.challenge7 import AESECB
from cryptopals.set2.challenge11 import detect_block_cipher_mode
from cryptopals.set2.challenge9 import PKCS7
from cryptopals.utils import generate_aes_key


UNKNOWN_STRING = (
    'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
    'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
    'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
    'YnkK'
)

_key = None


def oracle_encrypt(plaintext: bytes) -> bytes:
    global _key
    if _key is None:
        _key = generate_aes_key()

    unknown_data = b64decode(UNKNOWN_STRING)

    padder = PKCS7(AES_BLOCK_SIZE_BYTES)
    padded = padder.pad(plaintext + unknown_data)

    cipher = AESECB(_key)
    return cipher.encrypt(padded)


def detect_block_size(cipher: Callable[[bytes], bytes]) -> int:
    start = len(cipher(b''))
    for i in count(1):
        ciphertext = cipher(bytes(i))
        new = len(ciphertext)
        if new > start:
            return new - start


def decrypt_unknown():
    block_size = detect_block_size(oracle_encrypt)

    ciphertext = oracle_encrypt(bytes(100))
    mode = detect_block_cipher_mode(ciphertext)
    if mode != 'ECB':
        raise ValueError('Cipher not operating in ECB mode')

    known = []
    while True:
        pad_size = block_size - (len(known) % block_size) - 1
        pad = bytes(pad_size)
        base = pad + bytes(known)

        ciphertext_to_byte = {}
        for i in range(256):
            test_input = base + bytes([i])
            ciphertext = oracle_encrypt(test_input)
            chunk = ciphertext[:len(test_input)]
            ciphertext_to_byte[chunk] = i

        ciphertext = oracle_encrypt(pad)
        chunk = ciphertext[:len(base) + 1]
        byte = ciphertext_to_byte.get(chunk)
        if byte is None:
            return bytes(known)
        else:
            known.append(byte)
