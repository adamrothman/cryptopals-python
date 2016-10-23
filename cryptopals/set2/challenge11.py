# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/2/challenges/11
"""
import random
from collections import Counter
from os import urandom

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set1.challenge7 import AESECB
from cryptopals.set2.challenge10 import AESCBC
from cryptopals.set2.challenge9 import PKCS7
from cryptopals.utils import chunks


def generate_aes_key() -> bytes:
    return urandom(16)


def generate_aes_iv() -> bytes:
    return urandom(AES_BLOCK_SIZE_BYTES)


def mystery_encrypt(plaintext: bytes) -> bytes:
    key = generate_aes_key()

    if random.random() < 0.5:
        cipher = AESECB(key)
    else:
        cipher = AESCBC(key, generate_aes_iv())

    prefix_size = random.randint(5, 10)
    suffix_size = random.randint(5, 10)
    padder = PKCS7(AES_BLOCK_SIZE_BYTES)
    padded = padder.pad(bytes(prefix_size) + plaintext + bytes(suffix_size))

    ciphertext = cipher.encrypt(padded)
    mode = 'ECB' if isinstance(cipher, AESECB) else 'CBC'
    return (ciphertext, mode)


def detect_block_cipher_mode(ciphertext: bytes) -> bytes:
    counter = Counter()
    for block in chunks(ciphertext, AES_BLOCK_SIZE_BYTES):
        counter[block] += 1
    most_common = counter.most_common(1)[0]
    return 'ECB' if most_common[1] > 1 else 'CBC'
