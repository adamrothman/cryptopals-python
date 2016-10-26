# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/2/challenges/11
"""
import random
from collections import Counter
from typing import Callable

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals import utils
from cryptopals.set1.challenge7 import AESECB
from cryptopals.set2.challenge10 import AESCBC
from cryptopals.set2.challenge9 import PKCS7


def mystery_encrypt(plaintext: bytes) -> bytes:
    key = utils.generate_aes_key()

    if random.random() < 0.5:
        cipher = AESECB(key)
    else:
        cipher = AESCBC(key, utils.generate_aes_iv())

    prefix_size = random.randint(5, 10)
    suffix_size = random.randint(5, 10)
    padder = PKCS7(AES_BLOCK_SIZE_BYTES)
    padded = padder.pad(bytes(prefix_size) + plaintext + bytes(suffix_size))

    ciphertext = cipher.encrypt(padded)
    mode = 'ECB' if isinstance(cipher, AESECB) else 'CBC'
    return (ciphertext, mode)


def detect_block_cipher_mode(cipher: Callable[[bytes], bytes]) -> str:
    pt = bytes(100)  # Chosen to produce repeated blocks in ECB ciphertext
    ct = cipher(pt)
    counter = Counter()
    for block in utils.chunks(ct, AES_BLOCK_SIZE_BYTES):
        counter[block] += 1
    most_common = counter.most_common(1)[0]
    return 'ECB' if most_common[1] > 1 else 'CBC'
