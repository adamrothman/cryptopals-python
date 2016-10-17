# -*- coding: utf-8 -*-
from cryptopals.set1 import most_likely_english


def decrypt_single_byte_xor(ciphertext):
    """https://cryptopals.com/sets/1/challenges/3
    """
    candidate, score = most_likely_english([
        bytes([k ^ b for b in ciphertext])
        for k
        in range(256)
    ])
    print('{} ({})'.format(candidate, score))
    return candidate
