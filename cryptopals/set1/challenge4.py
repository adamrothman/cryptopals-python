# -*- coding: utf-8 -*-
from cryptopals.set1 import most_likely_english


def detect_single_xor(ciphertexts):
    """https://cryptopals.com/sets/1/challenges/4
    """
    pairs = []
    for ciphertext in ciphertexts:
        pair = most_likely_english([
            bytes([k ^ b for b in ciphertext])
            for k
            in range(256)
        ])
        pairs.append(pair)
    candidate, score = max(pairs, key=lambda p: p[1])
    print('{} ({})'.format(candidate, score))
    return candidate
