# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/8
"""
from collections import Counter
from typing import Sequence

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.utils import chunks


def detect_aes_ecb(ciphertexts: Sequence[bytes]):
    candidates = []
    for ciphertext in ciphertexts:
        counter = Counter()
        for block in chunks(ciphertext, AES_BLOCK_SIZE_BYTES):
            counter[block] += 1
        candidates.append((ciphertext, counter.most_common(3)))
    candidates.sort(key=lambda t: t[1][0][1], reverse=True)
    return candidates[0][0]
