# -*- coding: utf-8 -*-
from collections import Counter
from typing import Sequence

from cryptopals import Bytes
from cryptopals import chunks


def detect_aes_ecb(ciphertexts: Sequence[Bytes]):
    candidates = []
    for ciphertext in ciphertexts:
        counter = Counter()  # type: Counter[Sequence[int]]
        for block in chunks(ciphertext, 16):
            counter[block] += 1
        candidates.append((ciphertext, counter.most_common(3)))
    candidates.sort(key=lambda t: t[1][0][1], reverse=True)
    return candidates[0][0]
