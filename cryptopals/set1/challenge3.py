# -*- coding: utf-8 -*-
from cryptopals.set1 import Bytes
from cryptopals.set1 import DecryptionCandidate
from cryptopals.set1 import english_language_score


def break_single_xor(ciphertext: Bytes) -> DecryptionCandidate:
    """https://cryptopals.com/sets/1/challenges/3
    """
    candidates = []
    for k in range(256):
        plaintext = bytes([k ^ b for b in ciphertext])
        score = english_language_score(plaintext)
        candidates.append(
            DecryptionCandidate(
                key=bytes([k]),
                plaintext=plaintext,
                score=score,
            )
        )
    return max(candidates, key=lambda c: c.score)
