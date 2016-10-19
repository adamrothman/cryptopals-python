# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/3
"""
from cryptopals import DecryptionCandidate
from cryptopals.utils import english_language_score


def break_single_xor(ciphertext: bytes) -> DecryptionCandidate:
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
