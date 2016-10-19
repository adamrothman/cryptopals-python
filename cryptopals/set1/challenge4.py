# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/4
"""
from typing import Sequence

from cryptopals import DecryptionCandidate
from cryptopals.set1.challenge3 import break_single_xor


def detect_single_xor(ciphertexts: Sequence[bytes]) -> DecryptionCandidate:
    return max(
        [break_single_xor(c) for c in ciphertexts],
        key=lambda c: c.score,
    )
