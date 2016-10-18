# -*- coding: utf-8 -*-
from typing import Sequence

from cryptopals.set1 import Bytes
from cryptopals.set1 import DecryptionCandidate
from cryptopals.set1.challenge3 import break_single_xor


def detect_single_xor(ciphertexts: Sequence[Bytes]) -> DecryptionCandidate:
    """https://cryptopals.com/sets/1/challenges/4
    """
    return max(
        [break_single_xor(c) for c in ciphertexts],
        key=lambda c: c.score,
    )
