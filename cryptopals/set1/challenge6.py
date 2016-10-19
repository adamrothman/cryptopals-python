# -*- coding: utf-8 -*-
from itertools import combinations

from cryptopals import Bytes
from cryptopals import chunks
from cryptopals.set1 import DecryptionCandidate
from cryptopals.set1 import english_language_score
from cryptopals.set1 import hamming_distance
from cryptopals.set1.challenge3 import break_single_xor
from cryptopals.set1.challenge5 import repeating_xor


N = 4


def break_repeating_xor(ciphertext: Bytes) -> DecryptionCandidate:
    """https://cryptopals.com/sets/1/challenges/6
    """
    size_distance_pairs = []
    for key_size in range(2, 41):
        first_n_blocks = list(chunks(ciphertext, key_size))[:N]
        pairwise = combinations(first_n_blocks, 2)
        normalized_distances = [
            hamming_distance(a, b) / key_size
            for a, b
            in pairwise
        ]
        average_normalized = sum(normalized_distances) / len(normalized_distances)
        size_distance_pairs.append((key_size, average_normalized))

    key_size_candidates = sorted(size_distance_pairs, key=lambda p: p[1])

    candidates = []
    for key_size, _ in key_size_candidates[:N]:
        # First element is the concatenation of the first byte in every block.
        # Second is the concatenation of the second byte in each block.
        # etc...
        transposed = [bytearray() for _ in range(key_size)]
        for block in chunks(ciphertext, key_size):
            for i, b in enumerate(block):
                transposed[i].append(b)

        key_parts = []  # type: List[int]
        for i, block in enumerate(transposed):
            part, _, _ = break_single_xor(block)
            key_parts.extend(part)

        key = bytes(key_parts)
        plaintext = repeating_xor(ciphertext, key)

        candidates.append(
            DecryptionCandidate(
                key=key,
                plaintext=plaintext,
                score=english_language_score(plaintext),
            )
        )
    return max(candidates, key=lambda c: c.score)
