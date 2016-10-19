# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/5
"""


def repeating_xor(data: bytes, key: bytes) -> bytes:
    key_len = len(key)
    return bytes([
        key[i % key_len] ^ b
        for i, b
        in enumerate(data)
    ])
