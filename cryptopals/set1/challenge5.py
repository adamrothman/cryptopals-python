# -*- coding: utf-8 -*-
from cryptopals.set1 import Bytes


def repeating_xor(data: Bytes, key: Bytes) -> bytes:
    """https://cryptopals.com/sets/1/challenges/5
    """
    key_len = len(key)
    return bytes([
        key[i % key_len] ^ b
        for i, b
        in enumerate(data)
    ])
