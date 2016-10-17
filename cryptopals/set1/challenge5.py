# -*- coding: utf-8 -*-


def repeating_key_xor(data, key):
    """https://cryptopals.com/sets/1/challenges/5
    """
    key_len = len(key)
    return bytes([
        key[i % key_len] ^ b
        for i, b
        in enumerate(data)
    ])
