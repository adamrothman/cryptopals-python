# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/1/challenges/2
"""


def fixed_xor(a: bytes, b: bytes) -> bytes:
    len_a, len_b = len(a), len(b)
    if len_a != len_b:
        raise ValueError('Cannot XOR two buffers of differing lengths')
    return bytes([a[i] ^ b[i] for i in range(len_a)])
