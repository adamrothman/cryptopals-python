# -*- coding: utf-8 -*-
from cryptopals.set1 import Bytes


def single_xor(a: Bytes, b: Bytes) -> bytes:
    """https://cryptopals.com/sets/1/challenges/2
    """
    len_a, len_b = len(a), len(b)
    if len_a != len_b:
        raise RuntimeError('Cannot XOR two buffers of differing lengths')
    return bytes([
        a[i] ^ b[i]
        for i
        in range(len_a)
    ])
