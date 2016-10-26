# -*- coding: utf-8 -*-
"""https://cryptopals.com/sets/2/challenges/9
"""


class BasicPKCS7:

    def __init__(self, block_size):
        if block_size >= 256:
            raise ValueError('PKCS#7 padding is only well-defined for block sizes < 256')
        self.block_size = block_size

    def pad(self, data: bytes) -> bytes:
        length = self.block_size - (len(data) % self.block_size)
        padding = bytes([length for _ in range(length)])
        return data + padding

    def unpad(self, data: bytes) -> bytes:
        length = data[-1]
        return data[:-length]
