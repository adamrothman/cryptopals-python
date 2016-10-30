# -*- coding: utf-8 -*-
from math import ceil

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals import Cipher
from cryptopals.set1.challenge2 import fixed_xor
from cryptopals.set1.challenge7 import AESECB


def increment(counter_block: bytes, m_in_bits: int, byteorder: str) -> bytes:
    """See NIST Special Publication 800-38A, Appendix B.1
    http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    """
    if m_in_bits % 8 != 0:
        raise ValueError('m must be an even multiple of 8')
    m_in_bytes = int(m_in_bits / 8)

    prefix_bytes = counter_block[:-m_in_bytes]

    x_bytes = counter_block[-m_in_bytes:]
    x = int.from_bytes(x_bytes, byteorder=byteorder)
    next_x = (x + 1) % (2 ** m_in_bits)

    return prefix_bytes + next_x.to_bytes(m_in_bytes, byteorder=byteorder)


class AESCTR(Cipher):

    COUNTER_BITS = int(AES_BLOCK_SIZE_BYTES / 2) * 8

    def __init__(self, key: bytes, nonce: bytes, byteorder: str = 'big'):
        self.aes_ecb = AESECB(key)
        if len(nonce) != AES_BLOCK_SIZE_BYTES:
            raise ValueError(
                'Invalid nonce size ({} bytes) for AES CTR'.format(len(nonce))
            )
        self.nonce = nonce
        self.byteorder = byteorder

    def crypt(self, data: bytes) -> bytes:
        """Encryption and decryption in CTR mode are the same; the methods below
        just wrap this one.
        """
        # Blocks of keystream we need to generate
        block_count = ceil(len(data) / AES_BLOCK_SIZE_BYTES)

        keystream = bytearray()
        counter_block = self.nonce
        for block_i in range(block_count):
            keystream_block = self.aes_ecb.encrypt(counter_block)
            keystream.extend(keystream_block)
            counter_block = increment(
                counter_block,
                type(self).COUNTER_BITS,
                self.byteorder,
            )

        # We only need len(data) bytes of the keystream for the XOR
        keystream = keystream[:len(data)]
        return fixed_xor(keystream, data)

    def decrypt(self, ciphertext: bytes) -> bytes:
        return self.crypt(ciphertext)

    def encrypt(self, plaintext: bytes) -> bytes:
        return self.crypt(plaintext)
