# -*- coding: utf-8 -*-
"""I found the Wikipedia article on this attack pretty confusing and unhelpful.
SkullSecurity, on the other hand, has an awesome article that reaches just the
right depth: https://blog.skullsecurity.org/2013/padding-oracle-attacks-in-depth
"""
from typing import Callable
from typing import Tuple

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set2.challenge10 import AESCBC
from cryptopals.set2.challenge15 import InvalidPaddingError
from cryptopals.set2.challenge15 import PKCS7
from cryptopals.utils import chunks
from cryptopals.utils import generate_aes_iv
from cryptopals.utils import generate_aes_key


_key = generate_aes_key()
_padder = PKCS7(AES_BLOCK_SIZE_BYTES)


def encrypt(plaintext: bytes) -> Tuple[bytes, bytes]:
    iv = generate_aes_iv()
    cipher = AESCBC(_key, iv)
    pt = _padder.pad(plaintext)
    ct = cipher.encrypt(pt)
    return (iv, ct)


def padding_oracle(iv: bytes, ciphertext: bytes) -> bool:
    cipher = AESCBC(_key, iv)
    padded = cipher.decrypt(ciphertext)
    try:
        _padder.unpad(padded)
    except InvalidPaddingError:
        return False
    return True


def _build_c_prime(pad_byte: int, p_n: bytes, c_n1: bytes) -> bytearray:
    """C'[I] = pad ⊕ P_n[I] ⊕ C_n-1[I]
    """
    return bytearray([
        pad_byte ^ p_n[i] ^ c_n1[i]
        for i
        in range(len(c_n1))
    ])


def _decrypt_block(
    previous: bytes,
    block: bytes,
    oracle: Callable[[bytes, bytes], bool],
) -> bytearray:
    """Previous is C_n-1, block is C_n.
    """
    zero_iv = bytes(AES_BLOCK_SIZE_BYTES)
    known = bytearray(AES_BLOCK_SIZE_BYTES)

    for offset in range(1, AES_BLOCK_SIZE_BYTES + 1):
        for guess in range(256):
            c_prime = _build_c_prime(offset, known, previous)
            c_prime[-offset] = guess
            ct = bytes(c_prime + block)
            if oracle(zero_iv, ct) is True:
                # P_n[X] = P'2[X] ⊕ C_n-1[X] ⊕ C'[X]
                p_n_x = offset ^ previous[-offset] ^ c_prime[-offset]
                known[-offset] = p_n_x
                break
        else:
            raise RuntimeError('Never found suitable byte')
    return known


def decrypt_using_oracle(
    iv: bytes,
    ciphertext: bytes,
    oracle: Callable[[bytes, bytes], bool],
) -> bytes:
    known = bytearray()

    previous = iv
    for ct_block in chunks(ciphertext, AES_BLOCK_SIZE_BYTES):
        # We decrypt the ciphertext blocks from head to tail but the order
        # doesn't matter. You could even do it in parallel.
        pt_block = _decrypt_block(previous, ct_block, oracle)
        known.extend(pt_block)
        previous = ct_block

    plaintext = _padder.unpad(known)
    return bytes(plaintext)
