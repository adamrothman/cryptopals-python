# -*- coding: utf-8 -*-
from os import urandom
from random import randint
from typing import Callable

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set1.challenge7 import AESECB
from cryptopals.set2.challenge11 import detect_block_cipher_mode
from cryptopals.set2.challenge12 import detect_block_size
from cryptopals.set2.challenge12 import UNKNOWN_DATA
from cryptopals.set2.challenge9 import PKCS7
from cryptopals.utils import chunks
from cryptopals.utils import generate_aes_key
from cryptopals.utils import get_blocks


_key = generate_aes_key()
_padder = PKCS7(AES_BLOCK_SIZE_BYTES)
_prefix = urandom(randint(0, 100))  # Decryption works for arbitrary sizes


def count_matching_prefix_blocks(a: bytes, b: bytes, block_size: int) -> bytes:
    i = 0
    for a_block, b_block in zip(chunks(a, block_size), chunks(b, block_size)):
        if a_block == b_block:
            i += 1
        else:
            return i


def detect_prefix_size(cipher: Callable[[bytes], bytes]) -> int:
    block_size = detect_block_size(cipher)

    # First we need to figure out which block the prefix extends into
    ref = cipher(bytes(block_size))
    matching = None
    prefix_end_block_index = None  # Index of block containing the first non-prefix byte

    for i in range(block_size - 1, -1, -1):
        ct = cipher(bytes(i))
        prefix_end_block_index = count_matching_prefix_blocks(ct, ref, block_size)
        if matching is None:
            matching = prefix_end_block_index
        elif prefix_end_block_index < matching:
            break

    # Then we can to determine how far into that block the prefix extends
    test = cipher(bytes(2 * block_size))
    solid_zeros = get_blocks(test, prefix_end_block_index + 1, block_size)

    for i in range(block_size):
        ct = cipher(bytes(i + block_size))
        if i == 0 and get_blocks(ct, prefix_end_block_index, block_size) == solid_zeros:
            return prefix_end_block_index * block_size
        elif get_blocks(ct, prefix_end_block_index + 1, block_size) == solid_zeros:
            return prefix_end_block_index * block_size + block_size - i


def oracle_encrypt(plaintext: bytes) -> bytes:
    cipher = AESECB(_key)
    padded = _padder.pad(_prefix + plaintext + UNKNOWN_DATA)
    return cipher.encrypt(padded)


def decrypt_unknown_with_random_prefix():
    block_size = detect_block_size(oracle_encrypt)
    if detect_block_cipher_mode(oracle_encrypt) != 'ECB':
        raise ValueError('Cipher not operating in ECB mode')

    prefix_size = detect_prefix_size(oracle_encrypt)

    # Number of bytes we should ignore; prefix size rounded up to next block boundary
    ignore = prefix_size + block_size - prefix_size % block_size

    known = []
    while True:
        # This pad takes the prefix out of the equation and ensures that we're
        # starting on a block boundary.
        prefix_pad_size = block_size - prefix_size % block_size
        prefix_pad = bytes(prefix_pad_size)
        # Regular pad as in challenge 12.
        pad_size = block_size - len(known) % block_size - 1
        pad = bytes(pad_size)
        base = pad + bytes(known)

        ciphertext_to_byte = {}
        for i in range(256):
            test_input = prefix_pad + base + bytes([i])
            ct = oracle_encrypt(test_input)
            chunk = ct[ignore:ignore + len(base) + 1]
            ciphertext_to_byte[chunk] = i

        # Encrypt with _only_ the padding
        ct = oracle_encrypt(prefix_pad + pad)
        chunk = ct[ignore:ignore + len(base) + 1]
        byte = ciphertext_to_byte.get(chunk)
        if byte is None:
            return bytes(known)
        else:
            known.append(byte)
