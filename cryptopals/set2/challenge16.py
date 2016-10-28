# -*- coding: utf-8 -*-
from urllib.parse import quote

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set2.challenge10 import AESCBC
from cryptopals.set2.challenge15 import PKCS7
from cryptopals.utils import generate_aes_iv
from cryptopals.utils import generate_aes_key
from cryptopals.utils import get_blocks


PREFIX = b'comment1=cooking%20MCs;userdata='            # 32 bytes
SUFFIX = b';comment2=%20like%20a%20pound%20of%20bacon'  # 42 bytes


_key = generate_aes_key()
_iv = generate_aes_iv()
_cipher = AESCBC(_key, _iv)
_padder = PKCS7(AES_BLOCK_SIZE_BYTES)


def encrypt(supplied: bytes) -> bytes:
    quoted = supplied
    for b in (b';', b'='):
        quoted = quoted.replace(b, quote(b).encode('utf-8'))
    plaintext = PREFIX + quoted + SUFFIX
    padded = _padder.pad(plaintext)
    return _cipher.encrypt(padded)


def decrypt(ciphertext: bytes) -> bytes:
    padded = _cipher.decrypt(ciphertext)
    plaintext = _padder.unpad(padded)
    data = {}
    for pair in plaintext.split(b';'):
        k, v = pair.split(b'=', maxsplit=1)
        data[k] = v
    return data


def craft_ciphertext() -> bytes:
    # : (ASCII 58) is 1 bit away from ; (ASCII 59)
    # < (ASCII 60) is 1 bit away from = (ASCII 60)
    # The prefix is exactly 2 blocks.
    # We pad our string to create a valid ending block (we ignore the rest of
    # ciphertext).
    pt = _padder.pad(b':admin<true')
    ct = encrypt(pt)
    # Flipping bits in block 1 causes flips at the same offsets in subsequent
    # blocks. Block 1 of the plaintext becomes gibberish, but that's OK for our
    # purposes.
    # Flipping the LSB of the 16th byte (1st byte) makes the : a ;
    new_16 = bytes([ct[16] ^ 1])
    # Flipping the LSB of the 22nd byte (7th byte) makes the < a =
    new_22 = bytes([ct[22] ^ 1])
    block_1 = new_16 + ct[17:22] + new_22 + ct[23:32]
    # We leave blocks 0 and 2 alone. Block 1 contains our targeted flips.
    return get_blocks(ct, 0, AES_BLOCK_SIZE_BYTES) \
        + block_1 \
        + get_blocks(ct, 2, AES_BLOCK_SIZE_BYTES)


def verify_admin(ciphertext: bytes) -> bool:
    data = decrypt(ciphertext)
    return data.get(b'admin') == b'true'
