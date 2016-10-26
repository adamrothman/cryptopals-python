# -*- coding: utf-8 -*-
from typing import Any
from typing import Dict
from urllib.parse import parse_qs
from urllib.parse import quote

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.utils import generate_aes_key
from cryptopals.utils import get_blocks
from cryptopals.set1.challenge7 import AESECB
from cryptopals.set2.challenge9 import BasicPKCS7


_key = generate_aes_key()
_padder = BasicPKCS7(AES_BLOCK_SIZE_BYTES)


def profile_for(email: str) -> Dict[str, Any]:
    escaped = email.replace('&', quote('&')).replace('=', quote('='))
    profile = (
        ('email', escaped),
        ('uid', '10'),
        ('role', 'user'),
    )
    encoded = '&'.join(['='.join(pair) for pair in profile])
    return encoded.encode('utf-8')


def encrypt(plaintext: bytes) -> bytes:
    cipher = AESECB(_key)
    return cipher.encrypt(_padder.pad(plaintext))


def decrypt_and_parse(ciphertext: bytes) -> Dict[str, Any]:
    cipher = AESECB(_key)
    plaintext = cipher.decrypt(ciphertext)
    profile = _padder.unpad(plaintext)
    parsed = parse_qs(profile)
    return {
        k.decode('utf-8'): v[0].decode('utf-8')
        for k, v
        in parsed.items()
    }


def create_admin_ciphertext() -> bytes:
    # "email=" is 6 bytes, leaving 10 bytes in a block.
    # "&uid=10&role=" is 13 bytes, leaving 3 bytes in a block.
    #
    # We need to use an email that is 10 + 3 bytes to align the role at the
    # start of the third block.
    #
    # We're interested in the first 2 encrypted blocks using this email.
    email = 'adam@adam.com'  # 13 bytes
    p1 = profile_for(email)
    ct1 = encrypt(p1)

    # Next we need to produce a ciphertext block that is "admin" followed by
    # padding to the block size.
    #
    # We know the first 10 bytes of the email end up in the first block, so our
    # email address needs to be 10 bytes + ("admin" + PKCS7 padding).
    #
    # We're interested in the second encrypted block using this email.
    email = ('\x00' * 10) + 'admin' + ('\x0b' * 11)
    p2 = profile_for(email)
    ct2 = encrypt(p2)

    return get_blocks(ct1, (0, 2), AES_BLOCK_SIZE_BYTES) + get_blocks(ct2, (1, 2), AES_BLOCK_SIZE_BYTES)
