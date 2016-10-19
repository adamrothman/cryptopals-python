# -*- coding: utf-8 -*-
from base64 import b64decode

from cryptopals.set2 import challenge9
from cryptopals.set2 import challenge10


def test_challenge9():
    padder = challenge9.PKCS7(20)
    padded = padder.pad(b'YELLOW SUBMARINE')
    assert padded == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    unpadded = padder.unpad(padded)
    assert unpadded == b'YELLOW SUBMARINE'

    padder = challenge9.PKCS7(4)
    padded = padder.pad(b'hello world')
    assert padded == b'hello world\x01'
    unpadded = padder.unpad(padded)
    assert unpadded == b'hello world'

    padder = challenge9.PKCS7(16)
    padded = padder.pad(b'YELLOW SUBMARINE')
    assert padded == b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    unpadded = padder.unpad(padded)
    assert unpadded == b'YELLOW SUBMARINE'


def test_challenge10(play_that_funky_music_padded):
    with open('data/10.txt') as f:
        ciphertext = b64decode(f.read())

    aes_cbc = challenge10.AESCBC(
        b'YELLOW SUBMARINE',
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    )

    plaintext = aes_cbc.decrypt(ciphertext)
    assert plaintext == play_that_funky_music_padded

    _ciphertext = aes_cbc.encrypt(plaintext)
    assert _ciphertext == ciphertext
