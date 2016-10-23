# -*- coding: utf-8 -*-
from base64 import b64decode

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set2 import challenge9
from cryptopals.set2 import challenge10
from cryptopals.set2 import challenge11
from cryptopals.set2 import challenge12


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

    cipher = challenge10.AESCBC(
        b'YELLOW SUBMARINE',
        b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
    )

    plaintext = cipher.decrypt(ciphertext)
    assert plaintext == play_that_funky_music_padded

    _ciphertext = cipher.encrypt(plaintext)
    assert _ciphertext == ciphertext


def test_challenge11():
    # Plaintext chosen to produce repeated blocks in ECB ciphertext
    plaintext = bytes(100)
    for _ in range(10):
        ciphertext, mode = challenge11.mystery_encrypt(plaintext)
        guess = challenge11.detect_block_cipher_mode(ciphertext)
        assert guess == mode


def test_challenge12():
    unknown = challenge12.decrypt_unknown()
    padder = challenge9.PKCS7(AES_BLOCK_SIZE_BYTES)
    unpadded = padder.unpad(unknown)
    assert unpadded == (
        b"Rollin' in my 5.0\n"
        b"With my rag-top down so my hair can blow\n"
        b"The girlies on standby waving just to say hi\n"
        b"Did you stop? No, I just drove by\n"
    )
