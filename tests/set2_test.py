# -*- coding: utf-8 -*-
from base64 import b64decode

from pytest import raises

from cryptopals import AES_BLOCK_SIZE_BYTES
from cryptopals.set2 import challenge9
from cryptopals.set2 import challenge10
from cryptopals.set2 import challenge11
from cryptopals.set2 import challenge12
from cryptopals.set2 import challenge13
from cryptopals.set2 import challenge14
from cryptopals.set2 import challenge15
from cryptopals.set2 import challenge16


def test_challenge9():
    padder = challenge9.BasicPKCS7(20)
    padded = padder.pad(b'YELLOW SUBMARINE')
    assert padded == b'YELLOW SUBMARINE\x04\x04\x04\x04'
    unpadded = padder.unpad(padded)
    assert unpadded == b'YELLOW SUBMARINE'

    padder = challenge9.BasicPKCS7(4)
    padded = padder.pad(b'hello world')
    assert padded == b'hello world\x01'
    unpadded = padder.unpad(padded)
    assert unpadded == b'hello world'

    padder = challenge9.BasicPKCS7(16)
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
    for _ in range(32):
        mode_used = None

        def cipher(pt: bytes) -> bytes:
            """Need this wrapper to capture the actual mode used, for comparison
            later.
            """
            nonlocal mode_used
            ct, mode_used = challenge11.mystery_encrypt(pt)
            return ct

        guess = challenge11.detect_block_cipher_mode(cipher)
        assert guess == mode_used


def test_challenge12(rollin_in_my_50):
    unknown = challenge12.decrypt_unknown(challenge12.oracle_encrypt)
    padder = challenge9.BasicPKCS7(AES_BLOCK_SIZE_BYTES)
    unpadded = padder.unpad(unknown)
    assert unpadded == rollin_in_my_50


def test_challenge13():
    ciphertext = challenge13.create_admin_ciphertext()
    profile = challenge13.decrypt_and_parse(ciphertext)
    assert profile['role'] == 'admin'


def test_challenge14(rollin_in_my_50):
    unknown = challenge14.decrypt_unknown_with_prefix()
    padder = challenge9.BasicPKCS7(AES_BLOCK_SIZE_BYTES)
    unpadded = padder.unpad(unknown)
    assert unpadded == rollin_in_my_50


def test_challenge15():
    padder = challenge15.PKCS7(16)

    padded = padder.pad(b'YELLOW SUBMARINE')
    assert padded == b'YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10'
    unpadded = padder.unpad(padded)
    assert unpadded == b'YELLOW SUBMARINE'

    assert padder.unpad(b'ICE ICE BABY\x04\x04\x04\x04') == b'ICE ICE BABY'
    with raises(challenge15.InvalidPaddingError):
        padder.unpad(b'ICE ICE BABY\x05\x05\x05\x05')
    with raises(challenge15.InvalidPaddingError):
        padder.unpad(b'ICE ICE BABY\x01\x02\x03\x04')


def test_challenge16():
    ct = challenge16.encrypt(b'a;admin=true')
    assert challenge16.verify_admin(ct) is False

    ct = challenge16.craft_ciphertext()
    assert challenge16.verify_admin(ct) is True
