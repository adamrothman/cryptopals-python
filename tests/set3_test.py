# -*- coding: utf-8 -*-
from base64 import b64decode
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.ciphers.modes import CTR

from cryptopals.set3 import challenge17
from cryptopals.set3 import challenge18
from cryptopals.testing import check_cipher_interoperability


def test_challenge17():
    plaintexts = (
        b'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        b'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        b'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        b'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        b'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        b'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        b'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        b'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        b'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        b'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    )
    for pt in plaintexts:
        iv, ct = challenge17.encrypt(pt)
        decrypted = challenge17.decrypt_using_oracle(
            iv,
            ct,
            challenge17.padding_oracle,
        )
        assert decrypted == pt


def test_challenge18():
    key = b'YELLOW SUBMARINE'
    nonce = urandom(16)

    be_cipher = challenge18.AESCTR(key, nonce, byteorder='big')
    reference = Cipher(AES(key), CTR(nonce), default_backend())
    check_cipher_interoperability(
        be_cipher,
        reference,
        b'welcome to the wonderful world of cryptography',
    )

    # The ciphertext provided by the exercise prompt was produced using the
    # increment function in little endian mode (which seems to not be the
    # default)
    le_cipher = challenge18.AESCTR(
        key,
        bytes(16),
        byteorder='little',
    )
    ciphertext = b64decode(
        b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    )
    plaintext = le_cipher.crypt(ciphertext)
    assert plaintext == b"Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby "
