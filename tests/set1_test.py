# -*- coding: utf-8 -*-
from base64 import b64decode
from binascii import hexlify
from binascii import unhexlify

from cryptopals.set1 import challenge1
from cryptopals.set1 import challenge2
from cryptopals.set1 import challenge3
from cryptopals.set1 import challenge4
from cryptopals.set1 import challenge5
from cryptopals.set1 import challenge6
from cryptopals.set1 import challenge7
from cryptopals.set1 import challenge8


def test_challenge1():
    result = challenge1.hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    assert result == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def test_challenge2():
    result = challenge2.fixed_xor(
        unhexlify('1c0111001f010100061a024b53535009181c'),
        unhexlify('686974207468652062756c6c277320657965'),
    )
    assert hexlify(result) == b'746865206b696420646f6e277420706c6179'


def test_challenge3():
    key, plaintext, _ = challenge3.break_single_xor(
        unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    )
    assert key == b'X'
    assert plaintext == b"Cooking MC's like a pound of bacon"


def test_challenge4():
    with open('data/4.txt') as f:
        ciphertexts = [unhexlify(l.strip()) for l in f.readlines()]
    key, plaintext, _ = challenge4.detect_single_xor(ciphertexts)
    assert key == b'5'
    assert plaintext == b'Now that the party is jumping\n'


def test_challenge5():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext = challenge5.repeating_xor(plaintext, b'ICE')
    assert hexlify(ciphertext) == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'


def test_challenge6(play_that_funky_music):
    with open('data/6.txt') as f:
        ciphertext = b64decode(f.read())
    key, plaintext, _ = challenge6.break_repeating_xor(ciphertext)
    assert key == b'Terminator X: Bring the noise'
    assert plaintext == play_that_funky_music


def test_challenge7(play_that_funky_music_padded):
    with open('data/7.txt') as f:
        ciphertext = b64decode(f.read())
    aes_ecb = challenge7.AESECB(b'YELLOW SUBMARINE')
    plaintext = aes_ecb.decrypt(ciphertext)
    assert plaintext == play_that_funky_music_padded


def test_challenge8():
    with open('data/8.txt') as f:
        ciphertexts = [unhexlify(l.strip()) for l in f.readlines()]
    result = challenge8.detect_aes_ecb(ciphertexts)
    assert hexlify(result) == b'd880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a'
