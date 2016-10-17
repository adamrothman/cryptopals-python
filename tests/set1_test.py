# -*- coding: utf-8 -*-
from binascii import hexlify
from binascii import unhexlify

from cryptopals.set1 import challenge1
from cryptopals.set1 import challenge2
from cryptopals.set1 import challenge3
from cryptopals.set1 import challenge4
from cryptopals.set1 import challenge5


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
    result = challenge3.decrypt_single_byte_xor(
        unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    )
    assert result == b"Cooking MC's like a pound of bacon"


def test_challenge4():
    with open('data/4.txt') as f:
        ciphertexts = [unhexlify(l.strip()) for l in f.readlines()]
    result = challenge4.detect_single_xor(ciphertexts)
    assert result == b'Now that the party is jumping\n'


def test_challenge5():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    ciphertext = challenge5.repeating_key_xor(plaintext, b'ICE')
    assert hexlify(ciphertext) == b'0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
