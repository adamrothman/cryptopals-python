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
from cryptopals.set1 import hamming_distance


PLAY_THAT_FUNKY_MUSIC = (
    b"I'm back and I'm ringin' the bell \n"
    b"A rockin' on the mike while the fly girls yell \n"
    b"In ecstasy in the back of me \n"
    b"Well that's my DJ Deshay cuttin' all them Z's \n"
    b"Hittin' hard and the girlies goin' crazy \n"
    b"Vanilla's on the mike, man I'm not lazy. \n"
    b"\n"
    b"I'm lettin' my drug kick in \n"
    b"It controls my mouth and I begin \n"
    b"To just let it flow, let my concepts go \n"
    b"My posse's to the side yellin', Go Vanilla Go! \n"
    b"\n"
    b"Smooth 'cause that's the way I will be \n"
    b"And if you don't give a damn, then \n"
    b"Why you starin' at me \n"
    b"So get off 'cause I control the stage \n"
    b"There's no dissin' allowed \n"
    b"I'm in my own phase \n"
    b"The girlies sa y they love me and that is ok \n"
    b"And I can dance better than any kid n' play \n"
    b"\n"
    b"Stage 2 -- Yea the one ya' wanna listen to \n"
    b"It's off my head so let the beat play through \n"
    b"So I can funk it up and make it sound good \n"
    b"1-2-3 Yo -- Knock on some wood \n"
    b"For good luck, I like my rhymes atrocious \n"
    b"Supercalafragilisticexpialidocious \n"
    b"I'm an effect and that you can bet \n"
    b"I can take a fly girl and make her wet. \n"
    b"\n"
    b"I'm like Samson -- Samson to Delilah \n"
    b"There's no denyin', You can try to hang \n"
    b"But you'll keep tryin' to get my style \n"
    b"Over and over, practice makes perfect \n"
    b"But not if you're a loafer. \n"
    b"\n"
    b"You'll get nowhere, no place, no time, no girls \n"
    b"Soon -- Oh my God, homebody, you probably eat \n"
    b"Spaghetti with a spoon! Come on and say it! \n"
    b"\n"
    b"VIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \n"
    b"Intoxicating so you stagger like a wino \n"
    b"So punks stop trying and girl stop cryin' \n"
    b"Vanilla Ice is sellin' and you people are buyin' \n"
    b"'Cause why the freaks are jockin' like Crazy Glue \n"
    b"Movin' and groovin' trying to sing along \n"
    b"All through the ghetto groovin' this here song \n"
    b"Now you're amazed by the VIP posse. \n"
    b"\n"
    b"Steppin' so hard like a German Nazi \n"
    b"Startled by the bases hittin' ground \n"
    b"There's no trippin' on mine, I'm just gettin' down \n"
    b"Sparkamatic, I'm hangin' tight like a fanatic \n"
    b"You trapped me once and I thought that \n"
    b"You might have it \n"
    b"So step down and lend me your ear \n"
    b"'89 in my time! You, '90 is my year. \n"
    b"\n"
    b"You're weakenin' fast, YO! and I can tell it \n"
    b"Your body's gettin' hot, so, so I can smell it \n"
    b"So don't be mad and don't be sad \n"
    b"'Cause the lyrics belong to ICE, You can call me Dad \n"
    b"You're pitchin' a fit, so step back and endure \n"
    b"Let the witch doctor, Ice, do the dance to cure \n"
    b"So come up close and don't be square \n"
    b"You wanna battle me -- Anytime, anywhere \n"
    b"\n"
    b"You thought that I was weak, Boy, you're dead wrong \n"
    b"So come on, everybody and sing this song \n"
    b"\n"
    b"Say -- Play that funky music Say, go white boy, go white boy go \n"
    b"play that funky music Go white boy, go white boy, go \n"
    b"Lay down and boogie and play that funky music till you die. \n"
    b"\n"
    b"Play that funky music Come on, Come on, let me hear \n"
    b"Play that funky music white boy you say it, say it \n"
    b"Play that funky music A little louder now \n"
    b"Play that funky music, white boy Come on, Come on, Come on \n"
    b"Play that funky music \n"
)


def test_challenge1():
    result = challenge1.hex_to_b64('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d')
    assert result == b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'


def test_challenge2():
    result = challenge2.single_xor(
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


def test_challenge6():
    assert hamming_distance(b'this is a test', b'wokka wokka!!!') == 37

    with open('data/6.txt') as f:
        ciphertext = b64decode(f.read())
    key, plaintext, _ = challenge6.break_repeating_xor(ciphertext)
    assert key == b'Terminator X: Bring the noise'
    assert plaintext == PLAY_THAT_FUNKY_MUSIC


def test_challenge7():
    with open('data/7.txt') as f:
        ciphertext = b64decode(f.read())
    plaintext = challenge7.aes_ecb_decrypt(ciphertext, b'YELLOW SUBMARINE')
    assert plaintext == PLAY_THAT_FUNKY_MUSIC
