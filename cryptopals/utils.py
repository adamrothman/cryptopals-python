# -*- coding: utf-8 -*-
from collections import Counter
from math import sqrt
from os import urandom
from typing import Iterator
from typing import Sequence
from typing import TypeVar

from cryptopals import AES_BLOCK_SIZE_BYTES


T = TypeVar('T')


# http://www.data-compression.com/english.html
ENGLISH_CHAR_FREQUENCIES = {
    ' ': 0.1918182,
    'a': 0.0651738,
    'b': 0.0124248,
    'c': 0.0217339,
    'd': 0.0349835,
    'e': 0.1041442,
    'f': 0.0197881,
    'g': 0.0158610,
    'h': 0.0492888,
    'i': 0.0558094,
    'j': 0.0009033,
    'k': 0.0050529,
    'l': 0.0331490,
    'm': 0.0202124,
    'n': 0.0564513,
    'o': 0.0596302,
    'p': 0.0137645,
    'q': 0.0008606,
    'r': 0.0497563,
    's': 0.0515760,
    't': 0.0729357,
    'u': 0.0225134,
    'v': 0.0082903,
    'w': 0.0171272,
    'x': 0.0013692,
    'y': 0.0145984,
    'z': 0.0007836,
}
ENGLISH_CHARS = sorted(ENGLISH_CHAR_FREQUENCIES.keys())
ENGLISH_FREQUENCY_VECTOR = [ENGLISH_CHAR_FREQUENCIES[c] for c in ENGLISH_CHARS]


def chunks(iterable: Sequence[T], n: int) -> Iterator[Sequence[T]]:
    for i in range(0, len(iterable), n):
        yield iterable[i:i + n]


def cosine_similarity(a: Sequence[float], b: Sequence[float]) -> float:
    """See https://en.wikipedia.org/wiki/Cosine_similarity for details.
    """
    len_a, len_b = len(a), len(b)
    if len_a != len_b:
        raise RuntimeError('Cosine similarity may only be computed between vectors of equal arity')
    sum_a2, sum_ab, sum_b2 = 0.0, 0.0, 0.0
    for i in range(len_a):
        a_i, b_i = a[i], b[i]
        sum_a2 += a_i ** 2
        sum_ab += a_i * b_i
        sum_b2 += b_i ** 2
    return sum_ab / sqrt(sum_a2 * sum_b2)


def english_language_score(data: bytes) -> float:
    """Calculates the cosine similarity between the frequencies of English
    alphabet characters in the sample and expected frequencies for the same
    letters. Returns a value in the interval [0, 1]; the higher the value, the
    more likely the sample is English.
    """
    counter = Counter()
    for i in data:
        if i == 32 or (i >= 65 and i <= 90) or (i >= 97 and i <= 122):
            # space, A-Z, a-z
            counter[chr(i).lower()] += 1
        elif (i >= 33 and i <= 64) or (i >= 91 and i <= 96) or (i >= 123 and i <= 126):
            # numbers and (most) punctuation
            continue
        elif i == 9 or i == 10 or i == 13:
            # \t, \n, \r
            continue
        else:
            # data is almost certainly not English text
            return 0

    length = len(data)
    observed = [counter[c] / length for c in ENGLISH_CHARS]
    return cosine_similarity(observed, ENGLISH_FREQUENCY_VECTOR)


def generate_aes_key() -> bytes:
    return urandom(16)


def generate_aes_iv() -> bytes:
    return urandom(AES_BLOCK_SIZE_BYTES)


def hamming_distance(a: bytes, b: bytes) -> int:
    len_a, len_b = len(a), len(b)
    if len_a != len_b:
        raise ValueError('Hamming distance may only be computed between buffers of equal size')
    count = 0
    for i in range(len_a):
        count += hamming_weight(a[i] ^ b[i])
    return count


def hamming_weight(i: int) -> int:
    return bin(i).count('1')
