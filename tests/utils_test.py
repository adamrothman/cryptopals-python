# -*- coding: utf-8 -*-
from cryptopals import utils


def test_cosine_similarity():
    assert utils.cosine_similarity((1, 0), (1, 0)) == 1
    assert utils.cosine_similarity((1, 0), (0, 1)) == 0
    assert utils.cosine_similarity((1, 0), (-1, 0)) == -1
    x = utils.cosine_similarity((1, 0), (1, 1))
    assert x > 0 and x < 1


def test_hamming_distance():
    assert utils.hamming_distance(b'this is a test', b'wokka wokka!!!') == 37


def test_hamming_weight():
    assert utils.hamming_weight(0) == 0
    assert utils.hamming_weight(1) == 1
    assert utils.hamming_weight(2) == 1
    assert utils.hamming_weight(3) == 2
    assert utils.hamming_weight(4) == 1
    assert utils.hamming_weight(5) == 2
    assert utils.hamming_weight(6) == 2
    assert utils.hamming_weight(7) == 3
