# -*- coding: utf-8 -*-
from base64 import b64encode
from binascii import unhexlify


def hex_to_b64(hex_str):
    """https://cryptopals.com/sets/1/challenges/1
    """
    raw = unhexlify(hex_str)
    return b64encode(raw)
