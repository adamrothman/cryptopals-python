# -*- coding: utf-8 -*-
from collections import namedtuple

from cryptography.hazmat.primitives.ciphers.algorithms import AES


AES_BLOCK_SIZE_BYTES = int(AES.block_size / 8)


DecryptionCandidate = namedtuple(
    'DecryptionCandidate',
    ['key', 'plaintext', 'score'],
)
