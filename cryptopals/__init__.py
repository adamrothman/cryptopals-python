# -*- coding: utf-8 -*-
from collections import namedtuple


DecryptionCandidate = namedtuple(
    'DecryptionCandidate',
    ['key', 'plaintext', 'score'],
)
