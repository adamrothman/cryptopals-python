# -*- coding: utf-8 -*-
import abc
from collections import namedtuple

from cryptography.hazmat.primitives.ciphers.algorithms import AES


AES_BLOCK_SIZE_BYTES = int(AES.block_size / 8)


DecryptionCandidate = namedtuple(
    'DecryptionCandidate',
    ['key', 'plaintext', 'score'],
)


class Cipher(metaclass=abc.ABCMeta):

    @abc.abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        ...

    @abc.abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        ...
