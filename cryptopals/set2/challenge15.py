# -*- coding: utf-8 -*-
from cryptopals.set2.challenge9 import BasicPKCS7


class InvalidPaddingError(Exception):
    pass


class PKCS7(BasicPKCS7):

    def unpad(self, data: bytes) -> bytes:
        length = data[-1]
        padding = data[-length:]
        for b in padding:
            if b != length:
                raise InvalidPaddingError(
                    '{} is not valid PKCS7 padding'.format(padding)
                )
        return data[:-length]
