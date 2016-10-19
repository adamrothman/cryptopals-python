# -*- coding: utf-8 -*-
from typing import Iterator
from typing import Sequence
from typing import TypeVar
from typing import Union


Bytes = Union[bytearray, bytes]
T = TypeVar('T')


def chunks(iterable: Sequence[T], n: int) -> Iterator[Sequence[T]]:
    for i in range(0, len(iterable), n):
        yield iterable[i:i + n]
