#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import find_packages
from setuptools import setup


setup(
    name='cryptopals',
    version='0.0.1',

    packages=find_packages(),

    install_requires=[],

    author='Adam Rothman',
    author_email='rothman.adam@gmail.com',
    description='Implementations of cryptopals challenges in Python',
)
