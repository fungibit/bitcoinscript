#!/usr/bin/env python

from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

# Read version info from bitcoinscript/version.py
version_vars = {}
with open("bitcoinscript/version.py") as fp:
    exec(fp.read(), version_vars)
version_string = version_vars['__version_string__']

setup(
    name='bitcoinscript',
    description='Friendly interface for bitcoin scripts',
    long_description=long_description,
    version=version_string,

    author='fungibit',
    author_email='fungibit@yandex.com',
    url='https://github.com/fungibit/bitcoinscript',
    license='MIT',

    packages=find_packages(exclude=['tests*', 'bin']),
    platforms = ["POSIX", "Windows"],
    keywords='bitcoin, script, bitcoin-script, blockchain',
)
