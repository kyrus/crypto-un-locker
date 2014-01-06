#!/usr/bin/env python

import sys
from cx_Freeze import setup, Executable

setup(
 name="CryptoUnLocker",
 version="1.0",
 Description="Detection and Decryption tool for CryptoLocker files",
 executables= [Executable("CryptoUnLocker.py")]
)
