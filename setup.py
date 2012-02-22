#!/usr/bin/env python

from distutils.core import setup

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

setup(name="TACKpy",
      version="0.9.5",
      author="Trevor Perrin",
      author_email="tackpy@trevp.net",
      url="https://github.com/trevp/TACKpy",
      description="TACKpy implements TACK in python",
      license="public domain",
      scripts=["scripts/TACK.py"],
      packages=["TACKpy"])
