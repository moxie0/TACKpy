#!/usr/bin/env python

from distutils.core import setup

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

setup(name="TACKpy",
      version="0.9.4",
      author="Trevor Perrin",
      author_email="takckpy@trevp.net",
      url="http://trevp.net/TACK/",
      description="TACKpy implements TACK in python",
      license="public domain",
      scripts=["scripts/TACK.py"],
      packages=["TACKpy"])
