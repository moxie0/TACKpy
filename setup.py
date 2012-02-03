#!/usr/bin/env python

from distutils.core import setup

setup(name="TACKpy",
      version="0.9.3",
      author="Trevor Perrin",
      author_email="takckpy@trevp.net",
      url="http://trevp.net/TACK/",
      description="TACKpy implements TACK in python",
      license="public domain",
      scripts=["scripts/TACK.py"],
      packages=["TACKpy"])
