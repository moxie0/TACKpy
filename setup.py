#!/usr/bin/env python

from distutils.core import setup

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.
import os
import shutil

shutil.copyfile("tack.py", "tack/tack")

setup(name="TACKpy",
      version="0.9.6",
      author="Trevor Perrin",
      author_email="tackpy@trevp.net",
      url="https://github.com/trevp/TACKpy",
      description="TACKpy implements TACK in python",
      license="public domain",
      scripts=["tack/tack"],
      packages=["tack", "tack/commands", "tack/crypto", "tack/structures",
                "tack/tls", "tack/util"],
      install_requires=['M2Crypto'])

print "Cleaning up..."
if os.path.exists("build/"):
    shutil.rmtree("build/")

try:
    os.remove("tack/tack")
except:
    pass
