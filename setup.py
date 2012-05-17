#!/usr/bin/env python

# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

from distutils.core import setup

import os
import shutil

shutil.copyfile("tack.py", "tack/tack")

setup(  name="tackpy",
        version="0.9.6",
        author="Trevor Perrin",
        author_email="tackpy@trevp.net",
        url="https://github.com/trevp/TACKpy",
        description="TACKpy implements TACK in python",
        license="public domain",
        scripts=["tack/tack"],
        packages=["tack", "tack/commands", "tack/crypto", "tack/crypto/openssl",
                "tack/crypto/python", "tack/structures", "tack/tls", "tack/util"],
        data_files=[("", ["LICENSE", "tack.py", "Makefile"]),
                    ("testdata", ["testdata/serverX509Cert.pem", "testdata/serverX509Cert.der"])]
        )

print "Cleaning up..."
if os.path.exists("build/"):
    shutil.rmtree("build/")

try:
    os.remove("tack/tack")
except:
    pass
