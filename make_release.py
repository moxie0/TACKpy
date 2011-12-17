from numbertheory import *
from ellipticcurve import *
from ecdsa import *
from rijndael import *
from compat import *
from cryptomath import *
from ecdsa_wrappers import *
from time import *
from pem import *
from struct_parser import *
from asn1_parser import *
from constants import *
from tack_structures import *
from ssl_cert import *
from tack_cert import *
from keyfile import *
from tests import *


fnames = [\
"numbertheory.py",
"ellipticcurve.py",
"ecdsa.py",
"rijndael.py",
"compat.py",
"cryptomath.py",
"ecdsa_wrappers.py",
"time_funcs.py",
"pem.py",
"struct_parser.py",
"asn1_parser.py",
"constants.py",
"tack_structures.py",
"ssl_cert.py",
"tack_cert.py",
"keyfile.py",
"tests.py",
"main.py"] 


s = open("header.py").read()
for fname in fnames:
    s2 = open(fname).read()
    i = s2.find("################ ")
    assert(i != -1)
    s2 = s2[i:]
    s += s2
print s