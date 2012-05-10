"""The following three "wrapper" functions are used for working with ECDSA:
  ec256Generate
  ecdsa256Sign
  ecdsa256Verify

These wrapper functions operate on bytearrays:
  privateKey is a bytearray of length 32
  publicKey is a bytearray of length 64
  signature is a bytearray of length 64
  dataToSign/Verify is an arbitrary-length bytearray

Because M2Crypto operates on ASN.1-encoded signatures, and traditional OpenSSL
PEM-encoded public and private keys, there is a fair bit of data munging to
convert to/from M2Crypto formats.
"""
from M2Crypto import EC, BIO
import math
from tack.asn1.ASN1Object import ASN1Object
from tack.crypto.ASN1 import ASN1Parser, fromAsn1IntBytes, toAsn1IntBytes, asn1Length
from tack.crypto.Digest import Digest
from tack.util.PEMDecoder import PEMDecoder
from tack.util.PEMEncoder import PEMEncoder
from tack.compat import a2b_hex

def ec256Generate():
    # Generate M2Crypto.EC.EC object
    m2EC = EC.gen_params(EC.NID_X9_62_prime256v1)
    m2EC.gen_key()

    # Get the ASN.1 ECPrivateKey for the object
    m2Bio = BIO.MemoryBuffer()
    m2EC.save_key_bio(m2Bio, cipher=None)
    pemPrivKeyBytes = m2Bio.getvalue()

    # Parse the ASN.1 ECPrivateKey into byte arrays
    # for the 32-byte priv key, and 64-byte pub key
    (privateKey, publicKey) = _parseECPrivateKey(pemPrivKeyBytes)
    return privateKey, publicKey

def ecdsa256Sign(privateKey, publicKey, dataToSign):
    # Write the passed-in private key byte array into PEM form
    # Then create M2Crypto EC object from ASN.1 form
    pemPrivKeyBytes = _writeECPrivateKey(privateKey, publicKey)
    m2EC = EC.load_key_bio(BIO.MemoryBuffer(pemPrivKeyBytes))

    # Produce ASN.1 signature
    hash = Digest.SHA256(dataToSign)
    asn1SigBytes = m2EC.sign_dsa_asn1(hash)

    # Convert stupid ASN.1 signature into 64-byte signature
    # Double-check before returning
    sigBytes = _parseECSignature(asn1SigBytes)
    assert(ecdsa256Verify(publicKey, dataToSign, sigBytes))
    return sigBytes

def ecdsa256Verify(publicKey, dataToVerify, signature):
    # Write the passed-in public key byte array into PEM form
    # Then create M2Crypto EC_pub
    pemPubKeyBytes = _writeECPublicKey(publicKey)
    m2ECpub = EC.load_pub_key_bio(BIO.MemoryBuffer(pemPubKeyBytes))

    # Convert 64-byte signature into a stupid ASN.1 signature
    asn1SigBytes = _writeECSignature(signature)
    hash = Digest.SHA256(dataToVerify)
    return m2ECpub.verify_dsa_asn1(hash, asn1SigBytes)

# Marshal/unmarshal PEM-wrapped ECPrivateKey and ASN.1 Signatures
def _parseECPrivateKey(pemPrivKeyBytes):
    """Parse a bytearray containing a PEM-encoded ECPrivatey.

    Return a pair of (32-byte bytearray, 64-byte bytearray)
    containing the (privateKey, publicKey)
    """
    b = PEMDecoder(pemPrivKeyBytes).getDecoded("EC PRIVATE KEY")
    p = ASN1Parser(b)
    # The private key is stored as an ASN.1 integer which may
    # need to have zero padding removed (if 33 bytes) or added
    # (if < 32 bytes):
    privateKey = p.getChild(1).value
    privateKey = fromAsn1IntBytes(privateKey, 32)
    # There is a 00 04 byte prior to the 64-byte public key
    # I'm not sure why M2Crypto has the 00 byte there?,
    # some ASN1 thing - the 04 byte signals "uncompressed"
    # per SECG.  Anyways, strip both those bytes off ([2:])
    publicKey = p.getChild(3).getTagged().value[2:]
    assert(len(privateKey) == 32)
    assert(len(publicKey) == 64)
    return privateKey, publicKey

def _writeECPrivateKey(privateKey, publicKey):
    assert(len(privateKey) == 32)
    assert(len(publicKey) == 64)
    bytes1 = a2b_hex("02010104")
    bytes2 = a2b_hex("a00a06082a8648ce3d030107a14403420004")
    privateKey = toAsn1IntBytes(privateKey)
    b = bytes1 + asn1Length(len(privateKey)) + privateKey +\
        bytes2 + publicKey
    b = bytearray([0x30]) + asn1Length(len(b)) + b
    pemPrivKeyBytes = PEMEncoder(b).getEncoded("EC PRIVATE KEY")
    #        pemPrivKeyBytes = pem(b, "EC PRIVATE KEY")
    return pemPrivKeyBytes

def _writeECPublicKey(publicKey):
    assert(len(publicKey) == 64)
    bytes1 = a2b_hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
    asn1KeyBytes = bytes1 + publicKey
    pemPubKeyBytes = PEMEncoder(asn1KeyBytes).getEncoded("PUBLIC KEY")
    #        pemPubKeyBytes = pem(asn1KeyBytes, "PUBLIC KEY")
    return pemPubKeyBytes

def _parseECSignature(asn1SigBytes):
    p = ASN1Parser(bytearray(asn1SigBytes))
    r = _bytesToNumber(p.getChild(0).value)
    s = _bytesToNumber(p.getChild(1).value)
    return _numberToBytes(r, 32) + _numberToBytes(s, 32)

def _writeECSignature(ecSigBytes):
    assert(len(ecSigBytes) == 64)
    asn1R = toAsn1IntBytes(ecSigBytes[:32])
    asn1S = toAsn1IntBytes(ecSigBytes[32:])
    # Add ASN1 Type=2(int), and Length fields
    asn1R = bytearray([2]) + asn1Length(len(asn1R)) + asn1R
    asn1S = bytearray([2]) + asn1Length(len(asn1S)) + asn1S
    # Add ASN1 Type=0x30(Sequence) and Length fields
    asn1ECSigBytes = bytearray([0x30]) +\
                     asn1Length(len(asn1R+asn1S)) + asn1R + asn1S
    return asn1ECSigBytes

def _bytesToNumber(bytes):
    "Convert a sequence of bytes (eg bytearray) into integer."
    total = 0
    multiplier = 1
    for count in range(len(bytes)-1, -1, -1):
        byte = bytes[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def _numberToBytes(n, howManyBytes=None):
    """Convert an integer into a bytearray, zero-pad to howManyBytes.

    The returned bytearray may be smaller than howManyBytes, but will
    not be larger.  The returned bytearray will contain a big-endian
    encoding of the input integer (n).
    """
    if not howManyBytes:
        howManyBytes = _numBytes(n)
    bytes = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        bytes[count] = int(n % 256)
        n >>= 8
    return bytes

def _numBytes(n):
    "Return the number of bytes needed to represent the integer n."
    if n==0:
        return 0
    bits = _numBits(n)
    return int(math.ceil(bits / 8.0))

def _numBits(n):
    "Return the number of bits needed to represent the integer n."
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) +\
           {'0':0, '1':1, '2':2, '3':2,
            '4':3, '5':3, '6':3, '7':3,
            '8':4, '9':4, 'a':4, 'b':4,
            'c':4, 'd':4, 'e':4, 'f':4,
            }[s[0]]
