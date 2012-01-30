from .ecdsa import *
from .cryptomath import *
from .pem import *
from .asn1 import *
from .misc import *
from .m2crypto import *

################ ECDSA_WRAPPERS ###
"""The following three "wrapper" functions are used for working with ECDSA:
  ec256Generate
  ecdsa256Sign
  ecdsa256Verify

These wrapper functions operate on bytearrays:
  privateKey is a bytearray of length 32
  publicKey is a bytearray of length 64
  signature is a bytearray of length 64
  dataToSign/Verify is an arbitrary-length bytearray
  
There are M2Crypto/OpenSSL versions of these functions, as well as 
pure Python versions based on Peter Pearson's code (see the 
NUMBERTHEORY, ELLIPTICCURVE, and ECDSA sections for pure Python).

The M2Crypto/OpenSSL versions are loaded and used if present, otherwise 
the pure Python versions are used.

Because M2Crypto operates on ASN.1-encoded signatures, and traditional OpenSSL
PEM-encoded public and private keys, there is a fair bit of data munging to
convert to/from M2Crypto formats.
"""

import os

def ec256Generate():
    if m2cryptoLoaded:
        return m2crypto_ec256Generate()
    else:
        return python_ec256Generate()

def ecdsa256Sign(privateKey, publicKey, dataToSign):
    if m2cryptoLoaded:
        return m2crypto_ecdsa256Sign(privateKey, publicKey, dataToSign)
    else:
        return python_ecdsa256Sign(privateKey, publicKey, dataToSign) 
        
def ecdsa256Verify(publicKey, dataToVerify, signature):
    if m2cryptoLoaded:
        return m2crypto_ecdsa256Verify(publicKey, dataToVerify, signature)
    else:
        return python_ecdsa256Verify(publicKey, dataToVerify, signature) 
    
if m2cryptoLoaded:

    # Marshal/unmarshal PEM-wrapped ECPrivateKey and ASN.1 Signatures    

    def _parseECPrivateKey(pemPrivKeyBytes):
        """Parse a bytearray containing a PEM-encoded ECPrivatey.
        
        Return a pair of (32-byte bytearray, 64-byte bytearray)
        containing the (privateKey, publicKey)
        """
        b = dePem(pemPrivKeyBytes, "EC PRIVATE KEY")
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
        return (privateKey, publicKey)        
    
    def _writeECPrivateKey(privateKey, publicKey):
        assert(len(privateKey) == 32)
        assert(len(publicKey) == 64)
        bytes1 = a2b_hex("02010104")  
        bytes2 = a2b_hex("a00a06082a8648ce3d030107a14403420004")
        privateKey = toAsn1IntBytes(privateKey)
        b = bytes1 + asn1Length(len(privateKey)) + privateKey + \
            bytes2 + publicKey
        b = bytearray([0x30]) + asn1Length(len(b)) + b
        pemPrivKeyBytes = pem(b, "EC PRIVATE KEY")
        return pemPrivKeyBytes
    
    def _writeECPublicKey(publicKey):
        assert(len(publicKey) == 64)
        bytes1 = a2b_hex(\
            "3059301306072a8648ce3d020106082a8648ce3d03010703420004")  
        asn1KeyBytes = bytes1 + publicKey
        pemPubKeyBytes = pem(asn1KeyBytes, "PUBLIC KEY")
        return pemPubKeyBytes
            
    def _parseECSignature(asn1SigBytes):
        p = ASN1Parser(bytearray(asn1SigBytes))
        r = bytesToNumber(p.getChild(0).value)
        s = bytesToNumber(p.getChild(1).value)
        return numberToBytes(r, 32) + numberToBytes(s, 32)
    
    def _writeECSignature(ecSigBytes):
        assert(len(ecSigBytes) == 64)
        asn1R = toAsn1IntBytes(ecSigBytes[:32])
        asn1S = toAsn1IntBytes(ecSigBytes[32:])
        # Add ASN1 Type=2(int), and Length fields
        asn1R = bytearray([2]) + asn1Length(len(asn1R)) + asn1R         
        asn1S = bytearray([2]) + asn1Length(len(asn1S)) + asn1S 
        # Add ASN1 Type=0x30(Sequence) and Length fields       
        asn1ECSigBytes = bytearray([0x30]) + \
                            asn1Length(len(asn1R+asn1S)) + asn1R + asn1S
        return asn1ECSigBytes

    def m2crypto_ec256Generate():
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
        return (privateKey, publicKey)

    def m2crypto_ecdsa256Sign(privateKey, publicKey, dataToSign):        
        # Write the passed-in private key byte array into PEM form
        # Then create M2Crypto EC object from ASN.1 form        
        pemPrivKeyBytes = _writeECPrivateKey(privateKey, publicKey)
        m2EC = EC.load_key_bio(BIO.MemoryBuffer(pemPrivKeyBytes))

        # Produce ASN.1 signature
        hash = SHA256(dataToSign)
        asn1SigBytes = m2EC.sign_dsa_asn1(hash)
        
        # Convert stupid ASN.1 signature into 64-byte signature
        # Double-check before returning
        sigBytes = _parseECSignature(asn1SigBytes)
        assert(ecdsa256Verify(publicKey, dataToSign, sigBytes))
        return sigBytes 
        
    def m2crypto_ecdsa256Verify(publicKey, dataToVerify, signature):
        # Write the passed-in public key byte array into PEM form
        # Then create M2Crypto EC_pub
        pemPubKeyBytes = _writeECPublicKey(publicKey)        
        m2ECpub = EC.load_pub_key_bio(BIO.MemoryBuffer(pemPubKeyBytes))

        # Convert 64-byte signature into a stupid ASN.1 signature
        asn1SigBytes = _writeECSignature(signature)        
        hash = SHA256(dataToVerify)  
        return m2ECpub.verify_dsa_asn1(hash, asn1SigBytes)


# Always load the python functions, even if m2crypto loaded:

def python_ec256Generate(extraRandBytes=None):
    # ECDSA key generation per FIPS 186-3 B.4.1
    # (except we use 32 extra random bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as any extraRandBytes
    # REVIEW THIS CAREFULLY!  CHANGE AT YOUR PERIL!
    randBytes0 = bytearray(os.urandom(64))
    if extraRandBytes:
        randBytes0 += bytearray(extraRandBytes)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))
    c = bytesToNumber(randBytes) 
    n = generator_256.order()
    d = (c % (n-1))+1        
    privateKey = numberToBytes(d, 32)
    publicKeyPoint = generator_256 * d        
    publicKey = numberToBytes(publicKeyPoint.x(), 32) + \
                numberToBytes(publicKeyPoint.y(), 32)
    return (privateKey, publicKey)

def python_ecdsa256Sign(privateKey, publicKey, dataToSign):
    privateKeyNum = bytesToNumber(privateKey)
    hash = SHA256(dataToSign)
    g = generator_256
    n = g.order()
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))    
    privkey = Private_key(pubkey, privateKeyNum)    

    # Generating random nonce k per FIPS 186-3 B.5.1:
    # (except we use 32 extra bytes instead of 8 before reduction)
    # Random bytes taken from /dev/urandom as well as HMAC(privkey,hash)
    # REVIEW THIS CAREFULLY!!!  CHANGE AT YOUR PERIL!!!
    randBytes0 = bytearray(os.urandom(64))
    randBytes0+= HMAC_SHA256(privateKey, hash)
    randBytes = HMAC_SHA256(randBytes0, bytearray([1]))
    randBytes+= HMAC_SHA256(randBytes0, bytearray([2]))                       
    c = bytesToNumber(randBytes) 
    k = (c % (n-1))+1                
    hashNum = bytesToNumber(hash)
    sig = privkey.sign(hashNum, k)
    signature = numberToBytes(sig.r, 32) + numberToBytes(sig.s, 32)
    # Double-check value before returning
    assert(ecdsa256Verify(publicKey, dataToSign, signature))
    return signature

def python_ecdsa256Verify(publicKey, dataToVerify, signature):
    hashNum = bytesToNumber(SHA256(dataToVerify))
    g = generator_256  
    x = bytesToNumber(publicKey[:32])
    y = bytesToNumber(publicKey[32:])        
    pubkey = Public_key(g, Point(g.curve(), x,y))
    sig = Signature(bytesToNumber(signature[:32]), 
                            bytesToNumber(signature[32:]))
    return pubkey.verifies(hashNum, sig)

def testECDSAWrappers():
    print("Testing ECDSA WRAPPERS")
    privateKey, publicKey = python_ec256Generate()
    data = bytearray([0,1,2,3])
    badData = bytearray([0,1,2,4])
    signature = python_ecdsa256Sign(privateKey, publicKey, data)
    assert(python_ecdsa256Verify(publicKey, data, signature))
    assert(not python_ecdsa256Verify(publicKey, badData, signature)) 
    if m2cryptoLoaded:
        # See if M2Crypto can verify Python sig
        assert(m2crypto_ecdsa256Verify(publicKey, data, signature))
        privateKey, publicKey = m2crypto_ec256Generate()
        signature = m2crypto_ecdsa256Sign(privateKey, publicKey, data)
        assert(m2crypto_ecdsa256Verify(publicKey, data, signature))
        assert(not m2crypto_ecdsa256Verify(publicKey, badData, signature)) 
    return 1
