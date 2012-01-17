from ecdsa import *
from cryptomath import *
from pem import *
from asn1 import *
from misc import *

################ ECDSA_WRAPPERS ###

import os

try:
    from M2Crypto import EC, BIO
    m2cryptoLoaded = True

except ImportError:
    m2cryptoLoaded = False
    
if m2cryptoLoaded:
    from M2Crypto import EC

    # Marshal/unmarshal PEM-wrapped ECPrivateKey and ASN.1 Signatures    

    def _parseECPrivateKey(pemPrivKeyBytes):
        """Parse a bytearray containing a PEM-encoded ECPrivatey.
        
        Return a pair of (32-byte bytearray, 64-byte bytearray)
        containing the (privateKey, publicKey)
        """
        b = dePem(pemPrivKeyBytes, "EC PRIVATE KEY")
        p = ASN1Parser(b)
        privateKey = p.getChild(1).value
        # There is a 00 04 byte prior to the 64-byte public key
        # I'm not sure why M2Crypto has the 00 byte there?,
        # some ASN1 thing - the 04 byte signals "uncompressed"
        # per SECG.  Anyways, strip both those bytes off ([2:])
        publicKey = p.getChild(3).getTagged().value[2:]
        return (privateKey, publicKey)        
    
    def _writeECPrivateKey(privateKey, publicKey):
        bytes1 = a2b_hex("30770201010420")  
        bytes2 = a2b_hex("a00a06082a8648ce3d030107a14403420004")
        asn1KeyBytes = bytes1 + privateKey + bytes2 + publicKey
        pemPrivKeyBytes = pem(asn1KeyBytes, "EC PRIVATE KEY")
        return pemPrivKeyBytes
    
    def _writeECPublicKey(publicKey):
        bytes1 = a2b_hex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")  
        asn1KeyBytes = bytes1 + publicKey
        pemPubKeyBytes = pem(asn1KeyBytes, "PUBLIC KEY")
        return pemPubKeyBytes
            
    def _parseECSignature(asn1SigBytes):
        p = ASN1Parser(bytearray(asn1SigBytes))
        r = bytesToNumber(p.getChild(0).value)
        s = bytesToNumber(p.getChild(1).value)
        return numberToBytes(r, 32) + numberToBytes(s, 32)
    
    def _writeECSignature(ecSigBytes):
        r = bytesToNumber(ecSigBytes[:32])
        s = bytesToNumber(ecSigBytes[32:])
        asn1R = asn1Int(r)
        asn1S = asn1Int(s)
        asn1ECSigBytes = bytearray([0x30]) + \
                            asn1Length(len(asn1R+asn1S)) + asn1R + asn1S
        return asn1ECSigBytes

    def ec256Generate(extraRandBytes=None):
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

    def ecdsa256Sign(privateKey, publicKey, dataToSign):        
        # Write the passed-in private key byte array into PEM form
        # Then create M2Crypto EC object from ASN.1 form        
        pemPrivKeyBytes = _writeECPrivateKey(privateKey, publicKey)
        m2EC = EC.load_key_bio(BIO.MemoryBuffer(pemPrivKeyBytes))

        # Produce ASN.1 signature
        hash = SHA256(dataToSign)
        asn1SigBytes = m2EC.sign_dsa_asn1(hash)
        
        # Convert stupid ASN.1 signature into sensible 64-byte signature
        # Double-check before returning
        sigBytes = _parseECSignature(asn1SigBytes)
        assert(ecdsa256Verify(publicKey, dataToSign, sigBytes))
        return sigBytes 
        
    def ecdsa256Verify(publicKey, dataToVerify, signature):
        # Write the passed-in public key byte array into PEM form
        # Then create M2Crypto EC_pub
        pemPubKeyBytes = _writeECPublicKey(publicKey)        
        m2ECpub = EC.load_pub_key_bio(BIO.MemoryBuffer(pemPubKeyBytes))

        # Convert the sensible signature into a stupid 64-byte signature
        asn1SigBytes = _writeECSignature(signature)        
        hash = SHA256(dataToVerify)  
        return m2ECpub.verify_dsa_asn1(hash, asn1SigBytes)

else:

    def ec256Generate(extraRandBytes=None):
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

    def ecdsa256Sign(privateKey, publicKey, dataToSign):
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

    def ecdsa256Verify(publicKey, dataToVerify, signature):
        hashNum = bytesToNumber(SHA256(dataToVerify))
        g = generator_256  
        x = bytesToNumber(publicKey[:32])
        y = bytesToNumber(publicKey[32:])        
        pubkey = Public_key(g, Point(g.curve(), x,y))
        sig = Signature(bytesToNumber(signature[:32]), 
                                bytesToNumber(signature[32:]))
        return pubkey.verifies(hashNum, sig)

