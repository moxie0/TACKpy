"""
File format:

  version        1  byte = 0x01
  iter_count     4 bytes = uint32, bigendian
  salt          16 bytes
  EC privkey    32 bytes  } aes256-cbc(IV=0)  } hmac-sha256
  EC pubkey     64 bytes                      } hmac-sha256
  HMAC          32 bytes

  Total		    149

The AES256-CBC and HMAC-SHA256 steps require independent
32-byte keys (encKey and authKey, respectively).

These keys are derived from a 32-byte masterKey.  The masterKey is
derived from a password via PBKDF2-HMAC-SHA26:

  masterKey = PBKDF2-HMAC-SHA256(password, salt, iter_count)
  encKey = HMAC-SHA256(masterKey, 0x01)
  authKey = HMAC-SHA256(masterKey, 0x02)
"""
import os
from tack.InvalidPasswordException import InvalidPasswordException
from tack.crypto.ECGenerator import ECGenerator
from tack.crypto.ECPrivateKey import ECPrivateKey
from tack.crypto.ECPublicKey import ECPublicKey
from tack.crypto.PBKDF2 import PBKDF2
from tack.crypto.AES import AES
from tack.crypto.Digest import Digest
from tack.tls.TlsStructure import TlsStructure
from tack.tls.TlsStructureWriter import TlsStructureWriter
from tack.util.Util import Util
from tack.util.PEMDecoder import PEMDecoder
from tack.util.PEMEncoder import PEMEncoder

class TackKeyFile(TlsStructure):
    LENGTH = 149 # length of keyfile in bytes

    def __init__(self, data=None, password=None):
        TlsStructure.__init__(self, data)
        if data is not None:
            self.version = self.getInt(1)

            if self.version != 1:
                raise SyntaxError("Bad version in Secret File")

            self.password    = password
            self.iter_count  = self.getInt(4)
            self.salt        = self.getBytes(16)
            self.ciphertext  = self.getBytes(32)
            self.public_key  = ECPublicKey(self.getBytes(64))
            self.mac         = bytearray(self.getBytes(32))

            if self.password is not None:
                rawPrivateKey = self._decryptKey(password, self.salt, self.ciphertext,
                                                 self.iter_count, self.public_key, self.mac)
                self.private_key = ECPrivateKey(rawPrivateKey, self.public_key.getRawKey())

    @classmethod
    def createRandom(cls, password):
        tackKeyFile            = cls()
        tackKeyFile.password   = password
        tackKeyFile.version    = 1
        tackKeyFile.iter_count = 8192
        tackKeyFile.salt       = bytearray(os.urandom(16))
        tackKeyFile.public_key, tackKeyFile.private_key = ECGenerator().generateECKeyPair()
        tackKeyFile.ciphertext, tackKeyFile.mac         = tackKeyFile._encryptKey(password, tackKeyFile.salt,
                                                                                  tackKeyFile.iter_count,
                                                                                  tackKeyFile.public_key,
                                                                                  tackKeyFile.private_key)
        return tackKeyFile

    @classmethod
    def createFromPem(cls, pem, password):
        return cls(PEMDecoder(pem).getDecoded("TACK PRIVATE KEY"), password)

    def getPublicKey(self):
        return self.public_key

    def getPrivateKey(self):
        return self.private_key

    def serialize(self):
        w = TlsStructureWriter(TackKeyFile.LENGTH)
        w.add(self.version, 1)
        w.add(self.iter_count, 4)
        w.add(self.salt, 16)
        w.add(self.ciphertext, 32)
        w.add(self.public_key.getRawKey(), 64)
        w.add(self.mac, 32)
        assert(w.index == len(w.bytes)) # did we fill entire bytearray?

        return w.getBytes()

    def serializeAsPem(self):
        return PEMEncoder(self.serialize()).getEncoded("TACK PRIVATE KEY")

    def _encryptKey(self, password, salt, iter_count, public_key, private_key):
        encKey, authKey = self._deriveKeys(password, salt, iter_count)
        ciphertext      = AES(encKey, bytearray(16)).encrypt(private_key.getRawKey())
        macData         = ciphertext + public_key.getRawKey()
        mac             = Digest.HMAC_SHA256(authKey, macData)
        return ciphertext, mac


    def _decryptKey(self, password, salt, ciphertext, iter_count, public_key, mac):
        encKey, authKey = self._deriveKeys(password, salt, iter_count)
        macData         = ciphertext + public_key.getRawKey()
        calcMac         = Digest.HMAC_SHA256(authKey, macData)

        if not Util.constTimeCompare(calcMac, mac):
            raise InvalidPasswordException("Bad password")

        return AES(encKey, bytearray(16)).decrypt(ciphertext)

    # Uses PBKDF2, then HMAC-SHA256 as PRF to derive independent 32-byte keys
    def _deriveKeys(self, password, salt, iter_count):
        assert(iter_count>0)
        masterKey = PBKDF2.hmac_sha256(password, salt, iter_count)
        encKey    = Digest.HMAC_SHA256(masterKey, bytearray([1]))
        authKey   = Digest.HMAC_SHA256(masterKey, bytearray([2]))
        return encKey, authKey

    def __str__(self):
        return """TACK ID        = %s\n""" % str(self.public_key)

