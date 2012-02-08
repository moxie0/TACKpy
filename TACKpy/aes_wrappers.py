# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from .cryptomath import *
from .compat import *
from .m2crypto import *
from .rijndael import rijndael

################ AES WRAPPERS ###

class AES:
    def __init__(self, key, IV, implementation):
        if len(key) not in (16, 24, 32):
            raise AssertionError()
        if len(IV) != 16:
            raise AssertionError()
        self.isBlockCipher = True
        self.block_size = 16
        self.implementation = implementation
        if len(key)==16:
            self.name = "aes128"
        elif len(key)==24:
            self.name = "aes192"
        elif len(key)==32:
            self.name = "aes256"
        else:
            raise AssertionError()

    #CBC-Mode encryption, returns ciphertext
    #WARNING: *MAY* modify the input as well
    def encrypt(self, plaintext):
        assert(len(plaintext) % 16 == 0)

    #CBC-Mode decryption, returns plaintext
    #WARNING: *MAY* modify the input as well
    def decrypt(self, ciphertext):
        assert(len(ciphertext) % 16 == 0)

def createAES(key, IV):
    if m2cryptoLoaded:
        return OpenSSL_AES(key, IV)
    else:
        return Python_AES(key, IV)

"""OpenSSL/M2Crypto AES implementation."""
if m2cryptoLoaded:

    class OpenSSL_AES(AES):

        def __init__(self, key, IV):
            AES.__init__(self, key, IV, "openssl")
            self.key = key
            self.IV = IV

        def _createContext(self, encrypt):
            context = m2.cipher_ctx_new()
            if len(self.key)==16:
                cipherType = m2.aes_128_cbc()
            if len(self.key)==24:
                cipherType = m2.aes_192_cbc()
            if len(self.key)==32:
                cipherType = m2.aes_256_cbc()
            m2.cipher_init(context, cipherType, self.key, self.IV, encrypt)
            return context

        def encrypt(self, plaintext):
            AES.encrypt(self, plaintext)
            context = self._createContext(1)
            ciphertext = m2.cipher_update(context, plaintext)
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(ciphertext)

        def decrypt(self, ciphertext):
            AES.decrypt(self, ciphertext)
            context = self._createContext(0)
            #I think M2Crypto has a bug - it fails to decrypt and return the last block passed in.
            #To work around this, we append sixteen zeros to the string, below:
            plaintext = m2.cipher_update(context, ciphertext+('\0'*16))

            #If this bug is ever fixed, then plaintext will end up having a garbage
            #plaintext block on the end.  That's okay - the below code will discard it.
            plaintext = plaintext[:len(ciphertext)]
            m2.cipher_ctx_free(context)
            self.IV = ciphertext[-self.block_size:]
            return bytearray(plaintext)
                        
"""Pure-Python AES implementation."""

class Python_AES(AES):
    def __init__(self, key, IV):
        AES.__init__(self, key, IV, "python")
        self.rijndael = rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintextBytes):
        AES.encrypt(self, plaintextBytes)
        ciphertextBytes = plaintextBytes[:]
        chainBytes = self.IV

        #CBC Mode: For each block...
        for x in range(len(ciphertextBytes)//16):

            #XOR with the chaining block
            blockBytes = ciphertextBytes[x*16 : (x*16)+16]
            for y in range(16):
                blockBytes[y] ^= chainBytes[y]

            #Encrypt it
            encryptedBytes = self.rijndael.encrypt(blockBytes)

            #Overwrite the input with the output
            for y in range(16):
                ciphertextBytes[(x*16)+y] = encryptedBytes[y]

            #Set the next chaining block
            chainBytes = encryptedBytes

        self.IV = chainBytes
        return ciphertextBytes

    def decrypt(self, ciphertextBytes):
        AES.decrypt(self, ciphertextBytes)
        plaintextBytes = ciphertextBytes[:]
        chainBytes = self.IV

        #CBC Mode: For each block...
        for x in range(len(plaintextBytes)//16):

            #Decrypt it
            blockBytes = plaintextBytes[x*16 : (x*16)+16]
            decryptedBytes = self.rijndael.decrypt(blockBytes)

            #XOR with the chaining block and overwrite the input with output
            for y in range(16):
                decryptedBytes[y] ^= chainBytes[y]
                plaintextBytes[(x*16)+y] = decryptedBytes[y]

            #Set the next chaining block
            chainBytes = blockBytes

        self.IV = chainBytes
        return plaintextBytes

def testAES():
    print("Testing AES WRAPPERS")    
    key = a2b_hex("c286696d887c9aa0611bbb3e2025a45a")
    IV = a2b_hex("562e17996d093d28ddb3ba695a2e6f58")
    plaintext = a2b_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    ciphertext = a2b_hex("d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1")
    assert(isinstance(Python_AES(key, IV).encrypt(plaintext), bytearray))
    assert(isinstance(Python_AES(key, IV).decrypt(ciphertext), bytearray))
    assert(Python_AES(key, IV).encrypt(plaintext) == ciphertext)
    assert(Python_AES(key, IV).decrypt(ciphertext) == plaintext)
    if m2cryptoLoaded:    
        assert(isinstance(OpenSSL_AES(key, IV).encrypt(plaintext), bytearray))
        assert(isinstance(OpenSSL_AES(key, IV).decrypt(ciphertext), bytearray))        
        assert(OpenSSL_AES(key, IV).encrypt(plaintext) == ciphertext)
        assert(OpenSSL_AES(key, IV).decrypt(ciphertext) == plaintext)
    assert(createAES(key, IV).encrypt(plaintext) == ciphertext) 
    return 1   