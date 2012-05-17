# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import ctypes
from .OpenSSL import openssl as o
from .OpenSSL import bytesToC, cToBytes

BLOCKSIZE = 16

class OpenSSL_AES:
    
    def __init__(self, key, IV):
        if len(key) != 32:
            raise AssertionError()
        if len(IV) != 16:
            raise AssertionError()
        self.cipherType = o.EVP_aes_256_cbc()
        self.key = key
        self.IV = IV 

    def encrypt(self, plaintext):
        return self._transform(plaintext, 1)

    def decrypt(self, ciphertext):
        return self._transform(ciphertext, 0)
                
    def _transform(self, inBytes, encrypt):
        assert(len(inBytes) % BLOCKSIZE == 0)
        ctx = None
        inBuf = bytesToC(inBytes)
        keyBuf = bytesToC(self.key)
        ivBuf = bytesToC(self.IV)
        outBuf = ctypes.create_string_buffer(len(inBytes))
        try:
            # Create the CIPHER_CTX
            ctx = o.EVP_CIPHER_CTX_new()
            o.EVP_CIPHER_CTX_init(ctx)
            o.EVP_CipherInit(ctx, self.cipherType, keyBuf, ivBuf, encrypt)
            o.EVP_CIPHER_CTX_set_padding(ctx, 0)

            # Encrypt or Decrypt
            outLen = ctypes.c_int()
            o.EVP_CipherUpdate(ctx, outBuf, ctypes.byref(outLen), inBuf, len(inBytes))
            assert(outLen.value == len(inBytes))
            outBytes = cToBytes(outBuf)[:len(inBytes)]
        finally:
            o.EVP_CIPHER_CTX_cleanup(ctx)
            o.EVP_CIPHER_CTX_free(ctx)

        # Update the CBC chaining
        if encrypt:
            self.IV = outBytes[-BLOCKSIZE:]
        else:
            self.IV = inBytes[-BLOCKSIZE:]
        return outBytes
