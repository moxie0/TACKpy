import ctypes
from .OpenSSL import openssl as o
from tack.compat import bytesToStr

class OpenSSL_AES:
    def __init__(self, key, IV):
        if len(IV) != 16:
            raise AssertionError()

        self.blockSize = 16
        self.key = key
        self.IV = IV

        if len(key)==16:
            self.name = "aes128"
            self.cipherType = o.EVP_aes_128_cbc()
        elif len(key)==24:
            self.name = "aes192"
            self.cipherType = o.EVP_aes_192_cbc()
        elif len(key)==32:
            self.name = "aes256"
            self.cipherType = o.EVP_aes_256_cbc()            
        else:
            raise AssertionError()

    def encrypt(self, plaintext):
        return self._transform(plaintext, 1)

    def decrypt(self, ciphertext):
        return self._transform(ciphertext, 0)
                
    def _transform(self, inBytes, encrypt):
        assert(len(inBytes) % 16 == 0)
        ctx = None
        inBuf = bytesToStr(inBytes)
        outBuf = ctypes.create_string_buffer(len(inBytes))
        try:
            # Create the CIPHER_CTX
            ctx = o.EVP_CIPHER_CTX_new()
            o.EVP_CIPHER_CTX_init(ctx)
            o.EVP_CipherInit(ctx, self.cipherType, bytesToStr(self.key), bytesToStr(self.IV), encrypt)
            o.EVP_CIPHER_CTX_set_padding(ctx, 0)

            # Encrypt or Decrypt
            outLen = ctypes.c_int()
            o.EVP_CipherUpdate(ctx, outBuf, ctypes.byref(outLen), inBuf, len(inBytes))
            assert(outLen.value == len(inBytes))
            outBytes = bytearray(outBuf[:len(inBytes)])
        finally:
            o.EVP_CIPHER_CTX_cleanup(ctx)
            o.EVP_CIPHER_CTX_free(ctx)

        # Update the CBC chaining
        if encrypt:
            self.IV = outBytes[-self.blockSize:]
        else:
            self.IV = inBytes[-self.blockSize:]
        return outBytes
