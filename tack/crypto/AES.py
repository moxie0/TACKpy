from M2Crypto import m2

class AES:
    def __init__(self, key, IV):
        if len(key) not in (16, 24, 32):
            raise AssertionError()

        if len(IV) != 16:
            raise AssertionError()

        self.isBlockCipher = True
        self.block_size = 16
        self.key = key
        self.IV = IV

        if len(key)==16:
            self.name = "aes128"
        elif len(key)==24:
            self.name = "aes192"
        elif len(key)==32:
            self.name = "aes256"
        else:
            raise AssertionError()

    def encrypt(self, plaintext):
        assert(len(plaintext) % 16 == 0)
        context = self._createContext(1)
        ciphertext = m2.cipher_update(context, plaintext)
        m2.cipher_ctx_free(context)
        self.IV = ciphertext[-self.block_size:]
        return bytearray(ciphertext)

    def decrypt(self, ciphertext):
        assert(len(ciphertext) % 16 == 0)
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

    def _createContext(self, encrypt):
        context = m2.cipher_ctx_new()
        if len(self.key)==16:
            cipherType = m2.aes_128_cbc()
        elif len(self.key)==24:
            cipherType = m2.aes_192_cbc()
        elif len(self.key)==32:
            cipherType = m2.aes_256_cbc()
        else:
            raise AssertionError("Key is bad size: %s" % len(self.key))

        m2.cipher_init(context, cipherType, self.key, self.IV, encrypt)
        return context