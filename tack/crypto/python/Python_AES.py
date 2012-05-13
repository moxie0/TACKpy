
from .rijndael import rijndael

class Python_AES:
    def __init__(self, key, IV):
        self.rijndael = rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintextBytes):
        assert(len(plaintextBytes) % 16 == 0)
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
        assert(len(ciphertextBytes) % 16 == 0)
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
