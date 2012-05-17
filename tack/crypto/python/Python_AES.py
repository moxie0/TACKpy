# Authors: 
#   Trevor Perrin
#
# See the LICENSE file for legal information regarding use of this file.

from .rijndael import rijndael

BLOCKSIZE = 16

class Python_AES:
    
    def __init__(self, key, IV):
        if len(key) != 32:
            raise AssertionError()
        if len(IV) != 16:
            raise AssertionError()
        self.rijndael = rijndael(key, BLOCKSIZE)
        self.IV = IV

    def encrypt(self, plaintextBytes):
        assert(len(plaintextBytes) % BLOCKSIZE == 0)
        ciphertextBytes = plaintextBytes[:]
        chainBytes = self.IV

        #CBC Mode: For each block...
        for x in range(len(ciphertextBytes)//BLOCKSIZE):

            #XOR with the chaining block
            blockBytes = ciphertextBytes[x*BLOCKSIZE : (x*BLOCKSIZE)+BLOCKSIZE]
            for y in range(BLOCKSIZE):
                blockBytes[y] ^= chainBytes[y]

            #Encrypt it
            encryptedBytes = self.rijndael.encrypt(blockBytes)

            #Overwrite the input with the output
            for y in range(BLOCKSIZE):
                ciphertextBytes[(x*BLOCKSIZE)+y] = encryptedBytes[y]

            #Set the next chaining block
            chainBytes = encryptedBytes

        self.IV = chainBytes
        return ciphertextBytes

    def decrypt(self, ciphertextBytes):
        assert(len(ciphertextBytes) % BLOCKSIZE == 0)
        plaintextBytes = ciphertextBytes[:]
        chainBytes = self.IV

        #CBC Mode: For each block...
        for x in range(len(plaintextBytes)//BLOCKSIZE):

            #Decrypt it
            blockBytes = plaintextBytes[x*BLOCKSIZE : (x*BLOCKSIZE)+BLOCKSIZE]
            decryptedBytes = self.rijndael.decrypt(blockBytes)

            #XOR with the chaining block and overwrite the input with output
            for y in range(BLOCKSIZE):
                decryptedBytes[y] ^= chainBytes[y]
                plaintextBytes[(x*BLOCKSIZE)+y] = decryptedBytes[y]

            #Set the next chaining block
            chainBytes = blockBytes

        self.IV = chainBytes
        return plaintextBytes
