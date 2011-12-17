################ CRYPTOMATH ###

import math, hashlib, hmac

def bytesToNumber(bytes):
    total = 0
    multiplier = 1
    for count in range(len(bytes)-1, -1, -1):
        byte = bytes[count]
        total += multiplier * byte
        multiplier *= 256
    return total

def numberToBytes(n, howManyBytes=None):
    if not howManyBytes:
        howManyBytes = numBytes(n)
    bytes = bytearray(howManyBytes)
    for count in range(howManyBytes-1, -1, -1):
        bytes[count] = int(n % 256)
        n >>= 8
    return bytes
    
def stringToNumber(s):
    return bytesToNumber(bytearray(s))
    
def numBits(n):
    if n==0:
        return 0
    s = "%x" % n
    return ((len(s)-1)*4) + \
    {'0':0, '1':1, '2':2, '3':2,
     '4':3, '5':3, '6':3, '7':3,
     '8':4, '9':4, 'a':4, 'b':4,
     'c':4, 'd':4, 'e':4, 'f':4,
     }[s[0]]
    
def numBytes(n):
    if n==0:
        return 0
    bits = numBits(n)
    return int(math.ceil(bits / 8.0))

def SHA256(b):
    return bytearray(hashlib.sha256(b).digest())

def HMAC_SHA256(k, b):
    return bytearray(hmac.new(bytes(k), bytes(b), hashlib.sha256).digest())

def constTimeCompare(a, b):
    if len(a) != len(b):
        return False
    result = 0
    for x in range(len(a)):
        result |= a[x]^b[x]
    if result:
        return False
    return True

