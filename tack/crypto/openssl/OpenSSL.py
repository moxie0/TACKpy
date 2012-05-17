# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import sys
from ctypes import *
from ctypes.util import find_library
from .OpenSSLException import OpenSSLException

def bytesToC(b):
    cbuf = create_string_buffer(bytes(b))
    return cbuf
    
def cToBytes(c):
    return bytearray(c)

class OpenSSL:
    
    def __init__(self):
        self.setInitError("uninitialized")
    
    def initialize(self):
        self.initErrorString = "unknown error loading OpenSSL"
        
        try:            
            if sys.platform == "win32":
                libraryName = find_library("libeay32")
            else:
                libraryName = find_library("crypto")
            if not libraryName:
                self.setInitError("OpenSSL not found")
                return
        except:
            self.setInitError("OpenSSL not found")
            raise
            
        try:
            if sys.platform == "win32":
                self._lib = CDLL(libraryName)
            else:
                self._lib = cdll.LoadLibrary(libraryName)
        except:
            self.setInitError("error loading OpenSSL")
            return
        
        try:
            self.POINT_CONVERSION_UNCOMPRESSED = 4
    
            class ECDSA_SIG(Structure):
                _fields_ = [("r", c_void_p), ("s", c_void_p)]
    
            self._add("SSLeay_version", ret=c_char_p)
            self._add("OBJ_txt2nid")
            self._add("ERR_load_crypto_strings", skipWrap=True)
            self._add("ERR_get_error", ret=c_long, skipWrap=True)
            self._add("ERR_peek_last_error", ret=c_long, skipWrap=True)
            self._add("ERR_error_string", ret=c_char_p, args=[c_long,  c_char_p], skipWrap=True)

            # Handle this specially as it may indicate Red Hat's 
            # OpenSSL without EC
            try:
                self._add("EC_KEY_new_by_curve_name", ret=c_void_p, args=[c_int])
            except:
                self.setInitError("OpenSSL is missing EC functions")
                return
        
            self._add("EC_KEY_free", args=[c_void_p], skipWrap=True)
            self._add("EC_KEY_dup", ret=c_void_p, args=[c_void_p])
            self._add("EC_KEY_generate_key", args=[c_void_p])
            self._add("EC_KEY_get0_public_key", ret=c_void_p, args=[c_void_p])
            self._add("EC_KEY_set_public_key", args=[c_void_p, c_void_p])
            self._add("EC_KEY_get0_private_key", ret=c_void_p, args=[c_void_p])
            self._add("EC_KEY_set_private_key", args=[c_void_p, c_void_p])
            self._add("EC_GROUP_new_by_curve_name", ret=c_void_p, args=[c_int])
            self._add("EC_GROUP_free", args=[c_void_p], skipWrap=True)
            self._add("EC_POINT_new", ret=c_void_p, args=[c_void_p])
            self._add("EC_POINT_free", args=[c_void_p], skipWrap=True)
            self._add("EC_POINT_oct2point", args=[c_void_p, c_void_p, c_void_p, c_size_t, c_void_p])
            self._add("EC_POINT_point2oct", args=[c_void_p, c_void_p, c_int, c_void_p, c_int, c_void_p] )
            self._add("ECDSA_do_sign", ret=POINTER(ECDSA_SIG), args=[c_void_p, c_int, c_void_p])
            self._add("ECDSA_do_verify", args=[c_void_p, c_int, POINTER(ECDSA_SIG), c_void_p], skipWrap=True)
            self._add("ECDSA_SIG_new", ret=POINTER(ECDSA_SIG))
            self._add("ECDSA_SIG_free", args=[c_void_p], skipWrap=True)
            self._add("BN_new", ret=c_void_p)
            self._add("BN_free", args=[c_void_p], skipWrap=True)
            self._add("BN_bn2bin", args=[c_void_p, c_void_p])
            self._add("BN_bin2bn", args=[c_void_p, c_int, c_void_p])
    
            self._add("EVP_CIPHER_CTX_new", ret=c_void_p)
            self._add("EVP_CIPHER_CTX_init", args=[c_void_p])
            self._add("EVP_CIPHER_CTX_cleanup", args=[c_void_p])        
            self._add("EVP_CIPHER_CTX_free", args=[c_void_p], skipWrap=True)
            self._add("EVP_CIPHER_CTX_set_padding", args=[c_void_p, c_int])        
            self._add("EVP_aes_128_cbc", ret=c_void_p)
            self._add("EVP_aes_192_cbc", ret=c_void_p)
            self._add("EVP_aes_256_cbc", ret=c_void_p)
            self._add("EVP_CipherInit", args=[c_void_p, c_void_p, c_void_p, c_void_p, c_int])
            self._add("EVP_CipherUpdate", args=[c_void_p, c_void_p, c_void_p, c_void_p, c_int])
            
            self.ERR_load_crypto_strings()
            self.enabled = True
        except:
            self.enabled = False
            # raise
            
                       
    def _add(self, name, ret=None, args=None, skipWrap=False):
        try:
            func = getattr(self._lib, name)
        except:
            self.setInitError("error loading OpenSSL:%s" % name)
            raise
            
        if ret:
            func.restype = ret
        if args:
            func.argtypes = args
        
        if skipWrap:
            setattr(self, name, func)
        else:
            def wrappedFunc(*a):
                retval = func(*a)
                if not retval:
                    errNum = self.ERR_peek_last_error()
                    errBuf = create_string_buffer(1024)
                    errStr = self.ERR_error_string(errNum, errBuf)
                    raise OpenSSLException(errStr)
                return retval            
            setattr(self, name, wrappedFunc)

    def setInitError(self, s):
        self.enabled = False
        self.initErrorString = s
        
# Singleton, initialize() this once then use it
openssl = OpenSSL()
        
        
        
        