
from ctypes import *
from ctypes.util import find_library

class OpenSSL:
    
    def initialize(self):
        libraryName = find_library("crypto")
        self._lib = cdll.LoadLibrary(libraryName)
        
        self.POINT_CONVERSION_UNCOMPRESSED = 4
        
        class ECDSA_SIG(Structure):
            _fields_ = [("r", c_void_p), ("s", c_void_p)]
        
        self._add("SSLeay_version", ret=c_char_p)
        self._add("OBJ_txt2nid", args=[c_char_p])
        self._add("EC_KEY_new_by_curve_name", ret=c_void_p, args=[c_int])
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
        self._add("EC_POINT_oct2point", args=[c_void_p, c_void_p, c_void_p, c_int, c_void_p])
        self._add("EC_POINT_point2oct", args=[c_void_p, c_void_p, c_int, c_void_p, c_int, c_void_p] )
        self._add("ECDSA_do_sign", ret=POINTER(ECDSA_SIG), args=[c_void_p, c_int, c_void_p])
        self._add("ECDSA_do_verify", args=[c_void_p, c_int, POINTER(ECDSA_SIG), c_void_p], skipWrap=True)
        self._add("ECDSA_SIG_new", ret=POINTER(ECDSA_SIG))
        self._add("ECDSA_SIG_free", args=[c_void_p], skipWrap=True)
        self._add("BN_new", ret=c_void_p)
        self._add("BN_free", args=[c_void_p], skipWrap=True)
        self._add("BN_bn2bin", args=[c_void_p, c_void_p])
        self._add("BN_bin2bn", args=[c_void_p, c_int, c_void_p])

    def _add(self, name, ret=None, args=None, skipWrap=False):
        func = getattr(self._lib, name)
        if ret:
            func.restype = ret
        if args:
            func.argtypes = args
        
        if skipWrap:
            setattr(self, name, func)
        else:
            def wrappedFunc(*a):
                retval = func(*a)
                assert(retval)
                return retval            
            setattr(self, name, wrappedFunc)

# Singleton, initialize() this once then use it
openssl = OpenSSL()
        
        
        
        