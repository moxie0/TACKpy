################ TESTS ###


def testStructures():
    pin = TACK_Pin()
    sig = TACK_Sig()
    
    pin.generate(TACK_Pin_Type.v1, 1000000, os.urandom(8), os.urandom(64))

    # Test reading/writing OOC pin
    pin2 = TACK_Pin()
    pin2.parse(pin.write())
    assert(pin.write() == pin2.write())


    # Test reading/writing TACK_Sig
    privKey, pubKey = ec256Generate()
    sig.generate(TACK_Sig_Type.v1_cert,
                 100000, 200000, os.urandom(32), pin,
                 lambda b:ecdsa256Sign(privKey, pubKey, b))
    sig2 = TACK_Sig()
    sig2.parse(sig.write())
    assert(sig.write() == sig2.write())
    #print "\nTACK_Sig:\n", sig2.writeText()

    # Test reading/writing TACK_Break_Sigs with 1 code
    break_sig = TACK_Break_Sig()
    break_sig.pin_label = os.urandom(8)
    break_sig.signature = os.urandom(64)
    break_sig2 = TACK_Break_Sig()
    break_sig2.parse(break_sig.write())
    assert(break_sig.write() == break_sig2.write())
        

def testKeyFile():
    f = TACK_KeyFile()
    f.generate()
    
    b = f.write("abracadabra")
    f2 = TACK_KeyFile()
    assert(f2.parse(b, "abracadabra"))
    assert(f2.__dict__ == f.__dict__)

    f2.generate(bytearray("blablabla"))    
    h = bytearray(range(100,200))
    sig = f2.sign(h)

def testCert():
    sigDays = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()//60) # Get time in minutes
    sigExp = currentTime + (24*60) * sigDays    
    
    sslBytes = bytearray(range(1,200))
    kf = TACK_KeyFile()
    kf.generate()    
        
    pin = TACK_Pin()
    pin.generate(TACK_Pin_Type.v1, 1000000, os.urandom(8), kf.public_key)
        
    privKey, pubKey = ec256Generate()
    sig = TACK_Sig()
    sig.generate(TACK_Sig_Type.v1_cert,
                 sigExp, sigExp+100, 
                 SHA256(sslBytes), pin,
                 lambda b :ecdsa256Sign(privKey,pubKey,b))
                     
    tc = TACK_Cert()
    tc.generate(pin, sig)

    tc2 = TACK_Cert()
    tc2.parse(tc.write())
    assert(tc.write() == tc2.write())
    
