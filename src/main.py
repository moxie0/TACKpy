#! /usr/bin/env python

from numbertheory import *
from ellipticcurve import *
from ecdsa import *
from rijndael import *
from misc import *
from compat import *
from cryptomath import *
from ecdsa_wrappers import *
from time_funcs import *
from pem import *
from struct_parser import *
from asn1 import *
from constants import *
from tack_structures import *
from ssl_cert import *
from tack_cert import *
from keyfile import *

################ MAIN ###

import sys, getpass, getopt

def handleArgs(argv, argString):
    try:
        opts, argv = getopt.getopt(argv, argString)
    except getopt.GetoptError, e:
        printError(e)    
    password = None
    outputFile = sys.stdout
    inTack  = None
    inCert = None
    inKey = None
    keyPem = None # Temporary to load PEM'd key
    outBreak = None
    generation = None
    duration = None
    expiration = None
    sigType = TACK_Sig_Type.v1_cert
    for opt, arg in opts:
        if opt == "-p":
            password = arg
        elif opt == "-o":
            try:
                outputFile = open(arg, "w")
            except IOError:
                printError("Error opening output file: %s" % arg)
        elif opt == "-i":
            try:
                tackPem = open(arg, "r").read()
            except IOError:
                printError("Error opening TACK file: %s" % arg)                        
            try:
                inTack = TACK()
                inTack.parsePem(tackPem)
            except SyntaxError:
                printError("TACK malformed: %s" % arg)
        elif opt == "-c":
            try:
                sslBytes = bytearray(open(arg, "rb").read())
            except IOError:
                printError("Error opening SSL certificate: %s" % arg)            
            inCert = SSL_Cert()
            try:
                inCert.parse(sslBytes)        
            except SyntaxError:
                prinError("SSL certificate malformed: %s" % arg)
        elif opt == "-k":
            try:
                keyPem = open(arg, "r").read()
            except IOError:
                printError("Error opening TACK Secret Key File: %s" % arg)            
        elif opt == "-g":
            try:
                generation = int(arg)
                if generation < 0 or generation>255:
                    raise ValueError()
            except ValueError:
                printError("Bad sig_generation: %s" % arg)            
        elif opt == "-d":
            try:
                duration = parseDurationArg(arg)
            except SyntaxError:
                printError("Bad pin_duration: %s" % arg)       
        elif opt == "-e":
            expiration = parseTimeArg(arg)
        elif opt == "-s":
            if arg == "v1_cert":
                sigType = TACK_Sig_Type.v1_cert
            elif arg == "v1_key":
                sigType = TACK_Sig_Type.v1_key
            else:
                printError("Unknown sig_type: %s" % arg)  
        else:
            assert(False)
    if argv:
        printError("Unknown arguments: %s" % argv)
        
    if keyPem:
        try:
            inKey = TACK_KeyFile()
            if password:
                if not inKey.parsePem(keyPem, password):
                    printError("Bad password")
            else:
                while 1:
                    password = getpass.getpass("Enter password for key file: ")
                    if inKey.parsePem(keyPem, password):
                        break
                    sys.stderr.write("PASSWORD INCORRECT!")
        except SyntaxError:
            printError("Error processing TACK Secret Key File")
        
    retList = []
    if "p:" in argString:
        retList.append(password)
    if "o:" in argString:
        retList.append(outputFile)
    if "i:" in argString:
        retList.append(inTack)
    if "c:" in argString:
        retList.append(inCert)
    if "k:" in argString:
        retList.append(inKey)
    if "g:" in argString:
        retList.append(generation)
    if "d:" in argString:
        retList.append(duration)
    if "e:" in argString:
        if not expiration:
            # round up to next minute
            expiration = int(math.ceil(inCert.notAfter / 60.0))
        retList.append(expiration) 
    if "s:" in argString:
        retList.append(sigType)
        if sigType == TACK_Sig_Type.v1_cert:
            retList.append(inCert.cert_sha256)
        else:
            retList.append(inCert.key_sha256)        
    return retList

def genkeyCmd(argv):
    password, outputFile = handleArgs(argv, "p:o:")    
    kf = TACK_KeyFile()
    kf.generate()
    if not password:
        password, password2 = "this", "that"
        while password != password2:
            password = getpass.getpass("Choose password for key file: ")    
            password2 = getpass.getpass("Re-enter password for key file: ")  
            if password != password2:
                sys.stderr.write("PASSWORDS DON'T MATCH!")      
    outputFile.write(kf.writePem(password))

def newCmd(argv):
    password, outputFile, inCert, inKey, generation, \
    duration, expiration, sigType, hash = \
        handleArgs(argv, "p:o:c:k:g:d:e:s:")
    
    if generation == None:
        generation = 0
    if duration == None:
        duration = 5
        
    tack = TACK()
    tack.new(inKey, sigType, expiration, generation, hash, duration)
    outputFile.write(tack.writePem())
    
def updateCmd(argv):
    password, outputFile, tack, inCert, inKey, generation, \
    duration, expiration, sigType, hash = \
        handleArgs(argv, "p:o:i:c:k:g:d:e:s:")

    if generation == None:
        generation = tack.sig.sig_generation
    if duration == None:
        duration = tack.pin_duration
        
    tack.update(inKey, sigType, expiration, generation, hash, duration)
    outputFile.write(tack.writePem())    

def adjustCmd(argv):
    outputFile, tack, duration, = handleArgs(argv, "o:i:d:")
    tack.pin_duration = duration
    outputFile.write(tack.writePem())    
    
def breakCmd(argv):
    password, outputFile, tack, inKey = \
        handleArgs(argv, "p:o:i:k:")

    breakSig = TACK_Break_Sig()   
    breakSig.generate(tack.pin, inKey.sign(tack.pin.write()))
    outputFile.write(breakSig.writePem())    
     
def viewCmd(argv):
    if len(argv) < 1:
        printError("Missing argument: object to view")
    if len(argv) > 1:
        printError("Can only view one object")
    try:
        b = bytearray(open(argv[0], "rb").read())
    except IOError:
        printError("File not found: %s" % argv[0])
        
    # Is it a TACK SECRET KEY file?
    try:
        kfv = TACK_KeyFileViewer()
        kfv.parse(b)
        print(kfv.writeText())
        return
    except SyntaxError:
        pass
        
    # Is it a TACK BREAK SIG file?
    try:
        t = TACK_Break_Sig()
        t.parsePem(b)
        print(t.writeText())
        return        
    except SyntaxError:
        pass
            
    # Is it a TACK file?
    try:
        t = TACK()
        t.parsePem(b)
        print(t.writeText())
        return        
    except SyntaxError:
        pass
        
    # Is it an SSL certificate?        
    try:
        sslc = SSL_Cert()
        sslc.parse(b)
        print(sslc.writeText())
        return      
    except SyntaxError:
        printError("Unrecognized file type")

def printUsage(s=None):
    if m2cryptoLoaded:
        crypto = "M2Crypto/OpenSSL"
    else:
        crypto = "Python crypto"        
    if s:
        print("ERROR: %s" % s)
    print("""\nTACK-tool version VV.VV.VV (using %s)  

Commands (use "help <command>" to see optional args):
  genkey
  new    -k KEY -c CERT  
  update -k KEY -c CERT -i TACK
  adjust -i TACK -d DURATION
  break  -k KEY -i TACK
  view   FILE
  help   COMMAND
""" % crypto)
    sys.exit(-1)
    
def helpCmd(argv):
    if len(argv) == 0:
        printUsage()
    cmd = argv[0]
    if cmd == "genkey"[:len(cmd)]:
        print( \
"""Creates a new TACK Secret Key file.

  genkey

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")        
    elif cmd == "new"[:len(cmd)]:
        s = posixTimeToStr(time.time())        
        print( \
"""Creates a TACK based on a new pin for the target SSL certificate.
        
  new -k KEY -c CERT
  
  -k KEY             : Use this TACK SecretKey file
  -c CERT            : Sign this SSL certificate

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -g GENERATION      : Use this generation number (0-255)
  -s SIG_TYPE        : Target signature to "v1_key" or "v1_cert"
  -d DURATION        : Use this duration for the pin:
                         ("5m", "30d", "1d12h5m", etc.)
  -e EXPIRATION      : use this UTC time for sig_expiration
                        ("%s", "%sZ",
                         "%sZ", "%sZ" etc.)
                        (or, specify a duration from current time)
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "update"[:len(cmd)]:
        s = posixTimeToStr(time.time())                
        print( \
"""Updates a TACK for the target SSL certificate.

  update -k KEY -c CERT -i TACK
  
  -k KEY             : Use this TACK SecretKey file
  -c CERT            : Sign this SSL certificate
  -i TACK            : Read this TACK file

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -g GENERATION      : Use this generation number (0-255)
  -s SIG_TYPE        : Target signature to "v1_key" or "v1_cert"
  -d DURATION        : Use this duration for the pin:
                         ("5m", "30d", "1d12h5m", etc.)
  -e EXPIRATION      : use this UTC time for sig_expiration
                        ("%s", "%sZ",
                         "%sZ", "%sZ" etc.)
                        (or, specify a duration from current time)
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "break"[:len(cmd)]:
        print( \
"""Creates a break signature based on an input TACK.

  break -k KEY -i TACK 

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")
    elif cmd == "view"[:len(cmd)]:
        print("""Views a TACK certificate, SSL certificate, or Key File.

  view <file>
""")        

    elif cmd == "adjust"[:len(cmd)]:
        print( \
"""Adjusts pin_duration.

  adjust -i TACK -d DURATION
  
  -i TACK            : Update this TACK file
  -d DURATION        : Use this duration for the pin:
                           ("5m", "30d", "1d12h5m", etc.)

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
""")
    else:
        printError("Help requested for unknown command")
        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "test":
        testCert()
        testStructures()
        testKeyFile()
    elif sys.argv[1] == "genkey"[:len(sys.argv[1])]:
        genkeyCmd(sys.argv[2:])
    elif sys.argv[1] == "new"[:len(sys.argv[1])]:
        newCmd(sys.argv[2:])
    elif sys.argv[1] == "update"[:len(sys.argv[1])]:
        updateCmd(sys.argv[2:])
    elif sys.argv[1] == "adjust"[:len(sys.argv[1])]:
        adjustCmd(sys.argv[2:])
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        breakCmd(sys.argv[2:])
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        viewCmd(sys.argv[2:])
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        helpCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])