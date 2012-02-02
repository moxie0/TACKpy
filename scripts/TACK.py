#! /usr/bin/env python

from TACKpy import TACK, TACK_Break_Sig, TACK_Cert, \
    TACK_KeyFile, TACK_KeyFileViewer, \
    SSL_Cert, __version__, \
    m2cryptoLoaded, TACK_Pin_Type, TACK_Sig_Type, \
    posixTimeToStr, selfTest, pemSniff, \
    parseDurationArg, parseTimeArg

################ MAIN ###

import time, math, sys, getpass, getopt

def printError(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)

def handleArgs(argv, argString, mandatoryString=""):
    """Helper function for handling cmdline args.

argv should be sys.argv[2:], i.e. the cmdline args minus "TACK <cmd>".
argString is a string with each char indicating a supported arg.
mandatoryString is a string with each char indicating a mandatory arg.

Allowed chars in argString: "poickgdesb"
Allowed chars in mandatoryString: "ickd"

Returns a list populated with an entry (or entries) for each char in 
argString.  The list is populated in "poickgdes" order, regardless of 
argString order.

Even if a char is not used as an argument, it will still return a value, 
usually None.  Note that the caller has to be careful to unpack the return 
values in the correct order.
"""
    # Convert to getopt argstring format:
    # Add ":" after each arg, ie "abc" -> "a:b:c:"
    getOptArgString = ":".join(argString) + ":"
    try:
        opts, argv = getopt.getopt(argv, getOptArgString)
    except getopt.GetoptError as e:
        printError(e) 
    # Default values if arg not present   
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
    breakSigs = None
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
                tackPem = open(arg, "rU").read()
            except IOError:
                printError("Error opening TACK file: %s" % arg)                        
            try:
                inTack = TACK()
                inTack.parsePem(tackPem)
            except SyntaxError:
                printError("TACK malformed: %s" % arg)
        elif opt == "-c":
            try:
                inCert = SSL_Cert()
                inCert.open(arg)
            except SyntaxError:
                printError("SSL certificate malformed: %s" % arg)
            except IOError:
                printError("Error opening SSL certificate: %s" % arg)                
        elif opt == "-k":
            try:
                keyPem = open(arg, "rU").read()
            except IOError:
                printError("Error opening TACK Secret Key File: %s" % arg)            
        elif opt == "-g":
            try:
                generation = int(arg) # Could raise ValueError
                if generation < 0 or generation>255:
                    raise ValueError()
            except ValueError:
                printError("Bad generation: %s" % arg)            
        elif opt == "-d":
            try:
                duration = parseDurationArg(arg)
            except SyntaxError:
                printError("Bad duration: %s" % arg)       
        elif opt == "-e":
            # parseTimeArg will error and exit if arg is malformed
            try:
                expiration = parseTimeArg(arg)
            except SyntaxError as e:
                printError(e)
        elif opt == "-s":
            if arg == "v1_cert":
                sigType = TACK_Sig_Type.v1_cert
            elif arg == "v1_key":
                sigType = TACK_Sig_Type.v1_key
            else:
                printError("Unknown sig.type: %s" % arg)
        elif opt == "-b":
            try:
                breakSigsPem = open(arg, "rU").read()
            except IOError:
                printError("Error opening Break Sigs file: %s" % arg)                        
            try:
                breakSigs = TACK_Break_Sig.parsePemList(breakSigsPem)
            except SyntaxError:
                printError("Break Sigs malformed: %s" % arg)              
        else:
            assert(False)
    if argv:
        printError("Unknown arguments: %s" % argv)

    # Check that mandatory args were present
    if "k" in mandatoryString and not keyPem:
        printError("-k missing (TACK_Key)")
    if "c" in mandatoryString and not inCert:
        printError("-c missing (SSL certificate)")
    if "i" in mandatoryString and not inTack:
        printError("-i missing (TACK)")
    if "d" in mandatoryString and duration == None:
        printError("-d missing (duration)")        

    # Load the key, prompting for password if not specified on cmdline
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
                    sys.stderr.write("PASSWORD INCORRECT!\n")
        except SyntaxError:
            printError("Error processing TACK Secret Key File")

    # Populate the return list
    retList = []
    if "p" in argString:
        retList.append(password)
    if "o" in argString:
        retList.append(outputFile)
    if "i" in argString:
        retList.append(inTack)
    if "c" in argString:
        retList.append(inCert)
    if "k" in argString:
        retList.append(inKey)
    if "g" in argString:
        retList.append(generation)
    if "d" in argString:
        retList.append(duration)
    if "e" in argString:
        if not expiration:
            # round up to next minute
            expiration = int(math.ceil(inCert.notAfter / 60.0))
        retList.append(expiration) 
    if "s" in argString:
        retList.append(sigType)
        if sigType == TACK_Sig_Type.v1_cert:
            retList.append(inCert.cert_sha256)
        else:
            retList.append(inCert.key_sha256)  
    if "b" in argString:
        retList.append(breakSigs)      
    return retList
    
def addPemComments(inStr):
    """Add pre-PEM metadata/comments to PEM strings."""
    versionStr = __version__
    timeStr = posixTimeToStr(time.time(), True)
    outStr = "Created by TACK.py %s\nCreated at %s\n%s" % \
                (versionStr, timeStr, inStr)
    return outStr
    
def genkeyCmd(argv):
    """Handle "TACK genkey <argv>" command."""
    password, outputFile = handleArgs(argv, "po")    
    kf = TACK_KeyFile()
    kf.create() # EC key is generated here
    if not password:
        password, password2 = "this", "that"
        while password != password2:
            password = getpass.getpass("Choose password for key file: ")    
            password2 = getpass.getpass("Re-enter password for key file: ")  
            if password != password2:
                sys.stderr.write("PASSWORDS DON'T MATCH!\n")      
    outputFile.write(addPemComments(kf.writePem(password)))

def createCmd(argv):
    """Handle "TACK create <argv>" command."""
    password, outputFile, inCert, inKey, generation, \
    duration, expiration, sigType, hash = \
        handleArgs(argv, "pockgdes", "kc")
    
    if generation == None:
        generation = 0
    if duration == None:
        duration = 5
        
    tack = TACK()
    tack.create(inKey, sigType, expiration, generation, hash, duration)
    outputFile.write(addPemComments(tack.writePem()))
    
def updateCmd(argv):
    """Handle "TACK update <argv>" command."""    
    password, outputFile, tack, inCert, inKey, generation, \
    duration, expiration, sigType, hash = \
        handleArgs(argv, "poickgdes", "kci")

    if generation == None:
        generation = tack.sig.generation
    if duration == None:
        duration = tack.duration
        
    tack.update(inKey, sigType, expiration, generation, hash, duration)
    outputFile.write(addPemComments(tack.writePem()))    

def adjustCmd(argv):
    """Handle "TACK adjust <argv>" command."""    
    outputFile, tack, duration, = handleArgs(argv, "oid", "id")
    tack.duration = duration
    outputFile.write(addPemComments(tack.writePem()))    
    
def breakCmd(argv):
    """Handle "TACK break <argv>" command."""
    password, outputFile, tack, inKey = \
        handleArgs(argv, "poik", "ki")

    breakSig = TACK_Break_Sig()   
    breakSig.create(tack.pin, inKey.sign(tack.pin.write()))
    outputFile.write(addPemComments(breakSig.writePem()))    

def makecertCmd(argv):
    """Handle "TACK makecert <argv>" command."""    
    outputFile, tack, breakSigs = handleArgs(argv, "oib", "i")
    tc = TACK_Cert()
    tc.create(tack, breakSigs)
    outputFile.write(tc.writePem())     

def viewCmd(argv):
    """Handle "TACK view <argv>" command."""    
    if len(argv) < 1:
        printError("Missing argument: file to view")
    if len(argv) > 1:
        printError("Can only view one file")
    try:
        # Read both binary (bytearray) and text (str) versions of the input
        b = bytearray(open(argv[0], "rb").read())
        try:
            s = open(argv[0], "rU").read()
        except UnicodeDecodeError:
            # Python3 error, so it must be a binary file; not text
            s = None            
    except IOError:
        printError("Error opening file: %s" % argv[0])

    fileType = None
    try:
        if s:            
            if pemSniff(s, "TACK SECRET KEY"):
                fileType = "Secret Key"
                kfv = TACK_KeyFileViewer()
                kfv.parse(s)
                print(kfv.writeText())
                return
            elif pemSniff(s, "TACK"):
                fileType = "TACK"
                t = TACK()
                t.parsePem(s)
                print(t.writeText())
                return
            elif pemSniff(s, "TACK BREAK SIG"):
                fileType = "Break Sig"
                tbsList = TACK_Break_Sig.parsePemList(s)
                s = ""
                for tbs in tbsList:
                    s += tbs.writeText()
                print(s)  
                return
            elif pemSniff(s, "CERTIFICATE"):
                fileType = "Certificate"
                sslc = SSL_Cert() 
                sslc.parsePem(s)
                print(sslc.writeText())
        # Is it an SSL certificate?
        try:
            sslc = SSL_Cert()
            sslc.parse(b)
            print(sslc.writeText())
        except SyntaxError:
            printError("Unrecognized file type")
    except SyntaxError as e:
        printError("Error parsing %s: %s" % (fileType, e))

def testCmd(argv):
    assert(selfTest() == 1)
    print("OK")

def printUsage(s=None):
    if m2cryptoLoaded:
        crypto = "M2Crypto/OpenSSL"
    else:
        crypto = "Python crypto"        
    if s:
        print("ERROR: %s" % s)
    print("""\nTACK.py version %s (using %s)  

Commands (use "help <command>" to see optional args):
  genkey
  create -k KEY -c CERT  
  update -k KEY -c CERT -i TACK
  adjust -i TACK -d DURATION
  break  -k KEY -i TACK
  makecert -i TACK
  view   FILE
  test  
  help   COMMAND
""" % (__version__, crypto))
    sys.exit(-1)
    
def helpCmd(argv):
    """Handle "TACK help <argv>" command."""    
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
    elif cmd == "create"[:len(cmd)]:
        s = posixTimeToStr(time.time())        
        print( \
"""Creates a TACK based on a target SSL certificate.
        
  create -k KEY -c CERT
  
  -k KEY             : Use this TACK SecretKey file
  -c CERT            : Sign this SSL certificate

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -g GENERATION      : Use this generation number (0-255)
  -s SIG.TYPE        : Target signature to "v1_key" or "v1_cert"
  -d DURATION        : Use this duration for the pin:
                         ("5m", "30d", "1d12h5m", etc.)
  -e EXPIRATION      : use this UTC time for expiration
                        ("%s", "%sZ",
                         "%sZ", "%sZ" etc.)
                        (or, specify a duration from current time)
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "update"[:len(cmd)]:
        s = posixTimeToStr(time.time())                
        print( \
"""Updates a TACK for a new target SSL certificate.

  update -k KEY -c CERT -i TACK
  
  -k KEY             : Use this TACK SecretKey file
  -c CERT            : Sign this SSL certificate
  -i TACK            : Read this TACK file

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -g GENERATION      : Use this generation number (0-255)
  -s SIG.TYPE        : Target signature to "v1_key" or "v1_cert"
  -d DURATION        : Use this duration for the pin:
                         ("5m", "30d", "1d12h5m", etc.)
  -e EXPIRATION      : use this UTC time for expiration
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
        print("""Views a TACK, TACK Key, TACK Break Sig, or SSL certificate.

  view <file>
""")        

    elif cmd == "adjust"[:len(cmd)]:
        print( \
"""Adjusts duration.

  adjust -i TACK -d DURATION
  
  -i TACK            : Update this TACK file
  -d DURATION        : Use this duration for the pin:
                           ("5m", "30d", "1d12h5m", etc.)

Optional arguments:
  -o FILE            : Write the output to this file (instead of stdout)
""")
    elif cmd == "makecert"[:len(cmd)]:
        print( \
"""Creates a TACK certificate with the input TACK and optional Break Sigs.

  makecert -i TACK 

Optional arguments:
  -b BREAKSIGS       : Include these Break Signatures in the output.
  -o FILE            : Write the output to this file (instead of stdout)
""")
    elif cmd == "test"[:len(cmd)]:
        print( \
"""Runs self-tests.
""")
    else:
        printError("Help requested for unknown command")
        

if __name__ == '__main__':
    if len(sys.argv) < 2:
        printUsage("Missing command")
    elif sys.argv[1] == "genkey"[:len(sys.argv[1])]:
        genkeyCmd(sys.argv[2:])
    elif sys.argv[1] == "create"[:len(sys.argv[1])]:
        createCmd(sys.argv[2:])
    elif sys.argv[1] == "update"[:len(sys.argv[1])]:
        updateCmd(sys.argv[2:])
    elif sys.argv[1] == "adjust"[:len(sys.argv[1])]:
        adjustCmd(sys.argv[2:])
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        breakCmd(sys.argv[2:])
    elif sys.argv[1] == "makecert"[:len(sys.argv[1])]:
        makecertCmd(sys.argv[2:])        
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        viewCmd(sys.argv[2:])
    elif sys.argv[1] == "test"[:len(sys.argv[1])]:
        testCmd(sys.argv[2:])
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        helpCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])