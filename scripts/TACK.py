#! /usr/bin/env python

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from TACKpy import TACK, TACK_Key, TACK_Break_Sig, TACK_Extension, \
    TACK_KeyFile, TACK_KeyFileViewer, \
    SSL_Cert, __version__, \
    m2cryptoLoaded, TACK_Version, \
    posixTimeToStr, selfTest, pemSniff, \
    parseDurationArg, parseTimeArg

################ MAIN ###

import time, math, sys, getpass, getopt

def printError(s):
    """Print error message and exit"""
    sys.stderr.write("ERROR: %s\n" % s)
    sys.exit(-1)

def handleArgs(argv, argString, mandatoryString="", flags="", 
                tackcertFlag=False):
    """Helper function for handling cmdline args.

argv should be sys.argv[2:], i.e. the cmdline args minus "TACK <cmd>".
argString is a string with each char indicating a supported arg.
mandatoryString is a string with each char indicating a mandatory arg.

Allowed chars in argString: "poickgmdesbn"
Allowed chars in mandatoryString: "ickd"
Allowed chars in flags: "v"

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
    getOptArgString += flags
    try:
        opts, argv = getopt.getopt(argv, getOptArgString)
    except getopt.GetoptError as e:
        printError(e) 
    # Default values if arg not present   
    password = None
    outputFile = (sys.stdout, None)
    inTack  = None
    inCert = None
    inKey = None
    keyPem = None # Temporary to load PEM'd key
    outBreak = None
    generation = None
    min_generation = None
    expiration = None
    breakSigs = None
    verbose = False
    numArg = None
    for opt, arg in opts:
        if opt == "-p":
            password = arg
        elif opt == "-o":
            # Defer opening it because -n might be set
            outputFile = (None, arg) 
        elif opt == "-i":
            try:
                s = open(arg, "rU").read()
            except IOError:
                printError("Error opening TACK file: %s" % arg)
            if not tackcertFlag or pemSniff(s, "TACK"):
                try:
                    inTack = TACK()
                    inTack.parsePem(s)
                except SyntaxError:
                    printError("TACK malformed: %s" % arg)
            elif pemSniff(s, "CERTIFICATE"):
                try:
                    inCert = SSL_Cert()
                    inCert.parsePem(s)
                    # OK, this is ugly, but we're returning the SSL_Cert
                    # via the "inTack" variable in the tackcertFlag=True
                    # case...
                    inTack = inCert
                except AssertionError:#SyntaxError:
                    printError("TACK Certificate malformed: %s" % arg)
                    raise
            else:
                printError("Input must be either TACK or TACK certificate.")
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
        elif opt == "-m":
            try:
                min_generation = int(arg) # Could raise ValueError
                if min_generation < 0 or min_generation>255:
                    raise ValueError()                
            except ValueError:
                printError("Bad min_generation: %s" % arg)        
        elif opt == "-e":
            # parseTimeArg will error and exit if arg is malformed
            try:
                expiration = parseTimeArg(arg)
            except SyntaxError as e:
                printError(e)
        elif opt == "-b":
            try:
                breakSigsPem = open(arg, "rU").read()
            except IOError:
                printError("Error opening Break Sigs file: %s" % arg)                        
            try:
                breakSigs = TACK_Break_Sig.parsePemList(breakSigsPem)
            except SyntaxError:
                printError("Break Sigs malformed: %s" % arg)   
        elif opt == "-v":
            verbose = True
        elif opt == "-n":
            try:
                leftArg, rightArg = arg.split("@") # could raise ValueError
                numTacks = int(leftArg) # could raise ValueError
                interval = parseDurationArg(rightArg) # SyntaxError
                if numTacks < 1 or numTacks >= 10000:
                    raise ValueError()
                numArg = (numTacks, interval)
            except (ValueError, SyntaxError):
                printError("Bad -n NUMTACKS: %s:" % arg)                
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

    # If -o and not -n, then open the output file
    if outputFile[1]:
        try:
            if not numArg:
                outputFile = (open(outputFile[1], "w"), outputFile[1])
        except IOError:
            printError("Error opening output file: %s" % arg)
            
    if min_generation is None:
        min_generation = 0
    if generation is None:
        generation = min_generation
    else:
        if generation < min_generation:
            printError("generation must be >= min_generation")

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
        retList.append(inCert.key_sha256)        
    if "k" in argString:
        retList.append(inKey)
    if "g" in argString:
        retList.append(generation)
    if "m" in argString:
        retList.append(min_generation)
    if "e" in argString:
        if not expiration:
            # If not specified and not -n,
            #   round up to next minute from certificate
            if not numArg:
                expiration = int(math.ceil(inCert.notAfter / 60.0))
        retList.append(expiration) 
    if "b" in argString:
        retList.append(breakSigs)
    if "n" in argString:
        retList.append(numArg)      
    if "v" in flags:
        retList.append(verbose)
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
    password, (outputFile,_), verbose = handleArgs(argv, "po", flags="v")    
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
    if verbose:
        sys.stderr.write(kf.writeText()+"\n")

def signCmd(argv):
    """Handle "TACK sign <argv>" command."""
    (password, (outputFile,outputFilename), inCert, hash, inKey, 
    generation, min_generation, expiration,
    numArg, verbose) = \
        handleArgs(argv, "pockgmen", "kcd", flags="v")
    
    if not numArg: # No -n
        tack = TACK()
        tack.create(inKey, min_generation, generation, 
                    expiration, hash)
        outputFile.write(addPemComments(tack.writePem()))
        if verbose:
            sys.stderr.write(tack.writeText()+"\n")    
    else:
        (numTacks, interval) = numArg
        if not outputFilename:
            printError("-o required with -n")
        if not expiration:
            printError("-e required with -n")
        for x in range(numTacks):
            tack = TACK()
            tack.create(inKey, min_generation, generation, 
                        expiration, hash)
            outputFile = open(outputFilename+"_%04d.pem" % x, "w")
            outputFile.write(addPemComments(tack.writePem()))
            outputFile.close()
            if verbose:
                sys.stderr.write(tack.writeText()+"\n")            
            expiration += interval       
 
def breakCmd(argv):
    """Handle "TACK break <argv>" command."""
    password, (outputFile,_), inKey, verbose = \
        handleArgs(argv, "pok", "k", flags="v")

    key = TACK_Key()
    key.create(inKey.public_key)
    breakSig = TACK_Break_Sig()
    breakSig.create(key, inKey.sign(key.write()))
    outputFile.write(addPemComments(breakSig.writePem()))
    if verbose:
        sys.stderr.write(breakSig.writeText()+"\n")        

def tackcertCmd(argv):
    """Handle "TACK tackcert <argv>" command."""    
    (outputFile,_), X, breakSigs, verbose = \
        handleArgs(argv, "oib", "i", tackcertFlag=True, flags="v")
    if isinstance(X, TACK):
        tack = X
        tackExt = TACK_Extension()
        tackExt.create(tack, breakSigs)
        tc = SSL_Cert()
        tc.create(tackExt)
        outputFile.write(tc.writePem())
        if verbose:
            sys.stderr.write(tackExt.writeText()+"\n")        
    elif isinstance(X, SSL_Cert):
        if breakSigs:
            printError("invalid arguments: Break Sigs with TACK Cert.")
        sslCert = X
        s = ""
        if sslCert.tackExt:
            if sslCert.tackExt.tack:
                s += sslCert.tackExt.tack.writePem()
            if sslCert.tackExt.break_sigs:
                for bs in sslCert.tackExt.break_sigs:
                    s += bs.writePem()
        print(s)
        if verbose:
            sys.stderr.write(sslCert.writeText()+"\n")        
        

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
                return
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
  sign   -k KEY -c CERT
  break  -k KEY
  tackcert -i TACK
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
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")        
    elif cmd == "sign"[:len(cmd)]:
        s = posixTimeToStr(time.time())        
        print( \
"""Creates a TACK based on a target SSL certificate.
        
  sign -k KEY -c CERT
  
  -k KEY             : Use this TACK SecretKey file
  -c CERT            : Sign this SSL certificate's public key

Optional arguments:
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
  -m MIN_GENERATION  : Use this min_generation number (0-255)
  -g GENERATION      : Use this generation number (0-255)
  -e EXPIRATION      : Use this UTC time for expiration
                         ("%s", "%sZ",
                          "%sZ", "%sZ" etc.)
                       Or, specify a duration from current time:
                         ("5m", "30d", "1d12h5m", "0m", etc.)                         
  - n NUM@INTERVAL   : Generate NUM TACKs, with expiration times spaced 
                       out by INTERVAL (see -d for INTERVAL syntax).  The 
                       -o argument is used as a filename prefix, and the
                       -e argument is used as the first expiration time.
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "break"[:len(cmd)]:
        print( \
"""Creates a break signature based on an input TACK SecretKey file.

  break -k KEY
  
  -k KEY             : Use this TACK SecretKey file 

Optional arguments:
  -v                 : Verbose
  -o FILE            : Write the output to this file (instead of stdout)
  -p PASSWORD        : Use this TACK key password instead of prompting
""")
    elif cmd == "view"[:len(cmd)]:
        print("""Views a TACK, TACK Key, TACK Break Sig, or SSL certificate.

  view <file>
""")        
    elif cmd == "tackcert"[:len(cmd)]:
        print( \
"""Creates a TACK certificate with the input TACK and optional Break Sigs.

(Alternatively, if input is a TACK certificate, writes out the TACK and/or
Break Signatures as PEM files).

  tackcert -i (TACK or CERT) 

Optional arguments:
  -v                 : Verbose
  -b BREAKSIGS       : Include Break Signatures from this file.
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
    elif sys.argv[1] == "sign"[:len(sys.argv[1])]:
        signCmd(sys.argv[2:])
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        breakCmd(sys.argv[2:])
    elif sys.argv[1] == "tackcert"[:len(sys.argv[1])]:
        tackcertCmd(sys.argv[2:])        
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        viewCmd(sys.argv[2:])
    elif sys.argv[1] == "test"[:len(sys.argv[1])]:
        testCmd(sys.argv[2:])
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        helpCmd(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])