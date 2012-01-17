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
from tests import *

################ MAIN ###

import sys, getpass, getopt, glob

def printUsage(s=None):
    if m2cryptoLoaded:
        crypto = "M2Crypto/OpenSSL"
    else:
        crypto = "Python crypto"        
    if s:
        print("ERROR: %s\n" % s)
    print("""TACK-tool version VV.VV.VV (using %s)  

Commands:
new    <cert>
update <cert>
adjust <duration>
break
view   <file>
help   <command>
""" % crypto)
    sys.exit(-1)

def newKeyFile(extraRandStr=""):
    # Don't prompt for more randomness - it might make users nervous
    #if not extraRandStr:
    #    while len(extraRandStr)<20:
    #        extraRandStr = getpass.getpass (
    #            "Enter at least 20 random keystrokes: ")    
    kf = TACK_KeyFile()
    kf.generate(extraRandStr)
    return kf

def openKeyFile(kfBytes, password=None):
    kf = TACK_KeyFile()
    if password:
        if not kf.parse(kfBytes, password):
            printError("Bad password")
        else:
            return kf
    while 1:
        password = getpass.getpass("Enter password for key file: ")
        if kf.parse(kfBytes, password):
            break
        print("PASSWORD INCORRECT!")
    return kf

def createFileRaiseOSExIfExists(name):
    fd = os.open(name, os.O_EXCL | os.O_CREAT | os.O_WRONLY)
    f = os.fdopen(fd, "wb")
    return f    

def writeKeyFile(kf, outkfName):
    passwordStr = ""
    while not passwordStr:
        password1, password2 = "a", "b"
        while password1 != password2:
            password1 = getpass.getpass("Choose password for key file: ")    
            password2 = getpass.getpass("Re-enter password for key file: ")  
            if password1 != password2:
                print("PASSWORDS DON'T MATCH!")      
            else:
                passwordStr = password1    
    b = kf.write(passwordStr)
    f = open(outkfName, "wb")
    f.write(b)
    f.close()
    return kf    

def writeTACKCert(tc, oldName, suffix, tcNameCounter, 
                    der=False, noBackup=False, outfName=None):    
    b = tc.write(der)
    if not der:
        newExt = ".pem"
    else:
        newExt = ".der"       
    
    # If there is an explicitly specified out-file, use it
    if outfName:
        open(outfName, "wb").write(b)
        return
        
    # Backup old TACK cert (if there is one)
    if oldName and not noBackup:
        oldf = open(oldName, "rb")
        oldBytes = oldf.read()
        oldf.close()
        bakName = "OLD_" + oldName
        try:
            bakf = createFileRaiseOSExIfExists(bakName)
        except OSError:
            # If the backup already exists:
            printError("Can't back up %s" % oldName) 
        bakf.write(oldBytes)
        bakf.close()
    
    # Create the new filename, giving it a name after the 
    # file it is replacing.
    newNameNoExt = "TACK_cert_%s_%s" % (suffix, getDateStr())
    newNameCounter = 0
    if oldName and oldName.startswith(newNameNoExt):
        newNameCounter = tcNameCounter + 1
    
    # Now look at the backup directory to see if there is
    # a name collison that will appear when we later try to
    # backup this file.  This could occur if the user reuses
    # a suffix that already has some backed-up files, but 
    # which does not match the current old file.
    for name in glob.glob("OLD_" + newNameNoExt + "*"):
        suffix, counter = parseTACKCertName(name, True)
        newNameCounter = max(newNameCounter, counter+1)

    # Prepare the new name, with counter and extension
    if newNameCounter > 0:    
        newNameNoExt += "_%03d" % newNameCounter    
    newName = newNameNoExt + newExt    
    
    # Write to the new file, remove the old file
    newf = open(newName, "wb")
    newf.write(b)
    newf.close()
    if oldName:
        os.remove(oldName)

def parseTACKCertName(tcName, old=False):
    if old:
        lIndex = len("OLD_TACK_cert_")
    else:
        lIndex = len("TACK_cert_")
    rIndex = tcName.find("_", lIndex)        
    tcSuffix = tcName[lIndex : rIndex]

    lIndex = rIndex+1
    rIndex = tcName.find("_", lIndex)
    if rIndex == -1:
        rIndex = tcName.find(".", lIndex)
    if rIndex == -1: # should be impossible, due to glob, but...
        printError("Malformed TACK certificate name, before date: %s" % tcName)
    dateStamp = tcName[lIndex : rIndex]
    try:
        time.strptime(dateStamp, "%Y-%m-%d")
    except ValueError:
        printError("Malformed TACK certificate name, bad date: %s" % tcName)

    if tcName[rIndex] == ".":
        tcNameCounter = 0
    else:
        if tcName[rIndex] != "_":
            printError(
                "Malformed TACK certificate name, after date: %s" % tcName)
        try:
            tcNameCounter = int(tcName[rIndex+1 : -4])
        except ValueError:
            printError("Malformed TACK certificate name, counter: %s" % tcName)
    return tcSuffix, tcNameCounter
            
def openTACKFiles(errorNoCertOrKey=False, password=None, kfName=None, 
                    tcName=None, skipKeyFile=False):
    if tcName:
        tcSuffix, tcNameCounter = None, None
    elif not tcName:       
        tcGlobPem = glob.glob("TACK_cert_*_*.pem")
        tcGlobDer = glob.glob("TACK_cert_*_*.der")
        tcGlob = tcGlobPem + tcGlobDer
        if len(tcGlob) == 0:
            if errorNoCertOrKey:
                printError("No TACK cert found")
            tcBytes = None
            tcName = None
            tcNameCounter = None
            tcSuffix = None
        elif len(tcGlob) > 1:
            printError("More than one TACK cert found")
        else:
            tcName = tcGlob[0]
            tcSuffix, tcNameCounter = parseTACKCertName(tcName)
    if tcName:
        tcBytes = bytearray(open(tcName, "rb").read())

    if not skipKeyFile and not kfName:
        kfGlob = glob.glob("TACK_key_*.pem")
        if len(kfGlob) == 0:
            if errorNoCertOrKey:
                printError("No TACK key found")
            kfBytes = None
        elif len(kfGlob) > 1:
            printError("More than one TACK key found")
        else:
            kfName = kfGlob[0]    
    if kfName:
        kfBytes = bytearray(open(kfName, "rb").read())        

    tc = TACK_Cert()
    if tcBytes:
        print("Updating %s..." % tcName)
        try:
            tc.parse(tcBytes)
        except SyntaxError:
            printError("TACK certificate malformed: %s" % tcName)
    else:
        tc.generate()
        print("No TACK certificate found, creating new one...")

    if not skipKeyFile and kfBytes:
        print("Opening %s..." % kfName)        
        try:
            kf = openKeyFile(kfBytes, password)   
        except SyntaxError:
            printError("%s malformed" % kfName)        
    else:
        kf = None
    return (tc, kf, tcName, tcSuffix, tcNameCounter)

def confirmY(s):
    query = raw_input(s)
    if query != "y":
        printError("Cancelled")    

def parseArgsIntoDict(argv, noArgArgs, oneArgArgs):
    argsDict = {}
    newArgv = []    
    for arg in argv:
        if not arg.startswith("--"):
            newArgv.append(arg)
            continue
        arg = arg[2:]
        parts = arg.split("=")
        if parts[0] in argsDict:
            printError("Duplicate argument: %s" % parts[0])
        if len(parts)==2:
            if not parts[0] in oneArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])
            argsDict[parts[0]] = parts[1]
        elif len(parts)==1:
            if not parts[0] in noArgArgs:
                printError("Unknown or malformed argument: %s" % parts[0])            
            argsDict[parts[0]] = None
        else:
            printError("Unknown or malformed argument: %s" % parts[0])
    return argsDict, newArgv

def pin(argv, update=False):        
    # Collect cmdline args into a dictionary        
    noArgArgs = ["der", "no_backup"]
    oneArgArgs= ["key", "in", "out",
                "pin_duration", "sig_type", "sig_expiration", 
                "sig_generation", "suffix", "password"]
    if not update:
        noArgArgs += ["replace"]
        oneArgArgs += ["out_key"]
    d, argv = parseArgsIntoDict(argv, noArgArgs, oneArgArgs)
    if len(argv) < 1:
        printError("Missing argument: SSL certificate file")    
    if len(argv) > 1:
        printError("Extra arguments")            
    sslName = argv[0]    
    
    # Set vars from cmdline dict
    der = "der" in d
    noBackup = "no_backup" in d
    forceReplace = "replace" in d
    kfName = d.get("key")
    infName = d.get("in")
    outfName = d.get("out")
    outkfName = d.get("out_key")
    if infName and not outfName:
        printError("--in requires --out")
    sig_generation = d.get("sig_generation")
    if sig_generation != None: # Ie not set on cmdline, DIFFERENT FROM 0
        try:
            sig_generation = int(sig_generation)
            if sig_generation < 0 or sig_generation > 255:
                printError("sig_generation out of range")
        except ValueError:
            printError("Malformed sig_generation")
    pin_duration = d.get("pin_duration")
    if pin_duration != None:
        try:
            pin_duration = parseDurationArg(pin_duration)
        except SyntaxError:
            printError("Malformed pin_duration")
    sig_expiration = d.get("sig_expiration")
    if sig_expiration != None:
        sig_expiration= parseTimeArg(sig_expiration)
    cmdlineSuffix = d.get("suffix")
    password = d.get("password")
    try:
        sig_type = {"v1_key" : TACK_Sig_Type.v1_key, 
                    "v1_cert" : TACK_Sig_Type.v1_cert}\
                    [d.get("sig_type", "v1_cert")]
    except KeyError:
            printError("Unrecognized sig_type")
                
    # Open the SSL cert
    try:
        sslBytes = bytearray(open(sslName, "rb").read())
    except IOError:
        printError("SSL certificate file not found: %s" % argv[0])
    sslc = SSL_Cert()
    try:
        sslc.parse(sslBytes)        
    except SyntaxError:
        prinError("SSL certificate malformed: %s" % argv[0])
    
    # Open the TACK_cert and TACK_key files, creating latter if needed
    tc, kf, tcName, parsedSuffix, tcNameCounter = \
        openTACKFiles(update, password, kfName, infName)
    if not kf:
        print("No TACK key found, creating new one...")
        kf = newKeyFile()
        mustWriteKeyFile = True
    else:
        mustWriteKeyFile = False        

    # Set sig_expiration (cmdline or from SSL cert)
    if sig_expiration == None:
        sig_expiration = int(math.ceil(sslc.notAfter / 60.0)) # round up 

    # Check existing TACK_Pin and TACK_Sig
    if update:
        if not tc.TACK:
            printError("TACK certificate has no TACK extension")
        # Maintain old sig_generation and pin_duration on updates, 
        # unless overridden on cmdline
        if pin_duration != None:
            tc.TACK.pin_duration = pin_duration
        if sig_generation == None: # i.e. not set on cmdline, DIFFERENT FROM 0
            sig_generation = tc.TACK.sig.sig_generation
        else:
            if sig_generation < tc.TACK.sig.sig_generation:
                confirmY(
'''WARNING: Requested sig_generation is EARLIER than existing!
Do you know what you are doing? ("y" to continue): ''')
        tc.TACK.sig = None
    elif not update and tc.TACK:
        if not forceReplace:
            confirmY('There is an existing TACK, choose "y" to replace: ')        
        tc.TACK = None

    # Set suffix for output (new=cmdline or prompt, update=parsed)
    suffix = None
    if not outfName:
        if cmdlineSuffix:
            suffix = cmdlineSuffix
        else:
            if not update:
                if mustWriteKeyFile:
                    suffix = raw_input(
    "Enter a short suffix for your TACK key and cert files: ")
                else:
                    suffix = raw_input(
    "Enter a short suffix for your TACK cert file: ")
            else:
                suffix = parsedSuffix

    # Produce the TACK_Pin (if "new")
    if not update:
        tc.TACK = TACK()
        tc.TACK.pin = TACK_Pin()            
        label = bytearray(os.urandom(8))
        # If pin_duration was not set or carried-over, set to 5 minutes
        if pin_duration == None:
            tc.TACK.pin_duration = 5        
        tc.TACK.pin.generate(TACK_Pin_Type.v1, label, kf.public_key)

    # Produce the TACK_Sig
    if sig_type == TACK_Sig_Type.v1_key:
        sig_target_sha256 = sslc.key_sha256
    elif sig_type == TACK_Sig_Type.v1_cert:
        sig_target_sha256 = sslc.cert_sha256
    tc.TACK.sig = TACK_Sig()
    # If sig_generation was not set or carried-over, set to 1970
    if sig_generation == None:
        sig_generation = 0
    tc.TACK.sig.generate(sig_type, sig_expiration, sig_generation, 
                    sig_target_sha256, tc.TACK.pin, kf.sign)

    # Write out files
    writeTACKCert(tc, tcName, suffix, tcNameCounter, der, noBackup, outfName)
    if mustWriteKeyFile:
        if not outkfName:
            outkfName = "TACK_key_%s.pem" % suffix
        writeKeyFile(kf, outkfName)

def adjust(argv):        
    # Collect cmdline args into a dictionary        
    noArgArgs = ["der", "no_backup"]
    oneArgArgs= ["in", "out", "suffix"]
    d, argv = parseArgsIntoDict(argv, noArgArgs, oneArgArgs)
    if len(argv) < 1:
        printError("Missing argument: duration")    
    if len(argv) > 1:
        printError("Extra arguments")
    try:
        pin_duration = parseDurationArg(argv[0])
    except SyntaxError:
        printError("Malformed pin_duration")   
    
    # Set vars from cmdline dict
    der = "der" in d
    noBackup = "no_backup" in d
    infName = d.get("in")
    outfName = d.get("out")    
    if infName and not outfName:
        printError("--in requires --out")    
    cmdlineSuffix = d.get("suffix")
    
    tc, kf, tcName, suffix, nameCounter = openTACKFiles(False, None, None,
                                            infName, skipKeyFile=True)    
    if cmdlineSuffix:
        suffix = cmdlineSuffix
        
    if not tc.TACK:
        print("WARNING: There is no existing TACK...")
        
    tc.TACK.pin_duration = pin_duration    

    writeTACKCert(tc, tcName, suffix, nameCounter, der, noBackup, outfName)    
    

def breakPin(argv):
    # Collect cmdline args into a dictionary        
    noArgArgs = ["der", "no_backup"]
    oneArgArgs= ["key", "in", "out", 
                "suffix", "password"]
    d, argv = parseArgsIntoDict(argv, noArgArgs, oneArgArgs)
    if len(argv) > 0:
        printError("Extra arguments")    
    
    # Set vars from cmdline dict
    der = "der" in d
    noBackup = "no_backup" in d
    kfName = d.get("key")    
    infName = d.get("in")
    outfName = d.get("out")    
    if infName and not outfName:
        printError("--in requires --out")    
    cmdlineSuffix = d.get("suffix")
    password = d.get("password")
    
    tc, kf, tcName, suffix, nameCounter = openTACKFiles(True, password, kfName,
                                            infName)
    
    if cmdlineSuffix:
        suffix = cmdlineSuffix
    if not tc.break_sigs:
        tc.break_sigs = TACK_Break_Sigs()

    if tc.break_sigs.isFull():
        printError("Maximum number of break signatures (%d) already present" %
            TACK_Break_Sigs.maxLen)
        
    break_sig = TACK_Break_Sig()   

    if not tc.TACK:
        printError("There is no existing TACK to break")
    pin_label = tc.TACK.pin.pin_label
    print("Breaking existing TACK, pin_label = 0x%s" % \
            b2a_hex(pin_label))
    confirmY('Is this correct? ("y" to continue): ')            
    
    break_sig.generate(tc.TACK.pin, kf.sign(tc.TACK.pin.write()))
    tc.break_sigs.add(break_sig)    
    tc.TACK = None
    
    writeTACKCert(tc, tcName, suffix, nameCounter, der, noBackup, outfName)
     
def view(argv):
    if len(argv) < 1:
        printError("Missing argument: object to view")
    if len(argv) > 1:
        printError("Can only view one object")
    try:
        b = bytearray(open(argv[0], "rb").read())
    except IOError:
        printError("File not found: %s" % argv[0])
    # If it's a key file
    try:
        kfv = TACK_KeyFileViewer()
        kfv.parse(b)
        print(kfv.writeText())
    except SyntaxError:
    # If not it could be a certificate
        try:
            written=0            
            tc = TACK_Cert()
            tc.parse(b)
            if tc.TACK or tc.break_sigs:
                print(tc.writeText())
                written = 1      
        except SyntaxError:
            pass
        if not written:
            try:
                sslc = SSL_Cert()
                sslc.parse(b)
                print(sslc.writeText())      
            except SyntaxError:
                printError("Unrecognized file type")

def help(argv):
    if len(argv) == 0:
        printUsage()
    cmd = argv[0]
    if cmd == "new"[:len(cmd)]:
        s = posixTimeToStr(time.time())        
        print( \
"""Creates a TACK based on a new pin for the target SSL certificate.
        
  new <cert> <args>

Optional arguments:
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup any existing TACK certificate
  --replace          : replace an existing TACK without prompting
  --key=             : use this TACK key
  --in=              : update this TACK certificate
  --out=             : write the output TACK certificate here
  --out_key=         : write the output TACK key here
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix
  --sig_type=        : target signature to "v1_key" or "v1_cert"
  --pin_duration=    : use this pin_duration
                         ("5m", "30d", "1d12h5m", etc.)
  --sig_expiration=  : use this UTC time for sig_expiration
                         ("%s", "%sZ",
                          "%sZ", "%sZ" etc.)
                         (or, specify a duration from current time)
  --sig_generation=  : the signature belongs to this generation
                         
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "update"[:len(cmd)]:
        s = posixTimeToStr(time.time())                
        print( \
"""Creates a TACK based on an existing pin for the target SSL certificate.

  update <cert> <args>

Optional arguments:
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the existing TACK certificate
  --key=             : use this TACK key
  --in=              : update this TACK certificate
  --out=             : write the output TACK certificate here    
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix
  --sig_type=        : target signature to "v1_key" or "v1_cert"
  --pin_duration=    : use this pin_duration
                         ("5m", "30d", "1d12h5m", etc.) 
  --sig_expiration=  : use this UTC time for sig_expiration
                         ("%s", "%sZ",
                          "%sZ", "%sZ" etc.)
                         (or, specify a duration from current time)
  --sig_generation=  : the signature belongs to this generation
""" % (s, s[:13], s[:10], s[:4]))
    elif cmd == "break"[:len(cmd)]:
        print( \
"""Adds a break signature to a TACK certificate, and removes any broken TACK.

  break <args>

Optional arguments:
  --label            : pin_label to break (8 bytes hexadecimal)
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the TACK certificate
  --key=             : use this TACK key  
  --in=              : update this TACK certificate
  --out=             : write the output TACK certificate here  
  --password=        : use this TACK key password
  --suffix=          : use this TACK file suffix 
""")
    elif cmd == "view"[:len(cmd)]:
        print("""Views a TACK certificate, SSL certificate, or Key File.

  view <file>
""")        

    elif cmd == "adjust"[:len(cmd)]:
        print( \
"""Adjusts pin_duration.

  adjust <duration> <args>

Duration can be specified in days, hours, minutes, or some combination:
  ("5m", "30d", "1d12h5m", "365d90m", "1h45m" etc.) 

Optional arguments:
  --der              : write output as .der instead of .pem
  --no_backup        : don't backup the existing TACK certificate
  --in=              : update this TACK certificate
  --out=             : write the output TACK certificate here    
  --suffix=          : use this TACK file suffix
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
    elif sys.argv[1] == "new"[:len(sys.argv[1])]:
        pin(sys.argv[2:], False)
    elif sys.argv[1] == "update"[:len(sys.argv[1])]:
        pin(sys.argv[2:], True)
    elif sys.argv[1] == "adjust"[:len(sys.argv[1])]:
        adjust(sys.argv[2:])
    elif sys.argv[1] == "break"[:len(sys.argv[1])]:
        breakPin(sys.argv[2:])
    elif sys.argv[1] == "view"[:len(sys.argv[1])]:
        view(sys.argv[2:])
    elif sys.argv[1] == "help"[:len(sys.argv[1])]:
        help(sys.argv[2:])
    else:
        printUsage("Unknown command: %s" % sys.argv[1])