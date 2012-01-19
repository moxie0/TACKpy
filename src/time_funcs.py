from compat import *
from misc import *

################ TIME FUNCS ###

import time, calendar, datetime, math

# u in seconds
def posixTimeToStr(u, includeSeconds=False):    
    t = time.gmtime(u)
    if includeSeconds:
        s = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)        
    else:
        s = time.strftime("%Y-%m-%dT%H:%MZ", t)
    return s

# u in minutes
def durationToStr(u):
    s = ""
    if u >= (1440): # 1440 minutes per day
        s += "%dd" % (u//1440)
        u %= 1440
    if u >= (60): # 60 minutes per hour
        s += "%dh" % (u//60)
        u %= 60
    if u>0 or not s:
        s += "%dm" % u
    return s
    
def parseTimeArg(arg):
    # First, see if they specified time as a duration
    try:
        mins = parseDurationArg(arg)
        return int(math.ceil(time.time() / 60.0)) + mins
    except SyntaxError:
        pass
        
    # Otherwise, allow them to specify as much or as little of
    # ISO8601 as they want, but must end with "Z"
    patterns = ["%Y-%m-%dT%H:%MZ", "%Y-%m-%dT%HZ", 
        "%Y-%m-%dZ", "%Y-%mZ", "%YZ"]
    t = None
    for p in patterns:
        try:
            t = time.strptime(arg, p)
            break
        except ValueError:
            pass
    if not t:
        s = posixTimeToStr(time.time())
        printError(\
'''Invalid time format, use e.g. "%s" (current time)
or some prefix, such as: "%sZ", "%sZ", or "%sZ",
*OR* some duration, such as "5m", "30d", "1d12h5m", etc."''' % 
            (s, s[:13], s[:10], s[:4]))    
    u = int(calendar.timegm(t)//60)
    if u < 0:
        printError("Time too early, epoch starts at 1970.")
    return u

def parseDurationArg(arg):
    arg = arg.upper()
    foundSomething = False
    try:
        mins = 0
        while 1:
            i = arg.find("D")
            if i != -1:
                mins += 1440 * int(arg[:i])
                arg = arg[i+1:]
                foundSomething = True
            i = arg.find("H")
            if i != -1:
                mins += 60 * int(arg[:i])
                arg = arg[i+1:]
                foundSomething = True
            i = arg.find("M")
            if i != -1: 
                mins += int(arg[:i])
                arg = arg[i+1:]
                foundSomething = True
            if arg:
                raise SyntaxError()
            if not foundSomething:
                raise SyntaxError()
            return mins
    except:
        raise SyntaxError()
        

def getDateStr():
    now = datetime.datetime.now()
    return now.strftime("%Y-%m-%d") 

# Return UNIX time int
def parseASN1UTCTime(b):
    try:
        if b[-1] != ord("Z"):
            raise SyntaxError()
        if len(b) == len("YYMHDDHHMMSSZ"):
            pass
        elif len(b) == len("YYHHDDHHMMZ"):
            b = b[:-1] + b"00Z"
        else:
            raise SyntaxError()
        year = int(b[:2])
        if year < 50:
            b = b"20" + b
        else:
            b = b"19" + b
    except:
        raise SyntaxError()
    return parseASN1GeneralizedTime(b)
    

def parseASN1GeneralizedTime(b):
    t = time.strptime(bytesToStrAscii(b), "%Y%m%d%H%M%SZ")
    return int(calendar.timegm(t))
    

