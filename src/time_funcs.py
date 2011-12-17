from compat import *

################ TIME FUNCS ###

import time, calendar, datetime

def posixTimeToStr(u, includeSeconds=False):    
    t = time.gmtime(u)
    if includeSeconds:
        s = time.strftime("%Y-%m-%dT%H:%M:%SZ", t)        
    else:
        s = time.strftime("%Y-%m-%dT%H:%MZ", t)
    return s
    
def getDefaultExpirationStr():
    days = pinDays = 550 # About 1.5 years
    currentTime = int(time.time()) # Get time in seconds
    exp = currentTime + (24*60*60) * days
    return posixTimeToStr(exp)

def parseTimeArg(arg):
    # Allow them to specify as much or as little of
    # ISO8601 as they want
    if arg.endswith("Z"):
        arg = arg[:-1]
    patterns = ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H", 
        "%Y-%m-%d", "%Y-%m", "%Y"]
    t = None
    for p in patterns:
        try:
            t = time.strptime(arg, p)
            break
        except ValueError:
            pass
    if not t:
        s = posixTimeToStr(time.time())
        printError(
'''Invalid time format, use e.g. "%s" (current time)
or some prefix, such as: "%s", "%s", or "%s"''' % 
            (s, s[:13], s[:10], s[:4]))    
    u = int(calendar.timegm(t)//60)
    if u < 0:
        printError("Time too early, epoch starts at 1970.")
    return u

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
    t = time.strptime(bytesToStr(b), "%Y%m%d%H%M%SZ")
    return int(calendar.timegm(t))
    

