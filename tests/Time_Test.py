# Authors: 
#   Trevor Perrin
#   Moxie Marlinspike
#
# See the LICENSE file for legal information regarding use of this file.

import unittest
from tack.util.Time import Time

class TimeTest(unittest.TestCase):

    def test_posix(self):
        assert(Time.posixTimeToStr(1234567890, True) == "2009-02-13T23:31:30Z")
        assert(Time.posixTimeToStr(1234567890) == "2009-02-13T23:31Z")

    def test_delta(self):
        assert(0 == Time.parseDeltaArg("0m"))
        assert(59 == Time.parseDeltaArg("59m"))
        assert(60 == Time.parseDeltaArg("1h"))
        assert(61 == Time.parseDeltaArg("1h1m"))
        assert(1439 == Time.parseDeltaArg("23h59m"))
        assert(1440 == Time.parseDeltaArg("1d"))
        assert(1441 == Time.parseDeltaArg("1d1m"))
        assert(1500 == Time.parseDeltaArg("1d1h"))
        assert(1501 == Time.parseDeltaArg("1d1h1m"))
        assert(1440*37+122 == Time.parseDeltaArg("37d2h2m"))

    def test_string(self):
        assert(Time.parseTimeArg("2012-07-20T05:40Z")*60 == 1342762800)
        assert(Time.parseTimeArg("2012-07-20T05Z")*60 == 1342760400)
        assert(Time.parseTimeArg("2012-07-20Z")*60 == 1342742400)
        assert(Time.parseTimeArg("2012-07Z")*60 == 1341100800)
        assert(Time.parseTimeArg("2012Z")*60 == 1325376000)
        
# !!! Add tests for ASN1 times

if __name__ == '__main__':
    unittest.main()
