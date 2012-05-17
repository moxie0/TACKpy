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

    def test_duration(self):
        assert(Time.durationToStr(0) == "0m")
        assert(Time.durationToStr(59) == "59m")
        assert(Time.durationToStr(60) == "1h")
        assert(Time.durationToStr(61) == "1h1m")
        assert(Time.durationToStr(1439) == "23h59m")
        assert(Time.durationToStr(1440) == "1d")
        assert(Time.durationToStr(1441) == "1d1m")
        assert(Time.durationToStr(1500) == "1d1h")
        assert(Time.durationToStr(1501) == "1d1h1m")
        assert(Time.durationToStr(1440*37+122) == "37d2h2m")

        assert(0 == Time.parseDurationArg("0m"))
        assert(59 == Time.parseDurationArg("59m"))
        assert(60 == Time.parseDurationArg("1h"))
        assert(61 == Time.parseDurationArg("1h1m"))
        assert(1439 == Time.parseDurationArg("23h59m"))
        assert(1440 == Time.parseDurationArg("1d"))
        assert(1441 == Time.parseDurationArg("1d1m"))
        assert(1500 == Time.parseDurationArg("1d1h"))
        assert(1501 == Time.parseDurationArg("1d1h1m"))
        assert(1440*37+122 == Time.parseDurationArg("37d2h2m"))

    def test_string(self):
        assert(Time.parseTimeArg("2012-07-20T05:40Z")*60 == 1342762800)
        assert(Time.parseTimeArg("2012-07-20T05Z")*60 == 1342760400)
        assert(Time.parseTimeArg("2012-07-20Z")*60 == 1342742400)
        assert(Time.parseTimeArg("2012-07Z")*60 == 1341100800)
        assert(Time.parseTimeArg("2012Z")*60 == 1325376000)

if __name__ == '__main__':
    unittest.main()