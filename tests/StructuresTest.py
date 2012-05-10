import unittest
from tack.compat import a2b_hex
from tack.structures.Tack import Tack
from tack.structures.TackBreakSig import TackBreakSig
from tack.structures.TackKeyFile import TackKeyFile
from tack.util.Time import Time

class StructuresTest(unittest.TestCase):

    def test_Tack(self):
        s = """
-----BEGIN TACK-----
TAmsAZIpzR+MYwQrsujLhesvpu3dRc5ROhfgySqUVkU1p1hdXo+PwQrmaQo9B9+o
hecRrWElh3yThwgYQRgbSwAAAY0cQDHeDLGfKtuw0c17GzHvjuPrWbdEWa75S0gL
7u64XGTJQUtzAwXIWOkQEQ0BRUlbzcGEa9a1PBhjmmWFNF+kGAswhLnXc5qL4y/Z
PDUV0rzIIYjXP58T5pphGKRgLlK3Aw==
-----END TACK-----"""

        t = Tack().createFromPem(s)

        assert(t.public_key.getRawKey() == a2b_hex("4c09ac019229cd1f8c63042bb2e8"
                                       "cb85eb2fa6eddd45ce513a17e0c9"
                                       "2a94564535a7585d5e8f8fc10ae6"
                                       "690a3d07dfa885e711ad6125877c"
                                       "9387081841181b4b"))
        assert(Time.posixTimeToStr(t.expiration*60) == "2019-06-25T22:24Z")
        assert(t.generation == 0)
        assert(t.target_hash == a2b_hex("31de0cb19f2adbb0d1cd7b1b31ef8ee3eb59b74459aef94b480beeeeb85c64c9"))
        assert(t.signature == a2b_hex("414b730305c858e910110d0145495"
                                      "bcdc1846bd6b53c18639a6585345f"
                                      "a4180b3084b9d7739a8be32fd93c3"
                                      "515d2bcc82188d73f9f13e69a6118"
                                      "a4602e52b703"))

    def test_BreakSig(self):
        s = """
-----BEGIN TACK BREAK SIG-----
TAmsAZIpzR+MYwQrsujLhesvpu3dRc5ROhfgySqUVkU1p1hdXo+PwQrmaQo9B9+o
hecRrWElh3yThwgYQRgbS0HynTQCmrY48oJsQtarSMoxnRNYHaaYOXwu9+4ur8mX
wjKhIA9fXWNxuP73ZoicU+qC4bZjMN+WKuy7k8bSQZY=
-----END TACK BREAK SIG-----"""

        tbs = TackBreakSig.createFromPem(s)
        assert(tbs.getTackId() == "nkufh.czttd.5cmlw.7cxtv.k6srn")
        assert(tbs.signature == a2b_hex("41f29d34029ab638f2826c42d6a"
                                        "b48ca319d13581da698397c2ef7"
                                        "ee2eafc997c232a1200f5f5d637"
                                        "1b8fef766889c53ea82e1b66330"
                                        "df962aecbb93c6d24196"))

    def test_BreakSigList(self):
        s = """
-----BEGIN TACK BREAK SIG-----
TAmsAZIpzR+MYwQrsujLhesvpu3dRc5ROhfgySqUVkU1p1hdXo+PwQrmaQo9B9+o
hecRrWElh3yThwgYQRgbS0HynTQCmrY48oJsQtarSMoxnRNYHaaYOXwu9+4ur8mX
wjKhIA9fXWNxuP73ZoicU+qC4bZjMN+WKuy7k8bSQZY=
-----END TACK BREAK SIG-----
Created by TACK.py 0.9.6
Created at 2012-05-10T00:54:10Z
-----BEGIN TACK BREAK SIG-----
73nkbxCcvFnrCIlcgtZx4iPevqxUFd9RFUNU18xfqzTCU8hV0jwYerdCwt8+VbkQ
OvHEbbRHmGAX8yseGrYX1dNuoFfSN1fCLY08u/0NU+x8fmJ6tEewegVAHguw67eR
PgegVlKuDULIASht9fvs6xTfxcFJDUgNaenZfcqAgAI=
-----END TACK BREAK SIG-----
"""
        tbsList = TackBreakSig.createFromPemList(s)
        assert(tbsList[0].getTackId()  == "nkufh.czttd.5cmlw.7cxtv.k6srn")
        assert(tbsList[1].getTackId()  == "6xwgu.ydz7m.7cki3.kizmd.pt2f2")
        assert(len(tbsList) == 2)
        return 1

    def test_KeyFile(self):
        s = """
    -----BEGIN TACK PRIVATE KEY-----
    AQAAIAAjOxiOdpiMo5qWidXwBTqJHxW5X1zRDBOA4ldqqFuKOSh6JJdrbXk1WsMN
    X/gyaVuHMBhC/g/rjtu/EnmIHoUuT9348iXeeROaLVRPdNqwr+5KEfjtTY7uXA6Q
    mhRUn+XmDePKRucRHYkcQaFPnzglrQ120Dh6aXD4PbtJMWajJtzTMvtEo9pNZhoM
    QTNZNoM=
    -----END TACK PRIVATE KEY-----"""
        publicKey = a2b_hex("87301842fe0feb8edbbf1279881e852e"
                            "4fddf8f225de79139a2d544f74dab0af"
                            "ee4a11f8ed4d8eee5c0e909a14549fe5"
                            "e60de3ca46e7111d891c41a14f9f3825")
        privateKey = a2b_hex("fc815de8b1de13a436e9cd69742cbf2c"
                             "d4c1c9bb33e023401d9291cf2781b754")
        kf = TackKeyFile.createFromPem(s, "asdf")
        assert(kf.getPublicKey().getRawKey() == publicKey)
        assert(kf.getPrivateKey().getRawKey() == privateKey)
        kf2 = TackKeyFile.createFromPem(kf.serializeAsPem(), "asdf")
        assert(kf2.getPublicKey().getRawKey() == publicKey)
        assert(kf2.getPrivateKey().getRawKey() == privateKey)
        kf3 = TackKeyFile.createRandom("123")
        kf4 = TackKeyFile.createFromPem(kf3.serializeAsPem(), "123")
        assert(kf3.getPublicKey().getRawKey() == kf4.getPublicKey().getRawKey())

if __name__ == '__main__':
    unittest.main()