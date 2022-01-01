#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2020-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc5794


class SMIMECapabilitiesTestCase(unittest.TestCase):
    pem_text = """\
MIGtMBAGCSqDGoyabgEBATADDQEBMBkGCSqDGoyabgEBAjAMBgorBgEEAYGsYDBP
MBcGCSqDGoyabgEBAzAKAgIAgAIBQAIBIDAQBgkqgxqMmm4BAQQwAwIBIDAOBgkq
gxqMmm4BARUCAWAwFAYJKoMajJpuAQEiMAcCAgCAAgFgMBMGCSqDGoyabgEBJTAG
AgEIAgFgMAsGCSqDGoyabgEBKDALBgkqgxqMmm4BASs=
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        alg_oid_list = [ ]
        for cap in asn1Object:
            capOID = cap['capabilityID']
            alg_oid_list.append(capOID)

            if cap['parameters'].hasValue():
                self.assertIn(capOID, rfc5280.algorithmIdentifierMap)
                param, rest = der_decoder(cap['parameters'],
                    asn1Spec=rfc5280.algorithmIdentifierMap[capOID])
                self.assertFalse(rest)
                self.assertTrue(param.prettyPrint())
                self.assertEqual(cap['parameters'], der_encoder(param))

        self.assertEqual(9, len(alg_oid_list))

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        for cap in asn1Object:
            count += 1
            capOID = cap['capabilityID']
            if cap['parameters'].hasValue():
                self.assertIn(capOID, rfc5280.algorithmIdentifierMap)

        self.assertEqual(9, count)


class EncryptedDataBogusPadTestCase(unittest.TestCase):
    pem_text = """\
MIIFkAYJKoZIhvcNAQcDoIIFgTCCBX0CAQIxWqJYAgEEMCQEEDiCUYXKXu8SzLos
n2xeYP4YEDIwMjAwOTEwODEyMDAwMFowCwYJKoMajJpuAQEqBCCh8LBZuLKwVns7
LxY59rh49JIEq25KH5GnMblbSVUanTCCBRoGCSqGSIb3DQEHATAZBgkqgxqMmm4B
AQIwDAYKKwYBBAGBrGAwT4CCBPBGQUtFX0lWX0ZBS0VfSVYhc8exehjJD/gtEOIr
g6tK5Emaa4PJ7l8f+EtyDD/ffQayXVAGz2MXUIQMEzmSLrnsr9NEyXvxGpvcsi7m
V8tDxZU0YuyhA/C/HMh7EaBKG1hjC7xNw+IRIUxrbRJakMQbzMWWYJupC5zRu4/G
e9i+JVOGgES2E0L5LZSZ53wmnHA0ols1PHl3F3Z2QM3CkewqA3NP1waXQ0XXb0Oy
l6Gq12B7ksm7euPWA3KctEjfYBD6nBT6wQd57rAMeFTk5aceWd2Sb/0xMpjfCg6G
zX8pAWVEU8LqTvVmlSWdx3f3fAtUgiZ+gx7jNY8A6duln8zvMQn3mtPDCa50GzSr
Ax8JreHRWSDr3Dp8EfJzUgfy7dWlI9xs5bh1TMkEMk+AHWQ5sBXTZkDgVAS5m1mI
bXe7dzuxKsfGxjWu1eyy9J77mtOGo9aAOqYfxv/I8YQcgWHTeQcIO39Rmt2QsI7t
rRaEJ1jgj2E1To5gRCbIQWzQuyoS6affgu/9dwPXCAt0+0XrnO5vhaKX/RWm7ve8
hYsiT0vI0hdBJ3rDRkdS9VL6NlnXOuohAqEq8b3s2koBigdri052hceAElTHD+4A
4qRDiMLlFLlQqoJlpBwCtEPZsIQSy62K7J/Towxxab5FoFjUTC5f79xPQPoKxYdg
UB5AeAu5HgdWTn49Uqg4v/spTPSNRTmDMVVyZ9qhzJfkDpH3TKCAE5t59w4gSPe/
7l+MeSml9O+L9HTd9Vng3LBbIds3uQ4cfLyyQmly81qpJjR1+Rvwo46hOm0kf2sI
Fi0WULmP/XzLw6b1SbiHf/jqFg7TFTyLMkPMPMmc7/kpLmYbKyTB4ineasTUL+bD
rwu+uSzFAjTcI+1sz4Wo4p7RVywBDKSI5Ocbd3iMt4XWJWtz0KBX6nBzlV+BBTCw
aGMAU4IpPBYOuvcl7TJWx/ODBjbO4zm4T/66w5IG3tKpsVMs4Jtrh8mtVXCLTBmK
DzyjBVN2X8ALGXarItRgLa7k80lJjqTHwKCjiAMmT/eh67KzwmqBq5+8rJuXkax0
NoXcDu6xkCMNHUQBYdnskaJqC2pu8hIsPTOrh7ieYSEuchFvu7lI0E+p7ypW65CM
iy+Y/Rm5OWeHzjKkU5AbPtx/Me2vpQRCgaPwciZunx2Ivi1+WYUBU1pGNDO7Xz7a
8UHbDURkh7b+40uz2d7YQjKgrZBv6YwLAmw1LTE4bT9PM9n7LROnX8u6ksei8yiw
8gZeVu+plWHbF+0O9siKAgxZlBna0XFgPpdzjMDTS/sfTIYXWlFj7camhsmTDRjo
5G2B212evaKmKgh5ALLSFSk86ZN5KvQvcfsp81jvJCBmDStrsUgSMzy0Og2quHOd
61hRTVlYzwvJvfMzHGKdIWwYUbHZOKo/KLEk3E36U9PkPoZGEL2ZeCH4F9Wh3mgg
0knBfEmlPnGexmBby6NXGK7VW3l6xcJlpdMaXKNVMfl2YK8k/34Hyft06KaYLEJs
xAqk1pmLEmGhdZC1OAqovVB/1agSzpMMaB9OWWqNsTjDc7tkDt8BZ72NsAbCI9Xm
sX81W+NqPb6Ju1dtI09bn113LX/ZbOSdVicQcXSpl0FnTZaHgHJdQLcU28O7yFFO
blqrvcMKpctdTA1TwG9LXEFttGrlpgjZF3edo0Cez10epK+S
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc5652.id_envelopedData, asn1Object['contentType'])

        ed, rest = der_decoder(asn1Object['content'],
                               asn1Spec=rfc5652.EnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(ed.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(ed))

        kwa = ed['recipientInfos'][0]['kekri']['keyEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria256_kw, kwa['algorithm'])

        cea = ed['encryptedContentInfo']['contentEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria128_cbc, cea['algorithm'])

        param, rest = der_decoder(cea['parameters'],
                                  asn1Spec=rfc5794.AriaCbcParameters())
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(cea['parameters'], der_encoder(param))

        id_bogus_pad_alg = univ.ObjectIdentifier('1.3.6.1.4.1.22112.48.79')
        self.assertEqual(id_bogus_pad_alg, param['padAlgo']['generalPadAlgo'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        kekri = asn1Object['content']['recipientInfos'][0]['kekri']
        kwa = kekri['keyEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria256_kw, kwa['algorithm'])

        eci = asn1Object['content']['encryptedContentInfo']
        cea = eci['contentEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria128_cbc, cea['algorithm'])

        id_bogus_pad_alg = univ.ObjectIdentifier('1.3.6.1.4.1.22112.48.79')
        gpa = cea['parameters']['padAlgo']['generalPadAlgo']
        self.assertEqual(id_bogus_pad_alg, gpa)

class EncryptedDataDefaultPadTestCase(unittest.TestCase):
    pem_text = """\
MIIFhAYJKoZIhvcNAQcDoIIFdTCCBXECAQIxWqJYAgEEMCQEEDiCUYXKXu8SzLos
n2xeYP4YEDIwMjAwOTEwODEyMDAwMFowCwYJKoMajJpuAQEqBCCh8LBZuLKwVns7
LxY59rh49JIEq25KH5GnMblbSVUanTCCBQ4GCSqGSIb3DQEHATANBgkqgxqMmm4B
AQIwAICCBPBGQUtFX0lWX0ZBS0VfSVYhc8exehjJD/gtEOIrg6tK5Emaa4PJ7l8f
+EtyDD/ffQayXVAGz2MXUIQMEzmSLrnsr9NEyXvxGpvcsi7mV8tDxZU0YuyhA/C/
HMh7EaBKG1hjC7xNw+IRIUxrbRJakMQbzMWWYJupC5zRu4/Ge9i+JVOGgES2E0L5
LZSZ53wmnHA0ols1PHl3F3Z2QM3CkewqA3NP1waXQ0XXb0Oyl6Gq12B7ksm7euPW
A3KctEjfYBD6nBT6wQd57rAMeFTk5aceWd2Sb/0xMpjfCg6GzX8pAWVEU8LqTvVm
lSWdx3f3fAtUgiZ+gx7jNY8A6duln8zvMQn3mtPDCa50GzSrAx8JreHRWSDr3Dp8
EfJzUgfy7dWlI9xs5bh1TMkEMk+AHWQ5sBXTZkDgVAS5m1mIbXe7dzuxKsfGxjWu
1eyy9J77mtOGo9aAOqYfxv/I8YQcgWHTeQcIO39Rmt2QsI7trRaEJ1jgj2E1To5g
RCbIQWzQuyoS6affgu/9dwPXCAt0+0XrnO5vhaKX/RWm7ve8hYsiT0vI0hdBJ3rD
RkdS9VL6NlnXOuohAqEq8b3s2koBigdri052hceAElTHD+4A4qRDiMLlFLlQqoJl
pBwCtEPZsIQSy62K7J/Towxxab5FoFjUTC5f79xPQPoKxYdgUB5AeAu5HgdWTn49
Uqg4v/spTPSNRTmDMVVyZ9qhzJfkDpH3TKCAE5t59w4gSPe/7l+MeSml9O+L9HTd
9Vng3LBbIds3uQ4cfLyyQmly81qpJjR1+Rvwo46hOm0kf2sIFi0WULmP/XzLw6b1
SbiHf/jqFg7TFTyLMkPMPMmc7/kpLmYbKyTB4ineasTUL+bDrwu+uSzFAjTcI+1s
z4Wo4p7RVywBDKSI5Ocbd3iMt4XWJWtz0KBX6nBzlV+BBTCwaGMAU4IpPBYOuvcl
7TJWx/ODBjbO4zm4T/66w5IG3tKpsVMs4Jtrh8mtVXCLTBmKDzyjBVN2X8ALGXar
ItRgLa7k80lJjqTHwKCjiAMmT/eh67KzwmqBq5+8rJuXkax0NoXcDu6xkCMNHUQB
YdnskaJqC2pu8hIsPTOrh7ieYSEuchFvu7lI0E+p7ypW65CMiy+Y/Rm5OWeHzjKk
U5AbPtx/Me2vpQRCgaPwciZunx2Ivi1+WYUBU1pGNDO7Xz7a8UHbDURkh7b+40uz
2d7YQjKgrZBv6YwLAmw1LTE4bT9PM9n7LROnX8u6ksei8yiw8gZeVu+plWHbF+0O
9siKAgxZlBna0XFgPpdzjMDTS/sfTIYXWlFj7camhsmTDRjo5G2B212evaKmKgh5
ALLSFSk86ZN5KvQvcfsp81jvJCBmDStrsUgSMzy0Og2quHOd61hRTVlYzwvJvfMz
HGKdIWwYUbHZOKo/KLEk3E36U9PkPoZGEL2ZeCH4F9Wh3mgg0knBfEmlPnGexmBb
y6NXGK7VW3l6xcJlpdMaXKNVMfl2YK8k/34Hyft06KaYLEJsxAqk1pmLEmGhdZC1
OAqovVB/1agSzpMMaB9OWWqNsTjDc7tkDt8BZ72NsAbCI9XmsX81W+NqPb6Ju1dt
I09bn113LX/ZbOSdVicQcXSpl0FnTZaHgHJdQLcU28O7yFFOblqrvcMKpctdTA1T
wG9LXEFttGrlpgjZF3edo0Cez10epK+S
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(rfc5652.id_envelopedData, asn1Object['contentType'])

        ed, rest = der_decoder(asn1Object['content'],
                               asn1Spec=rfc5652.EnvelopedData())
        self.assertFalse(rest)
        self.assertTrue(ed.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(ed))

        kwa = ed['recipientInfos'][0]['kekri']['keyEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria256_kw, kwa['algorithm'])

        cea = ed['encryptedContentInfo']['contentEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria128_cbc, cea['algorithm'])

        param, rest = der_decoder(cea['parameters'],
                                  asn1Spec=rfc5794.AriaCbcParameters())
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(cea['parameters'], der_encoder(param))

        self.assertEqual(1, param['m'])
        spa = param['padAlgo']['specifiedPadAlgo']
        self.assertEqual(rfc5794.id_pad_1, spa)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        # self.assertEqual(substrate, der_encoder(asn1Object))

        kekri = asn1Object['content']['recipientInfos'][0]['kekri']
        kwa = kekri['keyEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria256_kw, kwa['algorithm'])

        eci = asn1Object['content']['encryptedContentInfo']
        cea = eci['contentEncryptionAlgorithm']
        self.assertEqual(rfc5794.id_aria128_cbc, cea['algorithm'])
        self.assertEqual(1, cea['parameters']['m'])
        spa = cea['parameters']['padAlgo']['specifiedPadAlgo']
        self.assertEqual(rfc5794.id_pad_1, spa)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
