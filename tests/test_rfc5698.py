#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5698
from pyasn1_alt_modules import opentypemap


class DSSCTestCase(unittest.TestCase):
    pem_text = """\
MIIEMwYIKwYBBQULAQagggQlMIIEITAoDCZFdmFsdWF0aW9uIG9mIGNyeXB0b2dy
YXBoaWMgYWxnb3JpdGhtczAbDBlTb21lIEV2YWx1YXRpb24gQXV0aG9yaXR5GA8y
MDA5MDEwMTAwMDAwMFoMHkRpZ2l0YWwgc2lnbmF0dXJlIHZlcmlmaWNhdGlvbjCC
A6UwKTAQDAVTSEEtMaAHBgUrDgMCGjAVMBOhEYEPMjAwODA2MzAwMDAwMDBaMC8w
FgwHU0hBLTI1NqALBglghkgBZQMEAgEwFTAToRGBDzIwMTQxMjMxMDAwMDAwWjAv
MBYMB1NIQS01MTKgCwYJYIZIAWUDBAIDMBUwE6ERgQ8yMDE0MTIzMTAwMDAwMFow
bjASDANSU0GgCwYJKoZIhvcNAQEBMFgwKqAVMBMMDW1vZHVsdXNsZW5ndGiAAgQA
oRGBDzIwMDgwNjMwMDAwMDAwWjAqoBUwEwwNbW9kdWx1c2xlbmd0aIACCAChEYEP
MjAxNDEyMzEwMDAwMDBaMH4wEAwDRFNBoAkGByqGSM44BAEwajAzoB4wDQwHcGxl
bmd0aIACBAAwDQwHcWxlbmd0aIACAKChEYEPMjAwODA2MzAwMDAwMDBaMDOgHjAN
DAdwbGVuZ3RogAIIADANDAdxbGVuZ3RogAIA4KERgQ8yMDE0MTIzMTAwMDAwMFow
gYUwKQwaUEtDUyMxIHYxLjUgU0hBLTEgd2l0aCBSU0GgCwYJKoZIhvcNAQEFMFgw
KqAVMBMMDW1vZHVsdXNsZW5ndGiAAgQAoRGBDzIwMDgwMzMxMDAwMDAwWjAqoBUw
EwwNbW9kdWx1c2xlbmd0aIACCAChEYEPMjAwODA2MzAwMDAwMDBaMIGHMCsMHFBL
Q1MjMSB2MS41IFNIQS0yNTYgd2l0aCBSU0GgCwYJKoZIhvcNAQELMFgwKqAVMBMM
DW1vZHVsdXNsZW5ndGiAAgQAoRGBDzIwMDgwMzMxMDAwMDAwWjAqoBUwEwwNbW9k
dWx1c2xlbmd0aIACCAChEYEPMjAxNDEyMzEwMDAwMDBaMIGHMCsMHFBLQ1MjMSB2
MS41IFNIQS01MTIgd2l0aCBSU0GgCwYJKoZIhvcNAQENMFgwKqAVMBMMDW1vZHVs
dXNsZW5ndGiAAgQAoRGBDzIwMDgwMzMxMDAwMDAwWjAqoBUwEwwNbW9kdWx1c2xl
bmd0aIACCAChEYEPMjAxNDEyMzEwMDAwMDBaMIGJMBsMDlNIQS0xIHdpdGggRFNB
oAkGByqGSM44BAMwajAzoB4wDQwHcGxlbmd0aIACBAAwDQwHcWxlbmd0aIACAKCh
EYEPMjAwNzEyMzEwMDAwMDBaMDOgHjANDAdwbGVuZ3RogAIIADANDAdxbGVuZ3Ro
gAIA4KERgQ8yMDA4MDYzMDAwMDAwMFo=
"""

    def setUp(self):
        self.asn1Spec = rfc5698.SecuritySuitabilityPolicy()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc5698.id_ct_dssc, asn1Object['contentType'])
        tbsp, rest = der_decoder(
            asn1Object['content'], asn1Spec=rfc5698.TBSPolicy())
        self.assertFalse(rest)
        self.assertTrue(tbsp.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(tbsp))

        self.assertEqual(1, tbsp['version'])

    def testOpenTypes(self):
        cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')
        self.assertIn(rfc5698.id_ct_dssc, cmsContentTypesMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc5698.id_ct_dssc, asn1Object['contentType'])
        self.assertEqual(1, asn1Object['content']['version'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
