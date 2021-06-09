#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9044


class AuthenticatedDataGMAC128TestCase(unittest.TestCase):
    pem_text = """\
MIIBHQYLKoZIhvcNAQkQAQKgggEMMIIBCAIBADFRok8CAQQwIwQQ+28rOVL9dEnS
mPaKpLzZTRgPMjAyMDExMTAxMjAwMDBaMAsGCWCGSAFlAwQBLQQYDMG1WyligADX
AF3DS35MotxnNdU65N7xMBsGCWCGSAFlAwQBCTAOBAy9T+z9c30p5UGfMH6hCwYJ
YIZIAWUDBAIBMCsGCSqGSIb3DQEHAaAeBBxUaGlzIGlzIHNvbWUgc2FtcGxlIGNv
bnRlbnQuokswGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAvBgkqhkiG9w0BCQQx
IgQgyHXfKkIQcEqe3du238yHBHEWj5BNGDMYu/GErAsEXlMEDIbpDtygvp/XTdWc
Nw==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        ad, rest = der_decoder(
            asn1Object['content'],
            asn1Spec=rfc5652.AuthenticatedData())

        self.assertFalse(rest)
        self.assertTrue(ad.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(ad))

        self.assertEqual(0, ad['version'])
        self.assertEqual(
            rfc9044.id_aes128_GMAC,
            ad['macAlgorithm']['algorithm'])

        param, rest = der_decoder(
            ad['macAlgorithm']['parameters'],
            asn1Spec=rfc9044.GCMParameters())

        self.assertFalse(rest)
        self.assertTrue(ad.prettyPrint())
        self.assertEqual(ad['macAlgorithm']['parameters'], der_encoder(param))

        iv = univ.OctetString(hexValue='bd4fecfd737d29e5419f307e')
        self.assertEqual(iv, param['nonce'])
        self.assertEqual(12, param['length'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
                               asn1Spec=self.asn1Spec,
                               decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        ad = asn1Object['content']
        self.assertEqual(0, ad['version'])
        self.assertEqual(
            rfc9044.id_aes128_GMAC,
            ad['macAlgorithm']['algorithm'])

        param = ad['macAlgorithm']['parameters']
        iv = univ.OctetString(hexValue='bd4fecfd737d29e5419f307e')
        self.assertEqual(iv, param['nonce'])
        self.assertEqual(12, param['length'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
