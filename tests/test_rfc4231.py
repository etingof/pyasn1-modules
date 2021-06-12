#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2020-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc4231


class AuthenticatedDataHMACTestCase(unittest.TestCase):
    pem_text = """\
MIIBPAYLKoZIhvcNAQkQAQKgggErMIIBJwIBADFromkCAQQwIwQQ+28rOVL9dEnS
mPaKpLzZTRgPMjAyMDExMTAxMjAwMDBaMA0GCyqGSIb3DQEJEAMMBDAStUZBHNYL
oY34HUBosaOl5d2XDHF6Bf/z344mbKUYO7HAiQk9Z9SPuW6Mouv96wEwDAYIKoZI
hvcNAgkFAKELBglghkgBZQMEAgEwKwYJKoZIhvcNAQcBoB4EHFRoaXMgaXMgc29t
ZSBzYW1wbGUgY29udGVudC6iSzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMC8G
CSqGSIb3DQEJBDEiBCDIdd8qQhBwSp7d27bfzIcEcRaPkE0YMxi78YSsCwReUwQg
SKsIer5tGtrwyn32lCEg+97txfgu+ZVVfpyZm74euek=
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
        mac_alg = ad['macAlgorithm']
        self.assertEqual(rfc4231.id_hmacWithSHA256, mac_alg['algorithm'])

        param, rest = der_decoder(mac_alg['parameters'], asn1Spec=univ.Null())
        assert not rest
        assert der_encoder(param) == mac_alg['parameters']

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
        mac_alg = ad['macAlgorithm']
        self.assertEqual(rfc4231.id_hmacWithSHA256, mac_alg['algorithm'])
        self.assertEqual(univ.Null(""), mac_alg['parameters'])

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
