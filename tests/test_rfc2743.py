#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc2743


class GSSAPITestCase(unittest.TestCase):
    pem_text = """\
YH4GBisGAQUFAqB0MHKgRDBCBgkqhkiC9xIBAgIGCSqGSIb3EgECAgYGKoVwKw4D
BgYrBgEFBQ4GCisGAQQBgjcCAgoGBisFAQUCBwYGKwYBBQIFoyowKKAmGyRub3Rf
ZGVmaW5lZF9pbl9SRkM0MTc4QHBsZWFzZV9pZ25vcmU=
"""

    def setUp(self):
        self.asn1Spec = rfc2743.InitialContextToken()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertEqual(
            asn1Object['thisMech'], univ.ObjectIdentifier('1.3.6.1.5.5.2'))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
