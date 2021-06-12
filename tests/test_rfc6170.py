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
from pyasn1_alt_modules import rfc6170
from pyasn1_alt_modules import rfc3709


class LogoCertImageOIDTestCase(unittest.TestCase):
    pem_text = "BggrBgEFBQcUAw=="

    def setUp(self):
        self.asn1Spec = univ.ObjectIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc3709.id_logo_certImage, asn1Object)
        self.assertEqual(rfc6170.id_logo_certImage, asn1Object)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
