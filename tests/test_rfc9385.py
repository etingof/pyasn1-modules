#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.type import univ

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc9385


class GostR34102012256OIDTestCase(unittest.TestCase):
    gost3410_2012_256_oid_pem_text = "BggqhQMHAQEDAg=="

    def setUp(self):
        self.asn1Spec = univ.ObjectIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.gost3410_2012_256_oid_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        self.assertEqual(
            rfc9385.id_tc26_signwithdigest_gost3410_12_256, asn1Object)


class GostR34102012512OIDTestCase(unittest.TestCase):
    gost3410_2012_512_oid_pem_text = "BggqhQMHAQEDAw=="

    def setUp(self):
        self.asn1Spec = univ.ObjectIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.gost3410_2012_512_oid_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        self.assertEqual(
            rfc9385.id_tc26_signwithdigest_gost3410_12_512, asn1Object)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
