#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc8994


class ACPNodeNameTestCase(unittest.TestCase):
    pem_text = """\
oE4GCCsGAQUFBwgKoEIWQGZkODliNzE0RjNkYjAwMDAwMjAwMDAwMDY0MDAwMDAw
K2FyZWE1MS5yZXNlYXJjaEBhY3AuZXhhbXBsZS5jb20=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.GeneralName()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        self.assertIn(asn1Object['otherName']['type-id'],
                      rfc5280.anotherNameMap)
        self.assertEqual(rfc8994.id_on_AcpNodeName,
                         asn1Object['otherName']['type-id'])

        acpNode, rest = der_decoder(
            asn1Object['otherName']['value'],
            asn1Spec=rfc5280.anotherNameMap[asn1Object['otherName']['type-id']])

        self.assertFalse(rest)
        self.assertTrue(acpNode.prettyPrint())
        self.assertEqual(asn1Object['otherName']['value'], der_encoder(acpNode))
        self.assertIn('example.com', acpNode)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(
            rfc8994.id_on_AcpNodeName,
            asn1Object['otherName']['type-id'])
        self.assertIn('example.com', asn1Object['otherName']['value'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
