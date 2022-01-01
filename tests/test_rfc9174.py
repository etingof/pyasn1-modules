#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9174


class DTNTCPCPEKUTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIB8zCCAZqgAwIBAgIUAsJMTfFzPXEjQgv8hzX61gPlLRQwCgYIKoZIzj0EAwIw
IDEeMBwGA1UEAwwVQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTIxMTAyMzAzNTgw
MFoXDTIxMTEwMjAzNTgwMFowEjEQMA4GA1UEAwwHbm9kZTAwMTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABPxKn98UjqixrgiIx3ZUpLWw3q8yFXSYM6xWJNbTWoW3
CBWL/ZjTDzb9VVhNV34O/SrL78DhXMQKaPk2kz5lnoejgb8wgbwwDAYDVR0TAQH/
BAIwADA2BgNVHREELzAtoBwGCCsGAQUFBwgLoBAWDmR0bjovL25vZGUwMDEvgg1u
b2RlMDAxLmxvY2FsMAsGA1UdDwQEAwIHgDAnBgNVHSUEIDAeBggrBgEFBQcDIwYI
KwYBBQUHAwIGCCsGAQUFBwMBMB0GA1UdDgQWBBQUnHImDKsWD19h3w4bLThvvkpC
LjAfBgNVHSMEGDAWgBR5CN7I7XeM2IgirDTmETKzGrso7zAKBggqhkjOPQQDAgNH
ADBEAiBEHt895peKHaT33NsMY7M2Ei1p9Kb7d8q2YCRGGRnbBgIgC69DqkCiw/6Y
h8+YEpY2YN5ffny5AzQLooM7DzSKJcc=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        counter = 0
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                ekus, rest = der_decoder(
                    extn['extnValue'], asn1Spec=rfc5280.ExtKeyUsageSyntax())
                self.assertFalse(rest)
                self.assertTrue(ekus.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(ekus))
        
                self.assertIn(rfc9174.id_kp_bundleSecurity, ekus)
                counter += 1

            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                san, rest = der_decoder(
                    extn['extnValue'], asn1Spec=rfc5280.SubjectAltName())
                self.assertFalse(rest)
                self.assertTrue(san.prettyPrint())
                self.assertEqual(der_encoder(san), extn['extnValue'])

                for gn in san:
                    if gn['otherName'].hasValue():
                        self.assertEqual(
                            rfc9174.id_on_bundleEID, gn['otherName']['type-id'])

                        on, rest = der_decoder(gn['otherName']['value'],
                            asn1Spec=rfc9174.BundleEID())
                        self.assertFalse(rest)
                        self.assertTrue(on.prettyPrint())
                        self.assertEqual(
                            der_encoder(on), gn['otherName']['value'])

                        self.assertIn('node001', on)
                        counter += 1

        self.assertEqual(2, counter)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        counter = 0
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                ekus, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.ExtKeyUsageSyntax(), decodeOpenTypes=True)
                self.assertFalse(rest)
                self.assertTrue(ekus.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(ekus))
        
                self.assertIn(rfc9174.id_kp_bundleSecurity, ekus)
                counter += 1

            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                san, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName(), decodeOpenTypes=True)
                self.assertFalse(rest)
                self.assertTrue(san.prettyPrint())
                self.assertEqual(der_encoder(san), extn['extnValue'])

                for gn in san:
                    if gn['otherName'].hasValue():
                        self.assertEqual(
                            rfc9174.id_on_bundleEID, gn['otherName']['type-id'])
                        self.assertIn('node001', gn['otherName']['value'])
                        counter += 1

        self.assertEqual(2, counter)

class DTNTCPCPONTestCase(unittest.TestCase):
    othername_pem_text = "oBwGCCsGAQUFBwgLoBAWDmR0bjovL2V4YW1wbGUv"

    def setUp(self):
        self.asn1Spec = rfc5280.GeneralName()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.othername_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9174.id_on_bundleEID,
            asn1Object['otherName']['type-id'])
        othername, rest = der_decoder(
            asn1Object['otherName']['value'], rfc9174.BundleEID())
        self.assertFalse(rest)
        self.assertTrue(othername.prettyPrint())
        self.assertEqual(asn1Object['otherName']['value'],
            der_encoder(othername))

        self.assertIn('example', othername)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
