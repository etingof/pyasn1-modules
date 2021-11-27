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
from pyasn1_alt_modules import rfc9174


class DTNTCPCPEKUTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIC1zCCAl2gAwIBAgIJAKWzVCgbsG5NMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjEwMTE2MjAxMTI5WhcNMjIwMTE2MjAxMTI5WjBaMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xEDAOBgNVBAoTB0V4
YW1wbGUxGjAYBgNVBAMTEWR0bjQ4LmV4YW1wbGUuY29tMHYwEAYHKoZIzj0CAQYF
K4EEACIDYgAE8FF2VLHojmqlnawpQwjG6fWBQDPOy05hYq8oKcyg1PXH6kgoO8wQ
yKYVwsDHEvc1Vg6ErQm3LzdI8OQpYx3H386R2F/dT/PEmUSdcOIWsB4zrFsbzNwJ
GIGeZ33ZS+xGo4IBCDCCAQQwCwYDVR0PBAQDAgeAMEIGCWCGSAGG+EIBDQQ1FjNU
aGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0cnVzdGVkIGZvciBhbnkgcHVycG9z
ZS4wHQYDVR0OBBYEFPI12zQE2qVV8r1pA5mwYuziFQjBMB8GA1UdIwQYMBaAFPI1
2zQE2qVV8r1pA5mwYuziFQjBMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcD
IzAcBgNVHREEFTATghFkdG40OC5leGFtcGxlLmNvbTA0BggrBgEFBQcBAQQoMCYw
JAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmV4YW1wbGUuY29tLzAKBggqhkjOPQQD
AwNoADBlAjBrZPOd8T+aWNaik+7p/9TVHCD49n9Dvb3Vs2JfZzPA3Q2Is0jK6aJI
uHZfAh1QybsCMQC+sRcTa8IoiD5naC26IseGjn+V0vizzUcibyU81fikjZAN1F/j
m94qsr2FXsRt1T0=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                    ekus, rest = der_decoder(
                        extn['extnValue'], rfc5280.ExtKeyUsageSyntax())
                    self.assertFalse(rest)
                    self.assertTrue(ekus.prettyPrint())
                    self.assertEqual(extn['extnValue'], der_encoder(ekus))
            
                    self.assertIn(rfc9174.id_kp_bundleSecurity, ekus)
                    found = True

        self.assertTrue(found)

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
