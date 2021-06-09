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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4059


class WarrantyCertificateTestCase(unittest.TestCase):
    pem_text = """\
MIIC7DCCAnKgAwIBAgIJAKWzVCgbsG5OMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMjEwMTMwMTc0ODMyWhcNMjIwMTMwMTc0ODMyWjBuMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3NlMSAwHgYDVQQKExdC
b2d1cyBDb21tZXJjZSBTZXJ2aWNlczEdMBsGA1UEAxMUY29tbWVyY2UuZXhhbXBs
ZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASkrm8xpNVoCIOngV5bYdgp+o65
QBsYW4enstEkzfDz4ol4/NiF0IeFAKc3dZlTzk5DK3QldD46TEa8BUU5FiDVoZWj
9SnUbAP5qpHpbdH5m0wGmdZ3WY4Pwm5KTl8XX3CjggEJMIIBBTALBgNVHQ8EBAMC
B4AwQgYJYIZIAYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRy
dXN0ZWQgZm9yIGFueSBwdXJwb3NlLjAJBgNVHRMEAjAAMB0GA1UdDgQWBBS/dszg
PxHYt3vq+ckyOek0e4OpcDAfBgNVHSMEGDAWgBTyNds0BNqlVfK9aQOZsGLs4hUI
wTBnBggrBgEFBQcBEARbMFkwEwUAMAwCAgNIAgNKC0YCAQICAQAWQmh0dHBzOi8v
aW1nLmh1ZmZpbmd0b25wb3N0LmNvbS9hc3NldC81NWE2NzAyZDEyMDAwMDJiMDAx
MzRhZGQuanBlZzAKBggqhkjOPQQDAwNoADBlAjEAjweTyuXOCzWYRNwBXk+tM8/r
X/kfGlB5igFOcTuTrQJwJgQpdt5oGVXzwBgrAckDAjBbQJzl+k9IhBFYvBwmlmTj
SNZvBmsBe5D+PlZZF/XpJ21bf6HPAGkBMMDNPdTdKXk=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc4059.id_pe_warranty_extn:
                self.assertIn(extn['extnID'], rfc5280.certificateExtensionsMap)
                ev, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(ev.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(ev))
                self.assertEqual(840, ev['wData']['base']['amount']['currency'])
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
