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
from pyasn1_alt_modules import rfc8995


class MASAURLCertExtnTestCase(unittest.TestCase):
    pem_text = """\
MIIC0DCCATigAwIBAgIEKuxB1DANBgkqhkiG9w0BAQsFADAmMSQwIgYDVQQDDBto
aWdod2F5LXRlc3QuZXhhbXBsZS5jb20gQ0EwIBcNMjEwNDI2MTUxNjEwWhgPMjk5
OTEyMzEwMDAwMDBaMBwxGjAYBgNVBAUTETAwLUQwLUU1LUYyLTAwLTAyMFkwEwYH
KoZIzj0CAQYIKoZIzj0DAQcDQgAEA6N1Q4ezfMAKmoecrfb0OBMc1AyEH+BATkF5
8FsTSyBxs0SbSWLxFjDOuwB9gLGn2TsTUJumJ6VPw5Z/TP4hJ6NZMFcwHQYDVR0O
BBYEFEWIzJaWAGQ3sLojZWRkVAgGbFatMAkGA1UdEwQCMAAwKwYIKwYBBQUHASAE
HxYdaGlnaHdheS10ZXN0LmV4YW1wbGUuY29tOjk0NDMwDQYJKoZIhvcNAQELBQAD
ggGBAEN+iEvt/mGl86llrEdHxcZDGk7jRP0K2aKssgL7M54ggz1zhsCOA+xsYaO/
0JN0xlj9BzDxrH6M0qcM7OX7MP8vikbtAdFUMAnmxKSxaJ756IysYkRv3gFz4Bkq
odEKQqTTeBQbnCHv0QGSGI9QLlFBRJqS6ejNHZ4JtAufttHNBSyGX5+h8wcbNfKm
txJwUTmA6qaRs93eWOo5YLdadpzNOCScUe14RuPdwAvjUoOTwLAvY0HtQywaOxPN
sWlS8OxuIS6pYtCNqRHLVURVSa9cOXj94LfqwewgJbm4Fj5wFIr3qooJYYDLgBaH
4J3UaIoXIKenrb5gSWlEVmgrrACuPW9+o4VqzaDEnSTpV2xoH5gbyBzyVzEZI6FK
6dmXahYsD9rwhpxP94JbxZmiZa+HnqdZwywVYpe/ECqWY+pDCv/E2DM2EnquwGmC
TmQ91wFDHP6bhSSJpaORPGu/K2HUcpMDhIwBUkKkTESDUZ/Fyv+karPxm4dGqDNb
g7Q2Ew==
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
            if extn['extnID'] == rfc8995.id_pe_masa_url:
                extn_value, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                self.assertFalse(rest)
                self.assertTrue(extn_value.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extn_value))
                self.assertIn('example.com', extn_value)
                found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
