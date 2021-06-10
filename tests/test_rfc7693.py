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
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc7693


class SMIMECapabilitiesTestCase(unittest.TestCase):
    pem_text = """\
MIIBXjA8BgkqhkiG9w0BAQcwL6APMA0GCWCGSAFlAwQCAgUAoRwwGgYJKoZIhvcN
AQEIMA0GCWCGSAFlAwQCAgUAMDwGCSqGSIb3DQEBCjAvoA8wDQYJYIZIAWUDBAIC
BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQAwDQYJKoZIhvcNAQELBQAw
DQYJKoZIhvcNAQEMBQAwDQYJKoZIhvcNAQENBQAwDwYLKwYBBAGNOgwCAQUFADAP
BgsrBgEEAY06DAIBCAUAMA8GCysGAQQBjToMAgEMBQAwDwYLKwYBBAGNOgwCARAF
ADAPBgsrBgEEAY06DAICBAUAMA8GCysGAQQBjToMAgIFBQAwDwYLKwYBBAGNOgwC
AgcFADAPBgsrBgEEAY06DAICCAUAMA0GCWCGSAFlAwQCAQUAMA0GCWCGSAFlAwQC
AgUAMA0GCWCGSAFlAwQCAwUA
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        blake_oids = [ rfc7693.id_blake2b160,  rfc7693.id_blake2b256,
                       rfc7693.id_blake2b384,  rfc7693.id_blake2b512,
                       rfc7693.id_blake2s128,  rfc7693.id_blake2s160,
                       rfc7693.id_blake2s224,  rfc7693.id_blake2s256, ]

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        for cap in asn1Object:
            if cap['capabilityID'] in blake_oids:
                count += 1
                self.assertIn(cap['capabilityID'],
                    rfc5280.algorithmIdentifierMap)

        self.assertEqual(len(blake_oids), count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
