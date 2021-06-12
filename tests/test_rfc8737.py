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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc8737


class ACMEIdentifierTestCase(unittest.TestCase):
    pem_text = """\
MIIDXDCCAkSgAwIBAgIUaKWDEVneTUkvvTOZB4f4Hhbfkj0wDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAxMQdGVzdC5leGFtcGxlLmNvbTAeFw0yMDEyMjkyMjA1MjFa
Fw0yMTAxMDIyMjA1MjFaMBsxGTAXBgNVBAMTEHRlc3QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8vg/L5D+VSxSY4omMBkkZHlgg
rvM9cMHmwkAFzQwkO022DCRvYPfkvFjzbR5YqwuuZyyAeUHCgp/arIUslXQJ39W5
HEWtih/sHe5N/9u91IoDvP7Zn8OimXbC6YxKQvskJkIZ5r8Eqqwms3NIIwJ21FJz
jI3iA8GRdc7oJgMplU8GjO1PsKnW+tePOuaM7XDDUvTAazhloZRSts42K+bnh90m
vhyPZ57mDQ6EyplJU5MKZCSqzh3lfMKCwJgYEJk/CP7JwZc+/Y+ZkRQ5stXg/rTg
wh3+tkLdYIgzfVMzTuNSePUA5AjJEDK/wugIAMF7co7iZ1HbEhvI8niebv0zAgMB
AAGjgZcwgZQwMQYIKwYBBQUHAR8BAf8EIgQghzeHN4c3hzeHN4c3hzeHN4c3hzeH
N4c3hzeHN4c3hzcwQgYJYIZIAYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fu
bm90IGJlIHRydXN0ZWQgZm9yIGFueSBwdXJwb3NlLjAbBgNVHREEFDASghB0ZXN0
LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4IBAQAZdlB0TAKlgAsVqCm+Bg1j
iEA8A7ZKms6J/CYy6LB6oJPcUqVMmUMigEvWD2mIO4Q2cHwJ6Gn9Zf5jb0jhBPS2
HYGJN2wVGYmWdyB4TOWRhu122iXpKGkQZ01+knP+ueVLqYvmRGx/V3sw12mbN+PB
y+EhhFdfjfuY95qbo5yBmY7EQSKf7lXyUvFkPAtirj6lvzTEIshvS9qkj0XiMiO8
6F/d2sVhPWpD3JOxhp0D+JEYcXwfwmn6OprRUTAvCFhpC+qkQOoTa37Xy65V0435
LWIbHF0HSW/CxDQo22mHT+tMqd13NzlDN3HxurIEGU4fBjk/rMSxw/bAPf4O0QT3
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
           if extn['extnID'] == rfc8737.id_pe_acmeIdentifier:
               self.assertTrue(extn['critical'])
               self.assertIn(extn['extnID'], rfc5280.certificateExtensionsMap)
               auth, rest = der_decoder(
                   extn['extnValue'], asn1Spec=rfc8737.Authorization())
               self.assertFalse(rest)
               self.assertTrue(auth.prettyPrint())
               self.assertEqual(extn['extnValue'], der_encoder(auth))
               self.assertEqual(32, len(auth))
               found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
