#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc9189


# RFC 9189 Section A.1.3.1

class RFC9189FirstTestCase(unittest.TestCase):
    a131_pem_text = """\
MIGSBCjX8PBCI2eGeyX6QjOpVPWL3pLpybv7iBbJnxXmOYcioLK3v+hJPppcMGYw
HwYIKoUDBwEBAQEwEwYHKoUDAgIjAQYIKoUDBwEBAgIDQwAEQJMH4JjBcYjx8Ud/
77h/rvG7zZVnOxuPlwOiYtJjbfOoh/gUH+rCWhfMtZYEYe0WsPixvpNZQ5WhDmSF
RGtdyjQ=
"""

    def setUp(self):
        self.asn1Spec = rfc9189.GostKeyTransport()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.a131_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        oid = asn1Object['ephemeralPublicKey']['algorithm']['algorithm']
        self.assertEqual(univ.ObjectIdentifier('1.2.643.7.1.1.1.1'), oid)


# RFC 9189 Section A.1.3.2

class RFC9189SecondTestCase(unittest.TestCase):
    a132_pem_text = """\
MIHfBDAlDRtnonCrBNP2VBjh04C0y5RfCj3KUVAM86G+8392wHNBqYOcz2y6cYna
YetnF2wwgaowIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIDBggqhQMHAQECAwOBhAAE
gYDGW9cFtoYBmLrUpw65N7a0gITiYK33sQdKiRgoYsW//mSGKDVBMwsVD+SKc3yz
5bsEPkoRNANabUebGJNRvkHJvpp+KvwkYnb+TiNWhFKTsDF44uwAPKioFDJPFjUL
wKtTQYfehsdr4pqUCo2yrXFkaqDJUv30ESBlSIE+ufdUoQ==
"""

    def setUp(self):
        self.asn1Spec = rfc9189.GostKeyTransport()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.a132_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        oid = asn1Object['ephemeralPublicKey']['algorithm']['algorithm']
        self.assertEqual(univ.ObjectIdentifier('1.2.643.7.1.1.1.2'), oid)


# RFC 9189 Section A.2.2

class RFC9189ThirdTestCase(unittest.TestCase):
    a22_pem_text = """\
MIHyMIHvMCgEINYi0WelZC4pUlopXLnyj5byiw76p9OivuFJsBF4wt/VBARMkzZX
oIHCBgkqhQMHAQIFAQGggaowIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMH
AQECAwOBhAAEgYD7S/irn3GnpmJXDHfDOWHdYPw8FZUBtdIjs7OhsxWoSdxwgaCt
WeXlgkgi9uhr7yr+W9l/LTvkk+Q3x7yBs5xL0PuUAS6veg1kxCL39Wgtz3JoPaUn
VIrrKl32c0nQ3UJsq8UTANq/YSDS64UNfbd3CpbkhBy1/O6lRsiSg/LOlQQI+/Od
EOgAr3A=
"""

    def setUp(self):
        self.asn1Spec = rfc9189.TLSGostKeyTransportBlob()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.a22_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        oid = asn1Object['keyBlob']['transportParameters'] \
                  ['ephemeralPublicKey']['algorithm']['algorithm']
        self.assertEqual(univ.ObjectIdentifier('1.2.643.7.1.1.1.2'), oid)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
