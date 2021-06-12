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
from pyasn1_alt_modules import rfc2528


class KEACertificateTestCase(unittest.TestCase):
    kea_cert_pem_text = """\
MIICizCCAjOgAwIBAgIUY8xt3l0B9nIPWSpjs0hDJUJZmCgwCQYHKoZIzjgEAzA/
MQswCQYDVQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xETAP
BgNVBAoTCEJvZ3VzIENBMB4XDTE5MTAyMDIwMDkyMVoXDTIwMTAxOTIwMDkyMVow
cDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQHEwdIZXJuZG9uMRAw
DgYDVQQKEwdFeGFtcGxlMQ4wDAYDVQQDEwVBbGljZTEgMB4GCSqGSIb3DQEJARYR
YWxpY2VAZXhhbXBsZS5jb20wgaAwFwYJYIZIAWUCAQEWBApc+PEn5ladbYizA4GE
AAKBgB9Lc2QcoSW0E9/VnQ2xGBtpYh9MaDUBzIixbN8rhDwh0BBesD2TwHjzBpDM
2PJ6DD1ZbBcz2M3vJaIKoZ8hA2EUtbbHX1BSnVfAdeqr5St5gfnuxSdloUjLQlWO
rOYfpFVEp6hJoKAZiYfiXz0fohNXn8+fiU5k214byxlCPlU0o4GUMIGRMAsGA1Ud
DwQEAwIDCDBCBglghkgBhvhCAQ0ENRYzVGhpcyBjZXJ0aWZpY2F0ZSBjYW5ub3Qg
YmUgdHJ1c3RlZCBmb3IgYW55IHB1cnBvc2UuMB0GA1UdDgQWBBSE49bkPB9sQm27
Rs2jgAPMyY6UCDAfBgNVHSMEGDAWgBTNSGUBg7KmB1sG/iOBDMRz5NG1ODAJBgcq
hkjOOAQDA0cAMEQCIE9PWhUbnJVdNQcVYSc36BMZ+23uk2ITLsgSXtkScF6TAiAf
TPnJ5Wym0hv2fOpnPPsWTgqvLFYfX27GGTquuOd/6A==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.kea_cert_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        ai = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc2528.id_keyExchangeAlgorithm, ai['algorithm'])

        param, rest = der_decoder(
            ai['parameters'], asn1Spec=rfc2528.KEA_Parms_Id())
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(ai['parameters'], der_encoder(param))
        
        self.assertEqual(
            univ.OctetString(hexValue='5cf8f127e6569d6d88b3'), param)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.kea_cert_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        ai = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc2528.id_keyExchangeAlgorithm, ai['algorithm'])

        param = ai['parameters']
        self.assertEqual(
            univ.OctetString(hexValue='5cf8f127e6569d6d88b3'), param)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
