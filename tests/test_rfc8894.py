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

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc8894


class IssuerAndSubjectTestCase(unittest.TestCase):
    pem_text = """\
MIGzMD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRv
bjERMA8GA1UECgwIQm9ndXMgQ0EwcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZB
MRAwDgYDVQQHEwdIZXJuZG9uMRAwDgYDVQQKEwdFeGFtcGxlMQ4wDAYDVQQDEwVB
bGljZTEgMB4GCSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20=
"""

    def setUp(self):
        self.asn1Spec = rfc8894.IssuerAndSubject()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        emailAttr = asn1Object['subject']['rdnSequence'][5][0]
        oid = univ.ObjectIdentifier('1.2.840.113549.1.9.1')
        self.assertEqual(oid, emailAttr['type'])

        email, rest = der_decoder(emailAttr['value'], asn1Spec=char.IA5String())
        self.assertFalse(rest)
        self.assertTrue(email.prettyPrint())
        self.assertEqual(emailAttr['value'], der_encoder(email))

        self.assertEqual('alice@example.com', email)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        emailAttr = asn1Object['subject']['rdnSequence'][5][0]
        oid = univ.ObjectIdentifier('1.2.840.113549.1.9.1')
        self.assertEqual(oid, emailAttr['type'])
        self.assertEqual('alice@example.com', emailAttr['value'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
