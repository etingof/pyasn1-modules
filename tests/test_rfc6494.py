#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc6494


class CertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIDljCCAv+gAwIBAgIUV0x6DELQ4jdGSHcm0QFEbGWEj38wDQYJKoZIhvcNAQEF
BQAwUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQHEwdIZXJuZG9u
MREwDwYDVQQKEwhCb2d1cyBDQTEQMA4GA1UEAxMHU0VORCBDQTAeFw0yMDEyMTEx
NzExMTRaFw0yMTEyMTExNzExMTRaMF8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJW
QTESMBAGA1UECgwJQm9ndXMgSVNQMS8wLQYDVQQDDCZhZTEzMi00OC5pYWQtbXNl
MDEtYWEtaWUxLmJvZ3VzaXNwLm5ldDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEA8+d2MFk/VwFZASBZqVQNYoKl82dV9EXZtlhv9XaXHQoBWwEsFIx3Vt4qvDVx
R99EVq/8QadH4Duqe1kOXrjd/OR39hv6MxX1mVQKfnoslHpUl5SFl480xxeHKFdW
9L2YORSO4V2E4U1++3YD5OAEiXBJNCIVIRnqv57DNdSAqRkCAwEAAaOCAVswggFX
MB0GA1UdDgQWBBRwhJB73ODi5oatFF4kxyhezmNsrDCBjgYDVR0jBIGGMIGDgBQX
yVDy3dzL9sHlz8eGrZsFyACVH6FVpFMwUTELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AlZBMRAwDgYDVQQHEwdIZXJuZG9uMREwDwYDVQQKEwhCb2d1cyBDQTEQMA4GA1UE
AxMHU0VORCBDQYIUT+ZI0j8ZF+hTMrNrp95OWSgX0NowDAYDVR0TAQH/BAIwADAL
BgNVHQ8EBAMCB4AwEwYDVR0lBAwwCgYIKwYBBQUHAxcwMQYIKwYBBQUHAQcBAf8E
IjAgMAsEAgABMAUDAwAKAjARBAIAAjALAwkAIAENuMr+vr4wQgYJYIZIAYb4QgEN
BDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9yIGFueSBw
dXJwb3NlLjANBgkqhkiG9w0BAQUFAAOBgQBRpxWx42rSni3ApQ67zQfgh3SqLGNU
gtht7mHlJpW0LPdT7tnnrbAyzQVlLd2I3twy4xaTC3Amc5TfHqEh8ocRhf8wfCnP
a/TUx+t2ycyo8lQ495FoxYzpLYEJLCDIcUqkJY3Y30sPvYx5FEDrMKvWmp0yOvun
Ydk2mhKOR6JwKQ==
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
            if extn['extnID'] in rfc5280.certificateExtensionsMap:
                extnValue, rest = der_decoder(
                    extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])

                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                    self.assertTrue(rfc6494.id_kp_sendRouter, extnValue[0])
                    found = True

        self.assertTrue(found)

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
