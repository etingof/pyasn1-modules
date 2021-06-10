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
from pyasn1_alt_modules import rfc6962


class CriticalPoisonTestCase(unittest.TestCase):
    pem_text = """\
MIIC4jCCAkugAwIBAgIBCDANBgkqhkiG9w0BAQUFADBYMQswCQYDVQQGEwJHQjEn
MCUGA1UEChMeQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IFByZUNBMQ4wDAYDVQQI
EwVXYWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2
MDEwMDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBU
cmFuc3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGf
MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvrurKxRq3zr356srn3RdSleGTlVoX
mJrvjZerfN/3dhCTwLgj0qTjpRoXuG8oFitmolOJNevs3BA2Iz2i3WUxsMY7zGh2
Hr3IVAN7dzmSRrhwp7crFMmxZn3gmpZA7Z8/PHJdlQtNJlWYaf5/HpGaZut201wB
F8a80NjP0hAosQIDAQABo4HBMIG+MB0GA1UdDgQWBBRhLGTvrHm3KDl8nZPm34ZG
X6dqiDB9BgNVHSMEdjB0gBQH77NAIzT3nv4jgIOy4g1c6hB9QKFZpFcwVTELMAkG
A1UEBhMCR0IxJDAiBgNVBAoTG0NlcnRpZmljYXRlIFRyYW5zcGFyZW5jeSBDQTEO
MAwGA1UECBMFV2FsZXMxEDAOBgNVBAcTB0VydyBXZW6CAQEwCQYDVR0TBAIwADAT
BgorBgEEAdZ5AgQDAQH/BAIFADANBgkqhkiG9w0BAQUFAAOBgQBCPm+dvVk8wR1Z
qGE8r38KCOWa80OWwJpc9vjyLZ5MjKmnqutpIMSdyY6fxJczDGxj5rYk+JObNhfW
C9XZboSDJ3ucsf6MGikdqYiO7sPkhBqr1u5YVce01dDCioQwT1xIjm+/bNuPp/Sp
8BnJrf7EjKd08DTtXMr5VlMFqG62Vg==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        # The id_ce_criticalPoison is not automatically added to the map.
        # Normally certificates that contiain it are rejected.
        self.assertNotIn(
            rfc6962.id_ce_criticalPoison, rfc5280.certificateExtensionsMap)

        extn_map = { rfc6962.id_ce_criticalPoison: univ.Null(""), }
        extn_map.update(rfc5280.certificateExtensionsMap)

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        extn_list = []

        for extn in asn1Object['tbsCertificate']['extensions']:
            extn_list.append(extn['extnID'])
            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=extn_map[extn['extnID']])
            self.assertFalse(rest)
            if not ev == univ.Null(""):
                self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))

        self.assertIn(rfc6962.id_ce_criticalPoison, extn_list)

class EmbededSCTCertificateTestCase(unittest.TestCase):
    pem_text = """\
MIIDWTCCAsKgAwIBAgIBBzANBgkqhkiG9w0BAQUFADBVMQswCQYDVQQGEwJHQjEk
MCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4wDAYDVQQIEwVX
YWxlczEQMA4GA1UEBxMHRXJ3IFdlbjAeFw0xMjA2MDEwMDAwMDBaFw0yMjA2MDEw
MDAwMDBaMFIxCzAJBgNVBAYTAkdCMSEwHwYDVQQKExhDZXJ0aWZpY2F0ZSBUcmFu
c3BhcmVuY3kxDjAMBgNVBAgTBVdhbGVzMRAwDgYDVQQHEwdFcncgV2VuMIGfMA0G
CSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+75jnwmh3rjhfdTJaDB0ym+3xj6r015a/
BH634c4VyVui+A7kWL19uG+KSyUhkaeb1wDDjpwDibRc1NyaEgqyHgy0HNDnKAWk
EM2cW9tdSSdyba8XEPYBhzd+olsaHjnu0LiBGdwVTcaPfajjDK8VijPmyVCfSgWw
FAn/Xdh+tQIDAQABo4IBOjCCATYwHQYDVR0OBBYEFCAxVBryXAX/2GWLaEN5T16Q
Nve0MH0GA1UdIwR2MHSAFF+diA3Ic+ZU1PgN2OawwSS0R8NVoVmkVzBVMQswCQYD
VQQGEwJHQjEkMCIGA1UEChMbQ2VydGlmaWNhdGUgVHJhbnNwYXJlbmN5IENBMQ4w
DAYDVQQIEwVXYWxlczEQMA4GA1UEBxMHRXJ3IFdlboIBADAJBgNVHRMEAjAAMIGK
BgorBgEEAdZ5AgQCBHwEegB4AHYA3xwuwRUAlFJHqWFoMl3cXHlZ6PfG04j8AC4L
vT9012QAAAE92yffkwAABAMARzBFAiBIL2dRrzXbplQ2vh/WZA89v5pBQpSVkkUw
KI+j5eI+BgIhAOTtwNs6xXKx4vXoq2poBlOYfc9BAn3+/6EFUZ2J7b8IMA0GCSqG
SIb3DQEBBQUAA4GBAIoMS+8JnUeSea+goo5on5HhxEIb4tJpoupspOghXd7dyhUE
oR58h8S3foDw6XkDUmjyfKIOFmgErlVvMWmB+Wo5Srer/T4lWsAERRP+dlcMZ5Wr
5HAxM9MD+J86+mu8/FFzGd/ZW5NCQSEfY0A1w9B4MHpoxgdaLiDInza4kQyg
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        extn_list = []

        for extn in asn1Object['tbsCertificate']['extensions']:
            extn_list.append(extn['extnID'])
            ev, rest = der_decoder(extn['extnValue'],
                asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
            self.assertFalse(rest)
            if not ev == univ.Null(""):
                self.assertTrue(ev.prettyPrint())
            self.assertEqual(extn['extnValue'], der_encoder(ev))

        self.assertIn(rfc6962.id_ce_embeddedSCT, extn_list)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
