#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9336


class DocSigningCertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIClDCCAhmgAwIBAgIUFXu5hcVxmT/6ufi0cmwGouTF7YEwCgYIKoZIzj0EAwMw
PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMREw
DwYDVQQKDAhCb2d1cyBDQTAeFw0yMjA4MTEwMDAwMjRaFw0yMzA4MTEwMDAwMjRa
MEwxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4GA1UEBxMHSGVybmRvbjEQ
MA4GA1UEChMHRXhhbXBsZTEMMAoGA1UEAxMDQm9iMHYwEAYHKoZIzj0CAQYFK4EE
ACIDYgAEMaRiVS8WvN8Ycmpfq75jBbOMUukNfXAg6AL0JJBXtIFAuIJcZVlkLn/x
bywkcMLHK/O+w9RWUQa2Cjw+h8b/1Cl+gIpqLtE558bD5PfM2aYpJ/YE6yZ9nBfT
Qs7z1TH5o4HIMIHFMA4GA1UdDwEB/wQEAwIHgDBCBglghkgBhvhCAQ0ENRYzVGhp
cyBjZXJ0aWZpY2F0ZSBjYW5ub3QgYmUgdHJ1c3RlZCBmb3IgYW55IHB1cnBvc2Uu
MB0GA1UdDgQWBBTKa2Zy3iybV3+YjuLDKtNmjsIapTAfBgNVHSMEGDAWgBTyNds0
BNqlVfK9aQOZsGLs4hUIwTAaBgNVHREEEzARgQ9ib2JAZXhhbXBsZS5jb20wEwYD
VR0lBAwwCgYIKwYBBQUHAyQwCgYIKoZIzj0EAwMDaQAwZgIxAMEMwE4HoI1EbTKB
cKalSvfmChu8pixAOHHuCqMls/xupjIvH7tYphI/MaO9QxBKBgIxAPsr8XyO0VD7
mqtU35ik+eawW2Nf2x+gWPB8gS6jvQDBYV8N97ORHSH+cRuguuSBFg==
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
                self.assertFalse(rest)
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                    self.assertEqual(
                        rfc9336.id_kp_documentSigning, extnValue[0])
                    found = True

        self.assertTrue(found)

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
