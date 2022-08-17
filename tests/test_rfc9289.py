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
from pyasn1_alt_modules import rfc9289

class RPCServerCertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIICqjCCAjCgAwIBAgIUHs6FKYHBGp4ZXCsvoxt3iB5JOZIwCgYIKoZIzj0EAwMw
PzELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMREw
DwYDVQQKDAhCb2d1cyBDQTAeFw0yMjA4MTUyMTM3MDNaFw0yMzA4MTUyMTM3MDNa
MGMxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4GA1UEBxMHSGVybmRvbjEb
MBkGA1UEChMSVmlnaWwgU2VjdXJpdHkgTExDMRgwFgYDVQQDEw9ycGMuZXhhbXBs
ZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAS8tNaPak9Z2SEElxbI97MNShz3
7+N2fwIDdTiZOA2lNEd9YLWKiak9dZkz6o0cJVO5dPkFIOOwKEfY+MxFH0ExPCli
o42GuU+lH6m1tlHxpPmPxg2ys/XEKEvTd9Oai9SjgcgwgcUwDgYDVR0PAQH/BAQD
AgeAMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0
cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wHQYDVR0OBBYEFLvmo1rFhP0Qnrht8gzm
YhOQGkQ5MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMBoGA1UdEQQT
MBGCD3JwYy5leGFtcGxlLmNvbTATBgNVHSUEDDAKBggrBgEFBQcDIjAKBggqhkjO
PQQDAwNoADBlAjBWGbVQzaaw30D9+JLCFEiPQMHu0LfZaKFXoluk0NKKom6LTaa8
rbHZGgUIj5yC8LsCMQCXZ3SSvGstTrF3LrpPdL+FAdHND00Qhvv0kRitDas/YrJp
RX4igo315i+/xgOux9A=
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
                    self.assertEqual(rfc9289.id_kp_rpcTLSServer, extnValue[0])
                    found = True

        self.assertTrue(found)

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
