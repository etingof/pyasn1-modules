#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc3546


class PkiPathTestCase(unittest.TestCase):
    pem_text = """\
MIIFATCCAgIwggGIoAMCAQICCQDokdYGkU/O8jAKBggqhkjOPQQDAzA/MQswCQYD
VQQGEwJVUzELMAkGA1UECAwCVkExEDAOBgNVBAcMB0hlcm5kb24xETAPBgNVBAoM
CEJvZ3VzIENBMB4XDTE5MDUxNDA4NTgxMVoXDTIxMDUxMzA4NTgxMVowPzELMAkG
A1UEBhMCVVMxCzAJBgNVBAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMREwDwYDVQQK
DAhCb2d1cyBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABPBRdlSx6I5qpZ2sKUMI
xun1gUAzzstOYWKvKCnMoNT1x+pIKDvMEMimFcLAxxL3NVYOhK0Jty83SPDkKWMd
x9/Okdhf3U/zxJlEnXDiFrAeM6xbG8zcCRiBnmd92UvsRqNQME4wHQYDVR0OBBYE
FPI12zQE2qVV8r1pA5mwYuziFQjBMB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mw
YuziFQjBMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwMDaAAwZQIwWlGNjb9NyqJS
zUSdsEqDSvMZb8yFkxYCIbAVqQ9UqScUUb9tpJKGsPWwbZsnLVvmAjEAt/ypozbU
hQw4dSPpWzrn5BQ0kKbDM3DQJcBABEUBoIOol1/jYQPmxajQuxcheFlkMIIC9zCC
An2gAwIBAgIJAKWzVCgbsG46MAoGCCqGSM49BAMDMD8xCzAJBgNVBAYTAlVTMQsw
CQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9ndXMgQ0Ew
HhcNMTkwNTE0MTAwMjAwWhcNMjAwNTEzMTAwMjAwWjBlMQswCQYDVQQGEwJVUzEL
MAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xGzAZBgNVBAoTElZpZ2lsIFNl
Y3VyaXR5IExMQzEaMBgGA1UEAxMRbWFpbC52aWdpbHNlYy5jb20wdjAQBgcqhkjO
PQIBBgUrgQQAIgNiAATwUXZUseiOaqWdrClDCMbp9YFAM87LTmFirygpzKDU9cfq
SCg7zBDIphXCwMcS9zVWDoStCbcvN0jw5CljHcffzpHYX91P88SZRJ1w4hawHjOs
WxvM3AkYgZ5nfdlL7EajggEdMIIBGTALBgNVHQ8EBAMCB4AwQgYJYIZIAYb4QgEN
BDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9yIGFueSBw
dXJwb3NlLjAdBgNVHQ4EFgQU8jXbNATapVXyvWkDmbBi7OIVCMEwHwYDVR0jBBgw
FoAU8jXbNATapVXyvWkDmbBi7OIVCMEwgYUGCCsGAQUFBwEMBHkwd6J1oHMwcTBv
MG0WCWltYWdlL3BuZzAzMDEwDQYJYIZIAWUDBAIBBQAEIJtBNrMSSNo+6Rwqwctm
cy0qf68ilRuKEmlf3GLwGiIkMCsWKWh0dHA6Ly93d3cudmlnaWxzZWMuY29tL3Zp
Z2lsc2VjX2xvZ28ucG5nMAoGCCqGSM49BAMDA2gAMGUCMGhfLH4kZaCDH43A8m8m
HCUpYt9unT0qYu4TCMaRuOTYEuqj3qtuwyLcfAGuXKp/oAIxAIrPY+3yPj22pmfm
Qi5w21UljqoTj/+lQLkU3wfy5BdVKBwI0GfEA+YL3ctSzPNqAA==
"""

    def setUp(self):
        self.asn1Spec = rfc3546.PkiPath()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(2, len(asn1Object))
        self.assertEqual(substrate, der_encoder(asn1Object))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
