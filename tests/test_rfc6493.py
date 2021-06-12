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

from pyasn1.compat.octets import str2octs

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6493


class RPKIProvisioningTestCase(unittest.TestCase):
    pem_text = """\
MIIHfQYJKoZIhvcNAQcCoIIHbjCCB2oCAQMxDTALBglghkgBZQMEAgEwgc4GCyqG
SIb3DQEJEAEjoIG+BIG7QkVHSU46VkNBUkQNClZFUlNJT046My4wDQpBRFI6Ozs1
MTQ3IENyeXN0YWwgU3ByaW5ncyBEciBORTtCYWluYnJpZGdlIElzbGFuZDtXYXNo
aW5ndG9uOzk4MTEwO1VTDQpFTUFJTDpyYW5keUByZy5uZXQNCkZOOlJhbmR5IEJ1
c2gNCk46Ozs7Ow0KT1JHOlJHbmV0IE9VDQpURUw6KzEgMjA2IDM1Ni04MzQxDQpF
TkQ6VkNBUkQNCqCCBNUwggTRMIIDuaADAgECAgJ2vDANBgkqhkiG9w0BAQsFADAz
MTEwLwYDVQQDEyg2ZDZmYmZhOTc1M2RiOGQ4NDY0MzNkYjUzNTFkOWE5ZWMwN2M5
NmJkMB4XDTIxMDEyMTIxNDQ0MloXDTIyMDcwMTAwMDAwMFowMzExMC8GA1UEAxMo
RDE5QzgyN0FCOTU1RDQxNENEQTU1MEIwOTYyMjJGMTc2MUY0QjQ4QjCCASIwDQYJ
KoZIhvcNAQEBBQADggEPADCCAQoCggEBAJ8ec63eWPsU1kytl2heTfdOFLjBbB8H
I5Ra+OdRjy3EbALxk4FKMWQjIXR2gjySj+DIryoLRxkHMyF9GdHpu4rdWy1fz1AY
t4c4gR7Ye1g5tcupcT4DK4y6Bz3ooh9w2GqZEI8YQR92e83cX4Z35SMOG/rgACDy
+lZrLanpxP6FSv/bLQAaIC9Si5zQ0MBrUnLeJSh+YwgljLGXtPS1F3asfXfTlyux
D13gmeNNCM/YVY3czHrHwUwxeY66LrGIrWg1ueisxGqTS6CppdN20LjN9mdNYP9Z
v0629+XxqBrfg6ttX+UZ4s6BT3y7TXZkOrTdZDQ35FE12ffr0RTrGkECAwEAAaOC
Ae0wggHpMB0GA1UdDgQWBBTRnIJ6uVXUFM2lULCWIi8XYfS0izAfBgNVHSMEGDAW
gBRtb7+pdT242EZDPbU1HZqewHyWvTAYBgNVHSABAf8EDjAMMAoGCCsGAQUFBw4C
MFAGA1UdHwRJMEcwRaBDoEGGP3JzeW5jOi8vY2EucmcubmV0L3Jwa2kvUkduZXQt
T1UvYlctX3FYVTl1TmhHUXoyMU5SMmFuc0I4bHIwLmNybDBkBggrBgEFBQcBAQRY
MFYwVAYIKwYBBQUHMAKGSHJzeW5jOi8vcnBraS5yaXBlLm5ldC9yZXBvc2l0b3J5
L0RFRkFVTFQvYlctX3FYVTl1TmhHUXoyMU5SMmFuc0I4bHIwLmNlcjAOBgNVHQ8B
Af8EBAMCB4AwgYoGCCsGAQUFBwELBH4wfDBLBggrBgEFBQcwC4Y/cnN5bmM6Ly9j
YS5yZy5uZXQvcnBraS9SR25ldC1PVS8wWnlDZXJsVjFCVE5wVkN3bGlJdkYySDB0
SXMuZ2JyMC0GCCsGAQUFBzANhiFodHRwczovL2NhLnJnLm5ldC9ycmRwL25vdGlm
eS54bWwwFQYIKwYBBQUHAQgBAf8EBjAEoAIFADAhBggrBgEFBQcBBwEB/wQSMBAw
BgQCAAEFADAGBAIAAgUAMA0GCSqGSIb3DQEBCwUAA4IBAQAd8MEhKSzq0xkpQKEA
s0wRaGN3V3BzE3qJR3MRPuezmR1qb+1y/j12yc3W0hnSYnOB5axLaBBpshokX1ww
DUglAbQjxt8Jymfab/3VXnm5sXpG+8AVuErGwU+PnkMcOrELRGnrh2SwE9M8NEws
4vlFn40L5TsOKLvhQjtOP8Ox+ub84Sc1iFp5UzTN/P6IC7xczGuJSFXovb+2dkCD
dvW9bvVn9N5GPxqLMp77I+5r8T3nQcJzljEFx1pVGUxPZ4KHbqqpCK3s9sqO6o0I
tSvv76D93/u13QhTW+ly5nZ2IDCD3Qfr3w6rMLUlsY5sWYzHhHyZ6LCF87YM/5RZ
zCS2MYIBqjCCAaYCAQOAFNGcgnq5VdQUzaVQsJYiLxdh9LSLMAsGCWCGSAFlAwQC
AaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABIzAcBgkqhkiG9w0BCQUxDxcN
MjEwMTIxMjE0NDQyWjAvBgkqhkiG9w0BCQQxIgQg9g3G//K+FXuIiLGN/u0UZmW2
7sn5ajJt7yc25O+9EGkwDQYJKoZIhvcNAQEBBQAEggEAEv1PPTYLeo5skiBWpJMu
tKmUW/NXJKQXH0BVWe042LQGnyNW1YlfiGzuAR/J5oe9BoDj8tHfh5/uP+ieTN/h
ckl9juGBrgx2hwpWjAJo7y4UDPU+KC8EFqCRvY0cH94nvzxoF+8yK3eLH2UewQ/P
PSWPiMYVKZ3ETn0BdomnbmTHKsXPsOOuiPcc1CZxFVR3YW7B+0rc8HOaWaAf7hZ2
90+b62OfsIbsNTBLEpEuUBOf+ZTwdD/06/uutMXjvzwhYDHhfqUQmQncCgCnuLYY
AEaVoRU+RJcbuIp7iIQQUq1w7ZLNgDvu8r8McL6gIQJLUgnSE0oLzPxEDkTorm7/
XA==
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        self.assertEqual(rfc6493.id_ct_rpkiGhostbusters, layer)
        self.assertEqual(str2octs('BEGIN:VCARD'), substrate[0:11])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
