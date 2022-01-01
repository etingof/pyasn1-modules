#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2020-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9092


class GeofeedCSVTestCase(unittest.TestCase):
    pem_text = """\
MIIGlwYJKoZIhvcNAQcCoIIGiDCCBoQCAQMxDTALBglghkgBZQMEAgEwDQYLKoZ
IhvcNAQkQAS+gggSxMIIErTCCA5WgAwIBAgIUJ605QIPX8rW5m4Zwx3WyuW7hZu
MwDQYJKoZIhvcNAQELBQAwMzExMC8GA1UEAxMoM0FDRTJDRUY0RkIyMUI3RDExR
TNFMTg0RUZDMUUyOTdCMzc3ODY0MjAeFw0yMDA5MDMxOTA1MTdaFw0yMTA2MzAx
OTA1MTdaMDMxMTAvBgNVBAMTKDkxNDY1MkEzQkQ1MUMxNDQyNjAxOTg4ODlGNUM
0NUFCRjA1M0ExODcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCycT
QrOb/qB2W3i3Ki8PhA/DEWyii2TgGo9pgCwO9lsIRI6Zb/k+aSiWWP9kSczlcQg
tPCVwr62hTQZCIowBN0BL0cK0/5k1imJdi5qdM3nvKswM8CnoR11vB8pQFwruZm
r5xphXRvE+mzuJVLgu2V1upmBXuWloeymudh6WWJ+GDjwPXO3RiXBejBrOFNXha
FLe08y4DPfr/S/tXJOBm7QzQptmbPLYtGfprYu45liFFqqP94UeLpISfXd36AKG
zqTFCcc3EW9l5UFE1MFLlnoEogqtoLoKABt0IkOFGKeC/EgeaBdWLe469ddC9rQ
ft5w6g6cmxG+aYDdIEB34zrAgMBAAGjggG3MIIBszAdBgNVHQ4EFgQUkUZSo71R
wUQmAZiIn1xFq/BToYcwHwYDVR0jBBgwFoAUOs4s70+yG30R4+GE78Hil7N3hkI
wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCB4AwGAYDVR0gAQH/BA4wDDAKBg
grBgEFBQcOAjBhBgNVHR8EWjBYMFagVKBShlByc3luYzovL3Jwa2kuZXhhbXBsZ
S5uZXQvcmVwb3NpdG9yeS8zQUNFMkNFRjRGQjIxQjdEMTFFM0UxODRFRkMxRTI5
N0IzNzc4NjQyLmNybDBsBggrBgEFBQcBAQRgMF4wXAYIKwYBBQUHMAKGUHJzeW5
jOi8vcnBraS5leGFtcGxlLm5ldC9yZXBvc2l0b3J5LzNBQ0UyQ0VGNEZCMjFCN0
QxMUUzRTE4NEVGQzFFMjk3QjM3Nzg2NDIuY2VyMCEGCCsGAQUFBwEHAQH/BBIwE
DAGBAIAAQUAMAYEAgACBQAwRQYIKwYBBQUHAQsEOTA3MDUGCCsGAQUFBzANhilo
dHRwczovL3JyZHAuZXhhbXBsZS5uZXQvbm90aWZpY2F0aW9uLnhtbDANBgkqhki
G9w0BAQsFAAOCAQEABR2T0qT2V1ZlsZjj+yHPTArIVBECZFSCdP+bJTse85TqYi
blMsNS9yEu2SNbaZMNLuSSiAffYooh4nIYq/Rh6+xGs1n427JZUokoeLtY0UUb2
fIsua9JFo8YGTnpqDMGe+xnpbJ0SCSoBlJCIj+b+YS8WXjEHt2KW6wyA/BcNS8a
dS2pEUwC2cs/WcwzgbttnkcnG7/wkrQ3oqzpC1arKelyz7PGIIXJGy9nF8C3/aa
aEpHd7UgIyvXYuCY/lqWTm97jDxgGIYGC7660mtfOMkB8YF6kUU+td2dDQsMztc
OxbzqiGnicmeJfBwG2li6O0vorW4d5iIOTKpQyqfh45TGCAaowggGmAgEDgBSRR
lKjvVHBRCYBmIifXEWr8FOhhzALBglghkgBZQMEAgGgazAaBgkqhkiG9w0BCQMx
DQYLKoZIhvcNAQkQAS8wHAYJKoZIhvcNAQkFMQ8XDTIwMDkxMzE4NDUxMFowLwY
JKoZIhvcNAQkEMSIEICvi8p5S8ckg2wTRhDBQzGijjyqs5T6I+4VtBHypfcEWMA
0GCSqGSIb3DQEBAQUABIIBAHUrA4PaJG42BD3hpF8U0usnV3Dg5NQh97SfyKTk7
YHhhwu/936gkmAew8ODRTCddMvMObWkjj7/XeR+WKffaTF1EAdZ1L6REV+GlV91
cYnFkT9ldn4wHQnNNncfAehk5PClYUUQ0gqjdJT1hdaolT83b3ttekyYIiwPmHE
xRaNkSvKenlNqcriaaf3rbQy9dc2d1KxrL2429n134ICqjKeRnHkXXrCWDmyv/3
imwYkXpiMxw44EZqDjl36MiWsRDLdgoijBBcGbibwyAfGeR46k5raZCGvxG+4xa
O8PDTxTfIYwAnBjRBKAqAZ7yX5xHfm58jUXsZJ7Ileq1S7G6Kk=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        assert asn1Object['contentType'] == rfc5652.id_signedData
        sd, rest = der_decoder(asn1Object['content'],
            asn1Spec=rfc5652.SignedData())
        self.assertFalse(rest)
        self.assertTrue(sd.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(sd))

        found = False
        for sa in sd['signerInfos'][0]['signedAttrs']:
            if sa['attrType'] == rfc5652.id_contentType:
                 ct, rest = der_decoder(sa['attrValues'][0],
                     asn1Spec=rfc5652.ContentType())
                 self.assertFalse(rest)
                 self.assertTrue(ct.prettyPrint())
                 self.assertEqual(sa['attrValues'][0], der_encoder(ct))
                 self.assertEqual(rfc9092.id_ct_geofeedCSVwithCRLF, ct)
                 found = True

        assert found


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
