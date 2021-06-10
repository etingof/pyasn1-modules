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

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6492


class RPKIProvisioningTestCase(unittest.TestCase):
    pem_text = """\
MIIHSgYJKoZIhvcNAQcCoIIHOzCCBzcCAQMxDTALBglghkgBZQMEAgEwgbYGCyqGSIb3DQEJEAEc
oIGmBIGjPD94bWwgdmVyc2lvbj0nMS4wJyBlbmNvZGluZz0nVVRGLTgnPz4KPG1lc3NhZ2UgeG1s
bnM9Imh0dHA6Ly93d3cuYXBuaWMubmV0L3NwZWNzL3Jlc2NlcnRzL3VwLWRvd24vIiByZWNpcGll
bnQ9IlJHbmV0LU9VIiBzZW5kZXI9Im92c0NBIiB0eXBlPSJsaXN0IiB2ZXJzaW9uPSIxIi8+CqCC
AxYwggMSMIIB+qADAgECAgICTTANBgkqhkiG9w0BAQsFADAhMR8wHQYDVQQDExZvdnNDQSBCUEtJ
IHJlc291cmNlIENBMB4XDTIxMDEyMTAzMzAwNVoXDTIxMDMyMjAzMzAwNVowMzExMC8GA1UEAxMo
QzM2MTU4MTFDOTg2MDgwODlGRUQ3QTc5NzE0NUFFNzczOEE2NUMzMTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBAPqmJfF5uCDfj1gLxAgiU+PBYwlxoOHET1oIf4fdyE/7P2FBJI9oxngB
rhlqdvd8ef/gSZ6MksKs9/FQGRKtv54zOfl2nFmraP9T6VdoXaxbcmuY22EvPOJ85IVXVUEAJOQi
M5GskTLlAiSHQziCI+/ve4f8ojGU6Vtav/a+W713/UhPrTj2WwksC/Pu37smIv5pkxXJnyR3Dpoh
jwV79Qm4dDRLakZy9HsZ8wHSP6HH8qovBCXGU/7mpXFWzzrL0NaKI3uqGcJjQLwx3UE0g/NWwYv3
t52HpwRV5hiiQZB+4OiRI7OmLlQJH82TDoHOdLRIER9mRBwEamMQTQbx8f8CAwEAAaNCMEAwHQYD
VR0OBBYEFMNhWBHJhggIn+16eXFFrnc4plwxMB8GA1UdIwQYMBaAFMKR3eNCo3tIwJ7BNnpcKxLT
ruUaMA0GCSqGSIb3DQEBCwUAA4IBAQCY5tDRD3vOgi2NSP7TeYOiYYVQwNum35jbIdXGSAVwBSsZ
/j73/M0vzHzqKXOotHy/lGnNFUXDxydO9P3ZXPSfUVIY0yjZdMYa31xxT3D3wNgqFxJ9R0JzLk/p
ANtKy01CGWUnrmY3sU0t81bGbAalYsnfd54rKsQKywZiaw2iuT8EFlZNq+oUx9hVuc9S/G/kHzZQ
MLHO0iELIyUxrMNYn/0GXj77oA+Ixbd7InY3/CbrogYwRzkm+XDmHeh6DihdhMTr9ipx83Wu9Oy3
plZbw6KmbCv7HywYASQq5KpRsHQPyX3EUzOh5A9Nge2tosTrGNNc0K2xsxwYmLO5mu5HoYIBoDCC
AZwwgYUCAQEwDQYJKoZIhvcNAQELBQAwITEfMB0GA1UEAxMWb3ZzQ0EgQlBLSSByZXNvdXJjZSBD
QRcNMjEwMTIxMDMzMDA1WhcNMjEwMTIyMDQzMDA1WqAwMC4wHwYDVR0jBBgwFoAUwpHd40Kje0jA
nsE2elwrEtOu5RowCwYDVR0UBAQCAgSXMA0GCSqGSIb3DQEBCwUAA4IBAQA/ZWgZ9E8JOksCkhVv
VBEDIONm6hKY30rg2Ry0bRvZQ8KGlItB7nkO1MRZN+FDP5B7cRjKK814WAjIzLEg7+uqpEUv6zyk
NXAYlCptDqBGTnFiFYEsd7AkxcCY332c5ZAqikTs8v5fn78HA+Gda3hCJmkDZWvop61LQyTgYPnt
wk83fV8CBZ5il502ePT8yYpgWUPSHraSiHw9y8Sh7KL2dUuYzaOVD5FllP0Vjbh6Y8HyeJNfefXd
gU85n+/jRgYmTZf6HqnUh4Uj+os5VG8qep7cCYXl0fopq9tB78uuBCASN8CrOZE+01I6mQtdLClO
jJXSI0MJgEahSqiMxnOMMYIBqjCCAaYCAQOAFMNhWBHJhggIn+16eXFFrnc4plwxMAsGCWCGSAFl
AwQCAaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABHDAcBgkqhkiG9w0BCQUxDxcNMjEwMTIx
MjIwMDIxWjAvBgkqhkiG9w0BCQQxIgQgqTVNWNOGNThLE4cyQFln/dUkN+WlT005oaVkHQ9rip8w
DQYJKoZIhvcNAQEBBQAEggEAoEsmgmdUPbJyOd/9uG0E+b6YdB3LAEzWY2q1pNgNn5DXvV0ZQdeS
WlcZXXr15ijXe7uyKTVPouvrINeHx3M8UQQ6IMjo6QIP8Q/80HpFWR/jwYgXGD6W8eVVKbmal4fg
VGSNsLLzxSW0b0l+cDud99WaDxBkI+UJgOpDwgaxKlpb0J0r01cTZ3mGyNg1V67Z5UaqJXGKnspf
oeJDQYwjDTOPV6BTBMddrUQEUAGuG4slIH9qtlf0jo76iuZq26FVDftCPhXC7lAL7oQC0yoIjcur
J3DaFmF8obzBv328Fs29I7bOpWxLnqnxy2fcnVFkKteWzCdLXTHItJHUrcRgWQ==
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc6492.id_ct_xml, layers)

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

        self.assertEqual(rfc6492.id_ct_xml, layer)

        oid = None
        for attr in asn1Object['signerInfos'][0]['signedAttrs']:
            if attr['attrType'] == rfc5652.id_contentType:
                oid = attr['attrValues'][0]

        self.assertEqual(der_encoder(rfc6492.id_ct_xml), oid)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        ect = asn1Object['content']['encapContentInfo']['eContentType']
        self.assertEqual(rfc6492.id_ct_xml, ect)

        oid = None
        for attr in asn1Object['content']['signerInfos'][0]['signedAttrs']:
            if attr['attrType'] == rfc5652.id_contentType:
                oid = attr['attrValues'][0]

        self.assertEqual(rfc6492.id_ct_xml, oid)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
