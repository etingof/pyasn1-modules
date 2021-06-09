#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# 
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc5055


class SCVPCVRequestTestCase(unittest.TestCase):
    cvrequest_pem_text = """\
MIIGzQYLKoZIhvcNAQkQAQqggga8MIIGuDCCBpigggZroIIGZzCCBU+gAwIBAgIE
U5dbcTANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
Uy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1
cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxKDAmBgNVBAsT
H0RldmVsb3BtZW50IFVTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTUwNDMwMTIxODMz
WhcNMjUwNDMwMTI0ODMzWjCBrDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4g
R292ZXJubWVudDEnMCUGA1UECxMeRGVwYXJ0bWVudCBvZiBWZXRlcmFucyBBZmZh
aXJzMSIwIAYDVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMTYwNAYDVQQL
Ey1EZXZlbG9wbWVudCBEZXBhcnRtZW50IG9mIFZldGVyYW5zIEFmZmFpcnMgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzxCAh/K5oS1Uk3oOAFlAY
/bjhs+Ro29RQwKehntc8C9cl/Z1XsMwhbXUVFJnS2u22zNUeQY84Zdf50VvzQVEl
OLkXfWw7iwraKrdT9o8cNEiZta5NyP97OwuZ3htucUoaU9CIne/L278nAH3DIIDh
AuvBrAW+asogGCTDBCrPU/HIentIob1zSejqg0yCjgkGWWtFjMP6ylzWRzRBGWQU
Dq2XrGj11a5HfA5bvXbmNefAcyyxoFOGliA7xeQ5widg3VMBua3H21GGtKPiDzNz
NR75p9FQCfetuMOwQz3A4vXZwFphUjt1BI7h4NyYQRSO8HUozgjxSJ4SHQ4jdcub
AgMBAAGjggKfMIICmzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zCB
lwYDVR0gBIGPMIGMMAwGCmCGSAFlAwIBMAgwDAYKYIZIAWUDAgEwCTAMBgpghkgB
ZQMCATAKMAwGCmCGSAFlAwIBMAswDAYKYIZIAWUDAgEwDDAMBgpghkgBZQMCATAN
MAwGCmCGSAFlAwIBMFYwDAYKYIZIAWUDAgEwYjAMBgpghkgBZQMCATBtMAwGCmCG
SAFlAwIBMG4wUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vZGV2
cGtpLnRyZWFzdXJ5Lmdvdi9jYWNlcnRzaXNzdWVkdG9kZXZ0cmNhLnA3YzBGBggr
BgEFBQcBCwQ6MDgwNgYIKwYBBQUHMAWGKmh0dHA6Ly9kZXZwa2kudHJlYXN1cnku
Z292L2RldnZhY2Ffc2lhLnA3YzCCAQEGA1UdHwSB+TCB9jA8oDqgOIY2aHR0cDov
L2RldnBraS50cmVhc3VyeS5nb3YvRGV2X1VTX1RyZWFzdXJ5X1Jvb3RfQ0EuY3Js
MIG1oIGyoIGvpIGsMIGpMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zl
cm5tZW50MSMwIQYDVQQLExpEZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAG
A1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEoMCYGA1UECxMfRGV2ZWxv
cG1lbnQgVVMgVHJlYXN1cnkgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTAfBgNVHSME
GDAWgBSMbEt5Mx24G9ZA0CnoXbcJOUEGaTAdBgNVHQ4EFgQUL8oFKMHd/UxoSn2v
zShWn56MQ10wDQYJKoZIhvcNAQELBQADggEBAGiu2XFOYLDckeQzOpuVP9Ndp0qC
dTSykJTt6R9vc/h0KfKgvALZomVN/CSZ1EIj6Muk9IAc9vti2vBNLzbDJ8+bjriu
yGNhfsiVb0MSZebVVaSZy9Yng9hSWBmXaZ7Fge9FTTbsnxi9olxzIlIpmIUGZ3u9
Xdrlmm01JH8sIL4zpNpWk68fK5tHfkmTrJuPrWYwgZrAjJ3OtTsq/4UBdgVtTE0W
vepkDb7ni39T8PDqRXroFVxkbX9eLw34gvxnp7qRTxfO+fPge9F4djCjVglHj+G+
6NIJ0zPOauHrpny1LaFwR6XhXXQUrtbZZkV/PCEMVdT6muK1tEQVPjFyZmgwCgYI
KwYBBQUHEQOhCgYIKwYBBQUHEgEwDzANBgtghkgBZQoCEgIABKIahhhVUk46VlNT
QVBJOnZzcy1kdi1ycy1wMTE=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc5055.id_ct_scvp_certValRequest, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
        }

        substrate = pem.readBase64fromText(self.cvrequest_pem_text)

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual('URN:VSSAPI:vss-dv-rs-p11',
            asn1Object['requestorName']['uniformResourceIdentifier'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cvrequest_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual('URN:VSSAPI:vss-dv-rs-p11',
            asn1Object['content']['requestorName']['uniformResourceIdentifier'])

class SCVPCVResponseTestCase(unittest.TestCase):
    cvresponse_pem_text = """\
MIImEAYJKoZIhvcNAQcCoIImATCCJf0CAQMxDTALBglghkgBZQMEAgEwgh5VBgsq
hkiG9w0BCRABC6CCHkQEgh5AMIIePAIBAQIEYAdEhhgPMjAyMTAyMDMxODUwNDVa
MACgDzANBgtghkgBZQoCEgIABKEYoBYEFHwRAhGU/csilmOyiW+5Uj3jOS7QoxqG
GFVSTjpWU1NBUEk6dnNzLWR2LXJzLXAxMaSCHdUwgh3RoIIGZzCCBU+gAwIBAgIE
U5dbcTANBgkqhkiG9w0BAQsFADCBmjELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1Uu
Uy4gR292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1
cnkxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24gQXV0aG9yaXRpZXMxKDAmBgNVBAsT
H0RldmVsb3BtZW50IFVTIFRyZWFzdXJ5IFJvb3QgQ0EwHhcNMTUwNDMwMTIxODMz
WhcNMjUwNDMwMTI0ODMzWjCBrDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4g
R292ZXJubWVudDEnMCUGA1UECxMeRGVwYXJ0bWVudCBvZiBWZXRlcmFucyBBZmZh
aXJzMSIwIAYDVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0aWVzMTYwNAYDVQQL
Ey1EZXZlbG9wbWVudCBEZXBhcnRtZW50IG9mIFZldGVyYW5zIEFmZmFpcnMgQ0Ew
ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCzxCAh/K5oS1Uk3oOAFlAY
/bjhs+Ro29RQwKehntc8C9cl/Z1XsMwhbXUVFJnS2u22zNUeQY84Zdf50VvzQVEl
OLkXfWw7iwraKrdT9o8cNEiZta5NyP97OwuZ3htucUoaU9CIne/L278nAH3DIIDh
AuvBrAW+asogGCTDBCrPU/HIentIob1zSejqg0yCjgkGWWtFjMP6ylzWRzRBGWQU
Dq2XrGj11a5HfA5bvXbmNefAcyyxoFOGliA7xeQ5widg3VMBua3H21GGtKPiDzNz
NR75p9FQCfetuMOwQz3A4vXZwFphUjt1BI7h4NyYQRSO8HUozgjxSJ4SHQ4jdcub
AgMBAAGjggKfMIICmzAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zCB
lwYDVR0gBIGPMIGMMAwGCmCGSAFlAwIBMAgwDAYKYIZIAWUDAgEwCTAMBgpghkgB
ZQMCATAKMAwGCmCGSAFlAwIBMAswDAYKYIZIAWUDAgEwDDAMBgpghkgBZQMCATAN
MAwGCmCGSAFlAwIBMFYwDAYKYIZIAWUDAgEwYjAMBgpghkgBZQMCATBtMAwGCmCG
SAFlAwIBMG4wUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8vZGV2
cGtpLnRyZWFzdXJ5Lmdvdi9jYWNlcnRzaXNzdWVkdG9kZXZ0cmNhLnA3YzBGBggr
BgEFBQcBCwQ6MDgwNgYIKwYBBQUHMAWGKmh0dHA6Ly9kZXZwa2kudHJlYXN1cnku
Z292L2RldnZhY2Ffc2lhLnA3YzCCAQEGA1UdHwSB+TCB9jA8oDqgOIY2aHR0cDov
L2RldnBraS50cmVhc3VyeS5nb3YvRGV2X1VTX1RyZWFzdXJ5X1Jvb3RfQ0EuY3Js
MIG1oIGyoIGvpIGsMIGpMQswCQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zl
cm5tZW50MSMwIQYDVQQLExpEZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAG
A1UECxMZQ2VydGlmaWNhdGlvbiBBdXRob3JpdGllczEoMCYGA1UECxMfRGV2ZWxv
cG1lbnQgVVMgVHJlYXN1cnkgUm9vdCBDQTENMAsGA1UEAxMEQ1JMMTAfBgNVHSME
GDAWgBSMbEt5Mx24G9ZA0CnoXbcJOUEGaTAdBgNVHQ4EFgQUL8oFKMHd/UxoSn2v
zShWn56MQ10wDQYJKoZIhvcNAQELBQADggEBAGiu2XFOYLDckeQzOpuVP9Ndp0qC
dTSykJTt6R9vc/h0KfKgvALZomVN/CSZ1EIj6Muk9IAc9vti2vBNLzbDJ8+bjriu
yGNhfsiVb0MSZebVVaSZy9Yng9hSWBmXaZ7Fge9FTTbsnxi9olxzIlIpmIUGZ3u9
Xdrlmm01JH8sIL4zpNpWk68fK5tHfkmTrJuPrWYwgZrAjJ3OtTsq/4UBdgVtTE0W
vepkDb7ni39T8PDqRXroFVxkbX9eLw34gvxnp7qRTxfO+fPge9F4djCjVglHj+G+
6NIJ0zPOauHrpny1LaFwR6XhXXQUrtbZZkV/PCEMVdT6muK1tEQVPjFyZmgYDzIw
MjEwMjAzMTg1MDQ1WjAMMAoGCCsGAQUFBxEDMIIXMjCCFy4GCCsGAQUFBxIBBIIX
IDCCFxwwggZnMIIFT6ADAgECAgRTl1txMA0GCSqGSIb3DQEBCwUAMIGaMQswCQYD
VQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLExpEZXBh
cnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNhdGlvbiBB
dXRob3JpdGllczEoMCYGA1UECxMfRGV2ZWxvcG1lbnQgVVMgVHJlYXN1cnkgUm9v
dCBDQTAeFw0xNTA0MzAxMjE4MzNaFw0yNTA0MzAxMjQ4MzNaMIGsMQswCQYDVQQG
EwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MScwJQYDVQQLEx5EZXBhcnRt
ZW50IG9mIFZldGVyYW5zIEFmZmFpcnMxIjAgBgNVBAsTGUNlcnRpZmljYXRpb24g
QXV0aG9yaXRpZXMxNjA0BgNVBAsTLURldmVsb3BtZW50IERlcGFydG1lbnQgb2Yg
VmV0ZXJhbnMgQWZmYWlycyBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBALPEICH8rmhLVSTeg4AWUBj9uOGz5Gjb1FDAp6Ge1zwL1yX9nVewzCFtdRUU
mdLa7bbM1R5Bjzhl1/nRW/NBUSU4uRd9bDuLCtoqt1P2jxw0SJm1rk3I/3s7C5ne
G25xShpT0Iid78vbvycAfcMggOEC68GsBb5qyiAYJMMEKs9T8ch6e0ihvXNJ6OqD
TIKOCQZZa0WMw/rKXNZHNEEZZBQOrZesaPXVrkd8Dlu9duY158BzLLGgU4aWIDvF
5DnCJ2DdUwG5rcfbUYa0o+IPM3M1Hvmn0VAJ9624w7BDPcDi9dnAWmFSO3UEjuHg
3JhBFI7wdSjOCPFInhIdDiN1y5sCAwEAAaOCAp8wggKbMA4GA1UdDwEB/wQEAwIB
BjAPBgNVHRMBAf8EBTADAQH/MIGXBgNVHSAEgY8wgYwwDAYKYIZIAWUDAgEwCDAM
BgpghkgBZQMCATAJMAwGCmCGSAFlAwIBMAowDAYKYIZIAWUDAgEwCzAMBgpghkgB
ZQMCATAMMAwGCmCGSAFlAwIBMA0wDAYKYIZIAWUDAgEwVjAMBgpghkgBZQMCATBi
MAwGCmCGSAFlAwIBMG0wDAYKYIZIAWUDAgEwbjBRBggrBgEFBQcBAQRFMEMwQQYI
KwYBBQUHMAKGNWh0dHA6Ly9kZXZwa2kudHJlYXN1cnkuZ292L2NhY2VydHNpc3N1
ZWR0b2RldnRyY2EucDdjMEYGCCsGAQUFBwELBDowODA2BggrBgEFBQcwBYYqaHR0
cDovL2RldnBraS50cmVhc3VyeS5nb3YvZGV2dmFjYV9zaWEucDdjMIIBAQYDVR0f
BIH5MIH2MDygOqA4hjZodHRwOi8vZGV2cGtpLnRyZWFzdXJ5Lmdvdi9EZXZfVVNf
VHJlYXN1cnlfUm9vdF9DQS5jcmwwgbWggbKgga+kgawwgakxCzAJBgNVBAYTAlVT
MRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxIzAhBgNVBAsTGkRlcGFydG1lbnQg
b2YgdGhlIFRyZWFzdXJ5MSIwIAYDVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhvcml0
aWVzMSgwJgYDVQQLEx9EZXZlbG9wbWVudCBVUyBUcmVhc3VyeSBSb290IENBMQ0w
CwYDVQQDEwRDUkwxMB8GA1UdIwQYMBaAFIxsS3kzHbgb1kDQKehdtwk5QQZpMB0G
A1UdDgQWBBQvygUowd39TGhKfa/NKFafnoxDXTANBgkqhkiG9w0BAQsFAAOCAQEA
aK7ZcU5gsNyR5DM6m5U/012nSoJ1NLKQlO3pH29z+HQp8qC8AtmiZU38JJnUQiPo
y6T0gBz2+2La8E0vNsMnz5uOuK7IY2F+yJVvQxJl5tVVpJnL1ieD2FJYGZdpnsWB
70VNNuyfGL2iXHMiUimYhQZne71d2uWabTUkfywgvjOk2laTrx8rm0d+SZOsm4+t
ZjCBmsCMnc61Oyr/hQF2BW1MTRa96mQNvueLf1Pw8OpFeugVXGRtf14vDfiC/Gen
upFPF8758+B70Xh2MKNWCUeP4b7o0gnTM85q4eumfLUtoXBHpeFddBSu1tlmRX88
IQxV1Pqa4rW0RBU+MXJmaDCCB44wggV2oAMCAQICBFOXerQwDQYJKoZIhvcNAQEL
BQAwgZoxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxIzAh
BgNVBAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYDVQQLExlDZXJ0
aWZpY2F0aW9uIEF1dGhvcml0aWVzMSgwJgYDVQQLEx9EZXZlbG9wbWVudCBVUyBU
cmVhc3VyeSBSb290IENBMB4XDTA5MDMxODE5NDMzNVoXDTI5MDMxODIwMTMzNVow
gZoxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxIzAhBgNV
BAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYDVQQLExlDZXJ0aWZp
Y2F0aW9uIEF1dGhvcml0aWVzMSgwJgYDVQQLEx9EZXZlbG9wbWVudCBVUyBUcmVh
c3VyeSBSb290IENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoR1B
AI+w1UQepAfqGk4qAZklzEDi5pVBraxoVMsv6f4lC8+Tr0Hed60kQuV8H6yIWVHI
UncbEJByGUCnty6qEHReVwIi2ibHn6Dmg0i6OZSO26u35M3g8t96NdIv+wQw1shy
EczxQG/Xjjz09ed1bFCzGZX+KZDrYuPg+QqUBXgRNtYKLb9AHYO4wzV8vNYiAIbs
OBkyfIYEOCgjxLLhV8OgnctIEAO+Ek/c2Dz4Ip/L2LHk+Ki/DeuJ7/sVrAd7vx4t
XjMZoGkCsid/Brwpw+HUzgmoctfPNdcub8abxt18nhBrx49/lMzcMoXzCKI1KyKn
iUB28i+PSHmLana3RwIDAQABo4IC2DCCAtQwDgYDVR0PAQH/BAQDAgEGMA8GA1Ud
EwEB/wQFMAMBAf8wUQYIKwYBBQUHAQEERTBDMEEGCCsGAQUFBzAChjVodHRwOi8v
ZGV2cGtpLnRyZWFzdXJ5Lmdvdi9jYWNlcnRzaXNzdWVkdG9kZXZ0cmNhLnA3YzBG
BggrBgEFBQcBCwQ6MDgwNgYIKwYBBQUHMAWGKmh0dHA6Ly9kZXZwa2kudHJlYXN1
cnkuZ292L2RldnRyY2FsaW5rLnA3YzCBzwYDVR0gBIHHMIHEMAwGCmCGSAFlAwIB
MAgwDAYKYIZIAWUDAgEwCTAMBgpghkgBZQMCATAKMAwGCmCGSAFlAwIBMAswDAYK
YIZIAWUDAgEwDTAMBgpghkgBZQMCATAMMAwGCmCGSAFlAwIBMFYwDAYKYIZIAWUD
AgEwYjAMBgpghkgBZQMCATBtMAwGCmCGSAFlAwIBMG4wDAYKYIZIAWUDAgEwNzAM
BgpghkgBZQMCATA4MAwGCmCGSAFlAwIBMDkwDAYKYIZIAWUDAgEwSzAfBgNVHSME
GDAWgBQtJs/3OUA7rbYp1UFukSpVMnRfvjAdBgNVHQ4EFgQUjGxLeTMduBvWQNAp
6F23CTlBBmkwggECBgNVHR8EgfowgfcwgbWggbKgga+kgawwgakxCzAJBgNVBAYT
AlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxIzAhBgNVBAsTGkRlcGFydG1l
bnQgb2YgdGhlIFRyZWFzdXJ5MSIwIAYDVQQLExlDZXJ0aWZpY2F0aW9uIEF1dGhv
cml0aWVzMSgwJgYDVQQLEx9EZXZlbG9wbWVudCBVUyBUcmVhc3VyeSBSb290IENB
MQ0wCwYDVQQDEwRDUkwxMD2gO6A5hjdodHRwOi8vZGV2cGtpLnRyZWFzdXJ5Lmdv
di9EZXZfVVNfVHJlYXN1cnlfUm9vdF9DQTEuY3JsMA0GCSqGSIb3DQEBCwUAA4IC
AQAyZUOn1D/cHtOairXrrxkAkTS2ZSUrFGhPlKU5ozw9sWTlbHOnIholw+nrnoFm
lYC7HEGEhX1d3cT1kS34wtGS0NG1/cGfNOfYWPbhxXrSF5P0wkDfer94WwhXEpgS
WnOBXxlpp2B5qOf/N+SmqBkxWMofgp06HCuEBXr4oy2LshSUn9uNhLT1dbUtNBsz
ZxuSVT5G5oISoKH0ijMxqDYXVv+23pQPpelOuApmwo/2cxXRQmjQYdGrwsaz8OJR
F6UXSHUgjarfQ6tPnILkCpoNK2jng195B7BtDj5mAvVR/FzwX8XBXhllU8YyccrS
6X6+3wzP4LozlHfNbUHvc+tXINhPfXhsB8OQzzHG8NL0zIediJruN6l6zzHrdvId
qxe/kCcyprmdCeZ/t2P8YlMs6ylldzEu4BXq+fHSSAhDvSHdW9CGWTtpmqO1AW50
WZ42FM3K5Un/fMjOldh90eKanQI25J5u7osIRJAtcv2e2PBGxDzI9W3aelYlVY77
pyYCmbaxoB9QjcYHR1GRofQEaKwyxc3xnf/SBDC/fBDYNxJjPoS3shA/Kv/j662C
faIBsO3U/99gpwAaFTO8ACXyjmoXWmu9XgpH5et8cO//x7F3AzKnnVOVb6t/mGv4
ZMMeD3ti9zgjoTezvmcMUYuYZUjaMWYCVSe0JOsJJaBxyzCCCRswggcDoAMCAQIC
FDag4FH/iLOE4NydAoVVpAM+jIwiMA0GCSqGSIb3DQEBDAUAMHQxCzAJBgNVBAYT
AlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxETAPBgNVBAsTCEZQS0ktTEFC
MQ0wCwYDVQQLEwRDSVRFMSkwJwYDVQQDEyBUZXN0IEZlZGVyYWwgQ29tbW9uIFBv
bGljeSBDQSBHMjAeFw0yMDA2MjUxNjM3NTFaFw0yMzA2MjUxNjM3NTFaMIGaMQsw
CQYDVQQGEwJVUzEYMBYGA1UEChMPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLExpE
ZXBhcnRtZW50IG9mIHRoZSBUcmVhc3VyeTEiMCAGA1UECxMZQ2VydGlmaWNhdGlv
biBBdXRob3JpdGllczEoMCYGA1UECxMfRGV2ZWxvcG1lbnQgVVMgVHJlYXN1cnkg
Um9vdCBDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAKuWBrRkHVjK
9be3F11Rm+8JCHobGQfdRnEKcyAf2UB9SQkolivdC6aHwi089IkCcsoklr0UhAP8
1hV3hxaFsVhud3NEpX1SDSa0UPwmWzNzbjm0MCbsvmJD4vQt32HfS3YYlFsd8MbY
9Qqvr0xEBXhSuY2ts+2iog2hah5lgHRTF173R/xV4ebZbnZ3UOGJeoi0F1A40qqo
mcAwb+ts1P/4oWu3B0BTTcNXlq1kS6J+Tg8UUNsM5PDvtXLQE6Ju1msJmUSmivT5
prV0DJSkiGVp4YAoFX+vx325tKtbsO/RgfpFhq2rIxah+S9UbudJ4kvdT2EOpIt9
56U0xf8cRlXYZVlLeYaYKf37dloZb5Ya5XTmD86OWkTv14xOON+a0xjIWREXegsc
R8FOMec2Rq9/W+9xNvP2oq+83bFEUn5TKiXSTtW8A0z1nXq6TF/WJiVY31C/iN5V
tFyGeNdMlEvYs+sBwao61eQ+2QQVLGKDGUinwsOGHfgPeR8orD3qLzNIFFt2Sx0b
ILBNK5v7ZwFMHN/4O499MuvbU344D0vORCXAo3bqgUUQjHFpIy4iRn9z8GWGl37N
7Gf7pe6cXgqNM90qZ/THhdXBsG3yStvZ2knF4rumlL432W1Sg9+nd17upxA+SX7V
NEwZrpjMAlR00wRxMDN86IXbhmh0YZ+/AgMBAAGjggN8MIIDeDAdBgNVHQ4EFgQU
LSbP9zlAO622KdVBbpEqVTJ0X74wHwYDVR0jBBgwFoAUqpHlKOZcY6qqXQKswgjL
wOnQJCQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8wgd0GA1UdIASB
1TCB0jAMBgpghkgBZQMCATABMAwGCmCGSAFlAwIBMAIwDAYKYIZIAWUDAgEwTjAM
BgpghkgBZQMCATBPMAwGCmCGSAFlAwIBMFAwDAYKYIZIAWUDAgEwCDAMBgpghkgB
ZQMCATAJMAwGCmCGSAFlAwIBMAowDAYKYIZIAWUDAgEwYjAMBgpghkgBZQMCATAL
MAwGCmCGSAFlAwIBMAwwDAYKYIZIAWUDAgEwDTAMBgpghkgBZQMCATBWMAwGCmCG
SAFlAwIBMG0wDAYKYIZIAWUDAgEwbjCCASsGA1UdIQSCASIwggEeMBgGCmCGSAFl
AwIBMAEGCmCGSAFlAwIBMDcwGAYKYIZIAWUDAgEwAgYKYIZIAWUDAgEwODAYBgpg
hkgBZQMCATAIBgpghkgBZQMCATAIMBgGCmCGSAFlAwIBMAgGCmCGSAFlAwIBMEsw
GAYKYIZIAWUDAgEwCQYKYIZIAWUDAgEwCTAYBgpghkgBZQMCATAJBgpghkgBZQMC
ATA5MBgGCmCGSAFlAwIBMAwGCmCGSAFlAwIBMAwwGAYKYIZIAWUDAgEwDAYKYIZI
AWUDAgEwOjAYBgpghkgBZQMCATBOBgpghkgBZQMCATBvMBgGCmCGSAFlAwIBME8G
CmCGSAFlAwIBMHAwGAYKYIZIAWUDAgEwUAYKYIZIAWUDAgEwcTBDBggrBgEFBQcB
CwQ3MDUwMwYIKwYBBQUHMAWGJ2h0dHA6Ly9kZXZwa2kudHJlYXMuZ292L2RldnJv
b3Rfc2lhLnA3YzAPBgNVHSQECDAGgAEAgQEAMAoGA1UdNgQDAgEAMF4GCCsGAQUF
BwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3JlcG8uY2l0ZS5mcGtpLWxhYi5n
b3YvZmNwY2EvY2FDZXJ0c0lzc3VlZFRvVGVzdGZjcGNhZzIucDdjMEQGA1UdHwQ9
MDswOaA3oDWGM2h0dHA6Ly9yZXBvLmNpdGUuZnBraS1sYWIuZ292L2ZjcGNhL1Rl
c3RmY3BjYWcyLmNybDANBgkqhkiG9w0BAQwFAAOCAgEAOHodw94IInV2ug8RS5Io
LevLY6aTeKnHUoMQyfHMPqF8eIioe7N732L84BKNTIzNZlNc4Fz1ztUa1fR6XXj9
Bw6HDB9F1nFdaty/Yzg1Vkl2Q0UUAp/UYYMQUvJK2Efgc6/C09L+ao+hYA5+rklR
uYx1rm6bQQt/fPHKY7FH/QxdMy1bnPoaiwDkHnEbvQbXDqR1k/yElnVTm53dotRS
1O6DHThCpiGxgy0ftTH/wGNkJsQ2dA/5dRbsawSVKgUThiKevF+a6jzSZemAockb
VArE4z4w9W1DlkYb9pPtPUln0eMH80MuWHC+Q9AWKB9LMPAhq0ZRW94TN17IAhcG
DGrk2PoaEsC8TKtlJIyD1leDvG0Q25LNvN+4u/yZqojrmYl5Bvp9MKUnL7U8t00a
KOAqlWOx8P460P4uIBnbivjX3waxLfUVLejaesznjYpeKpstQG2ZOoUHsqov9vW+
KP/I0YCXT/Kr21am+2RS85+u4SN5P6cQUvRawaH+24LGff1bwPCXZcPHIk5yCv0H
8YCE2BojeJGqiPOM5PQu62WRFefvdLteDMHeMl8pXf0ihrOzAKVJN6EfeUyLKYN2
JeAhTrPe8KeAPGyff78Tfywybh8+t++7s606IhJsasjfznXsGQToqgarXHsfoSzS
nSml9Y+QeSEatY/MclDLIDyBDzIwMjEwMjA0MDA1MDQ1WqCCBUowggVGMIIDLqAD
AgECAgkAwqCvfJzO2dwwDQYJKoZIhvcNAQELBQAwgZsxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxIzAhBgNVBAsTGkRlcGFydG1lbnQgb2Yg
dGhlIFRyZWFzdXJ5MRwwGgYDVQQLExNWYWxpZGF0aW9uIFNlcnZpY2VzMS8wLQYD
VQQDEyZEZXZlbG9wbWVudCBWYWxpZGF0aW9uIFNlcnZpY2VzIENBIEcwMTAeFw0y
MDA5MjQxNjAzMzlaFw0yMzA5MjQxNjAzMzlaMIGrMQswCQYDVQQGEwJVUzEYMBYG
A1UECgwPVS5TLiBHb3Zlcm5tZW50MSMwIQYDVQQLDBpEZXBhcnRtZW50IG9mIHRo
ZSBUcmVhc3VyeTEoMCYGA1UECwwfRGV2ZWxvcG1lbnQgVmFsaWRhdGlvbiBTZXJ2
aWNlczEzMDEGA1UEAwwqRGV2ZWxvcG1lbnQgVmFsaWRhdGlvbiBTZXJ2aWNlcyBT
aWduZXIgRzAxMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr82WOhQ9
bjhJ9JkC6bb4k2EyCL8IWLf/MrdPjAYscKPMFLqhCVHFr2Ezqqk3AXizi8D1CEyE
Cp+vD/vsMJvfCyZbj0rR4XGzphvMBB3ff7yqSLUfYgOoG97TkDugx7346GFa/U4m
5U0dDbVvTpG3TOXpon1eQHhzIlv0ukhM8YK2MGCJvx/69X7idkXX8q+s2DR53R84
gSTrsIANhBTRoo4wXkEhbKNK2gPGLCDj6CQI9/2CmyBdRts0ytSuqizx1VP4f03l
+mg1aTvABu9/TJ7I+k4DWo0r752CqK5Id2OaWBXTaAiI0elI2w2B4COKhNbNL/zW
91INt49IMR45kQIDAQABo3sweTAOBgNVHQ8BAf8EBAMCB4AwJwYDVR0lBCAwHgYI
KwYBBQUHAwEGCCsGAQUFBwMJBggrBgEFBQcDDzAfBgNVHSMEGDAWgBQ2zH3+UZt7
Iq041jcIz3i7yit6SjAdBgNVHQ4EFgQUEE0NAHK4SNNLMUbNl+Xkg5KLPgQwDQYJ
KoZIhvcNAQELBQADggIBAADT0ix4OfCSdi8OgJCIW8GpsL6am9LeKfh467R4fDss
CHjW9+gfRk2VQq8SWhDkIK/T5ItQaDqlb9WKdQn7f/EdXMcarGr9N1dYDdOaGA8G
MITnMQT8s+4AoXAMb2oZmuwadV0tTg8t+PzD/S7L07BblRC8MA2mx95eeoo45WaY
pWiaC+9z0DcEXeRVdwROQacY1S3Ofe4Va77K09Ikvzky43jEdvDD38ZNdbowckHX
CNDfs7B9oGDR6zLzGNDPiCUfYJgGBqZJElwHHByAmd/4Wly4uHyYd2HaiY2d/WZx
BjXQ1cZ23/7Pd29ejUcaMJe65FAgpry/C01Xz2AOTBsNacAH6x6a8Wyw9jV2RSDI
RNYbgimZhIUi2r7GEbRQw4IQrshDoPjz0AxDL3J8KR+Ll0njPqBpob/dlBg4iKq8
T9CdtIkZpAQrgsL4PAbB8vgGFQcbRyi/WRmDD2oSr82XinKoqPb7yDi0DKoWMJXr
LOChtCNOJRHajOnQHpLEVHObWVdNegHm5fer3Yi89iJgKpeBVkQZeTJgTQd2IihA
bd8F5vwgDjqPMiuqpMGYw6Ve3c7hTqobjhcSH2RDkazvUQsm8+TsQ0XbqbeUeXDF
9Cfsay2E4WWIIyijY4FcHW/jdUxLCKqM4eeXzgpJbWxb9e01GQGkBEWZks982oSH
MYICQDCCAjwCAQEwgakwgZsxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdv
dmVybm1lbnQxIzAhBgNVBAsTGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MRww
GgYDVQQLExNWYWxpZGF0aW9uIFNlcnZpY2VzMS8wLQYDVQQDEyZEZXZlbG9wbWVu
dCBWYWxpZGF0aW9uIFNlcnZpY2VzIENBIEcwMQIJAMKgr3ycztncMAsGCWCGSAFl
AwQCAaBrMBoGCSqGSIb3DQEJAzENBgsqhkiG9w0BCRABCzAcBgkqhkiG9w0BCQUx
DxcNMjEwMjAzMTg1MDQ1WjAvBgkqhkiG9w0BCQQxIgQgevj+6BmMS5pBhPqnD6SZ
0AHGAK7dUiXMVY/Lpiwe+KQwDQYJKoZIhvcNAQEBBQAEggEAUkYnVWgM64B8xyUe
m/eWhxwO8Ywhu/QANcznMJJO12aKvfy1kocLzL6Y4JtqnwS66iQtLZ/5NpjN/Rs5
zjAH0iwA5h69WrLqTmAnO5qyRvjYdJTuVbxwr77QsqWydjG178iRNxcXbjNHYIlX
Meb1X7VYud64kkyW9Qg6fWkX/82LoaXtIBq9l4kun5sY7qVGoLExGIaTjl2XDNjn
qYWwLQzS2Vue93wPiswaW9QssrRr/L4NgX/7Ukx9SgnM6m3eCX8B71+C3ZnC2Yc1
Tvsh8Q651nTDnVqqjKV/DZ1GbztADNmxaC0myC41nNEOv+eMt6Uony2FFXBIEc6z
vMNSPw==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc5055.id_ct_scvp_certValResponse, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        substrate = pem.readBase64fromText(self.cvresponse_pem_text)

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual('URN:VSSAPI:vss-dv-rs-p11',
            asn1Object['requestorName'][0]['uniformResourceIdentifier'])

        found = False
        for cr in asn1Object['replyObjects']:
            for rwb in cr['replyWantBacks']:
                if rwb['wb'] in rfc5055.scvpWantBackMap:
                    wbv, rest = der_decoder(rwb['value'], 
                        asn1Spec=rfc5055.scvpWantBackMap[rwb['wb']])
                    self.assertFalse(rest)
                    self.assertTrue(wbv.prettyPrint())
                    self.assertEqual(rwb['value'], der_encoder(wbv))
            
                    self.assertEqual(2, wbv[0]['tbsCertificate']['version'])
                    found = True

        self.assertTrue(found)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cvresponse_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        substrate = asn1Object['content']['encapContentInfo']['eContent']
        oid = asn1Object['content']['encapContentInfo']['eContentType']
        asn1Spec = rfc5652.cmsContentTypesMap[oid]
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual('URN:VSSAPI:vss-dv-rs-p11',
            asn1Object['requestorName'][0]['uniformResourceIdentifier'])

        found = False
        for cr in asn1Object['replyObjects']:
            for rwb in cr['replyWantBacks']:
                if rwb['wb'] in rfc5055.scvpWantBackMap:
                    wbv, rest = der_decoder(rwb['value'], 
                        asn1Spec=rfc5055.scvpWantBackMap[rwb['wb']],
                        decodeOpenTypes=True)
                    self.assertFalse(rest)
                    self.assertTrue(wbv.prettyPrint())
                    self.assertEqual(rwb['value'], der_encoder(wbv))
            
                    self.assertEqual(2, wbv[0]['tbsCertificate']['version'])
                    found = True

        self.assertTrue(found)

class SCVPValPolRequestTestCase(unittest.TestCase):
    valpolrequest_pem_text = """\
MCMGCyqGSIb3DQEJEAEMoBQwEgQQ7V8C3E2ZIRLNgTQZzWGb+Q==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc5055.id_ct_scvp_valPolRequest, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
        }

        substrate = pem.readBase64fromText(self.valpolrequest_pem_text)

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(1, asn1Object['vpRequestVersion'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.valpolrequest_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(1, asn1Object['content']['vpRequestVersion'])

class SCVPValPolResponseTestCase(unittest.TestCase):
    valpolresponse_pem_text = """\
MIIW0wYJKoZIhvcNAQcCoIIWxDCCFsACAQMxDTALBglghkgBZQMEAgEwgg8YBgsq
hkiG9w0BCRABDaCCDwcEgg8DMIIO/wIBAQIBAQIBAQIEYAdEhhgPMjAyMTAyMDMx
NjIwMDdaGA8yMDIxMDIwMzIwMjAwN1owMgYIKwYBBQUHEQEGCCsGAQUFBxECBggr
BgEFBQcTAwYIKwYBBQUHEwIGCCsGAQUFBxEDMCgGCCsGAQUFBxIBBggrBgEFBQcS
BAYIKwYBBQUHEgIGCCsGAQUFBxIKMIIDVAYLYIZIAWUKAhICAAsGC2CGSAFlCgIS
AgAKBgtghkgBZQoCEgIAAQYLYIZIAWUKAhICAAIGC2CGSAFlCgISAgADBgtghkgB
ZQoCEgIABAYKYIZIAWUDAgEwAgYKYIZIAWUDAgEwBQYKYIZIAWUDAgEwBgYKYIZI
AWUDAgEwTwYKYIZIAWUDAgEwUAYKYIZIAWUDAgEwTgYKYIZIAWUDAgEwAQYKYIZI
AWUDAgEwCwYKYIZIAWUDAgEwDQYKYIZIAWUDAgEwbQYKYIZIAWUDAgEwbgYKYIZI
AWUDAgEwCgYKYIZIAWUDAgEwYgYKYIZIAWUDAgEwCQYKYIZIAWUDAgEwDAYKYIZI
AWUDAgEwVgYKYIZIAWUDAgEwCAYIKwYBBQUHEwEGC2CGSAFlCgISAgELBgtghkgB
ZQoCEgIBAQYLYIZIAWUKAhICAQIGC2CGSAFlCgISAgEDBgtghkgBZQoCEgIBBAYM
YIZIAWUKAhICAodpBgxghkgBZQoCEgICh2oGDGCGSAFlCgISAgKHawYMYIZIAWUK
AhICAodsBgtghkgBZQoCEgICAgYLYIZIAWUKAhICAg4GC2CGSAFlCgISAgIPBgtg
hkgBZQoCEgICEwYLYIZIAWUKAhICAhQGC2CGSAFlCgISAgISBgtghkgBZQoCEgIC
AQYLYIZIAWUKAhICAg0GC2CGSAFlCgISAgIRBgtghkgBZQoCEgICKAYLYIZIAWUK
AhICAikGC2CGSAFlCgISAgIIBgtghkgBZQoCEgICJAYLYIZIAWUKAhICAgcGC2CG
SAFlCgISAgIQBgtghkgBZQoCEgICJwYLYIZIAWUKAhICAgYGDGCGSAFlCgISAgKH
cwYKYIZIAWUDAgEDAgYKYIZIAWUDAgEDDgYKYIZIAWUDAgEDDwYKYIZIAWUDAgED
EwYKYIZIAWUDAgEDFAYKYIZIAWUDAgEDEgYKYIZIAWUDAgEDAQYKYIZIAWUDAgED
DQYKYIZIAWUDAgEDEQYKYIZIAWUDAgEDKAYKYIZIAWUDAgEDKQYKYIZIAWUDAgED
CAYKYIZIAWUDAgEDJAYKYIZIAWUDAgEDBwYKYIZIAWUDAgEDEAYKYIZIAWUDAgED
JwYKYIZIAWUDAgEDBjAKBggrBgEFBQcTAzAACgECMIIKqDAKBggrBgEFBQcTAaEG
BgRVHSAAggEAgwEAhAH/pYIKgqCCBGAwggNIoAMCAQICAgEwMA0GCSqGSIb3DQEB
CwUAMFkxCzAJBgNVBAYTAlVTMRgwFgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTAL
BgNVBAsTBEZQS0kxITAfBgNVBAMTGEZlZGVyYWwgQ29tbW9uIFBvbGljeSBDQTAe
Fw0xMDEyMDExNjQ1MjdaFw0zMDEyMDExNjQ1MjdaMFkxCzAJBgNVBAYTAlVTMRgw
FgYDVQQKEw9VLlMuIEdvdmVybm1lbnQxDTALBgNVBAsTBEZQS0kxITAfBgNVBAMT
GEZlZGVyYWwgQ29tbW9uIFBvbGljeSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
ADCCAQoCggEBANh1+zUWNFpBv1qvXDAEFByteES16ibqdWHHzTZ5+HzYvSlRZlkh
43mr1Hi+sC2wodWyNRYj0Mwevg7oq9zDydYS16dyaBgxuBcisj5+ughtxv3RWCxp
oAPwKqP2PyElPd+3MsWOJ7MjpeBSs12W6bC4xcWfu8WgboJAu8UnBTZJ1iYnaQw0
j88neioKo0FfjR0DhoMV4FXBxZgsnuwactxIwT75hNKEgsEbw3Q2t7nHNjJ6+DK2
0DauIhgxjFBzIZ7+gzswiCTj6cF+3u2Yxx+SEIqfW2IvnaS81YVvOv3JU6cgS6rb
IKshTh0NTuaYheWrEUddnT/EI8DjFAZu/p0CAwEAAaOCATAwggEsMA8GA1UdEwEB
/wQFMAMBAf8wgekGCCsGAQUFBwELBIHcMIHZMD8GCCsGAQUFBzAFhjNodHRwOi8v
aHR0cC5mcGtpLmdvdi9mY3BjYS9jYUNlcnRzSXNzdWVkQnlmY3BjYS5wN2MwgZUG
CCsGAQUFBzAFhoGIbGRhcDovL2xkYXAuZnBraS5nb3YvY249RmVkZXJhbCUyMENv
bW1vbiUyMFBvbGljeSUyMENBLG91PUZQS0ksbz1VLlMuJTIwR292ZXJubWVudCxj
PVVTP2NBQ2VydGlmaWNhdGU7YmluYXJ5LGNyb3NzQ2VydGlmaWNhdGVQYWlyO2Jp
bmFyeTAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFK0MenVc5fOYxHmYDqwo/Zf0
5wL8MA0GCSqGSIb3DQEBCwUAA4IBAQCPc9rhf4Cxh/bsLM/RhGMe9vGIt5ryEbXv
VK2Kbhg3KO9cG+TvULdsJhgjIk0dJkcg6Qmc4nBicasRz5GJ6LP1KqBHwBTLTkLB
3QwOG/CHW+zld9eq4FTXRfSFPuy0Hd58in9bTZyWitCiMp/abDEM+KTvfnPokdwI
enBaoK9igVn4AHSiyN1UykFWR73pwE/tIN3jpQnfrijC/NHIF9gSx2/eLum9mpHy
PFqULpEigImhjFjMg3omGXUCpQ59CiZzUeqGyweoyP1jWjWb0q+/TzFIwYRw2zV7
mhkP5Y/0agxvM9nrHHCiDeO5UANhAv9K7JKk3C3uKjSTB7cs5xiPoIIGGjCCBAKg
AwIBAgIUNCyN+1i9mr19nWjJHSFZF0YeYp0wDQYJKoZIhvcNAQEMBQAwdDELMAkG
A1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDERMA8GA1UECxMIRlBL
SS1MQUIxDTALBgNVBAsTBENJVEUxKTAnBgNVBAMTIFRlc3QgRmVkZXJhbCBDb21t
b24gUG9saWN5IENBIEcyMB4XDTIwMDIwNDE4MTY1N1oXDTQwMDIwMzE4MTY1N1ow
dDELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDERMA8GA1UE
CxMIRlBLSS1MQUIxDTALBgNVBAsTBENJVEUxKTAnBgNVBAMTIFRlc3QgRmVkZXJh
bCBDb21tb24gUG9saWN5IENBIEcyMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
CgKCAgEApUd8tUk14kAKR+s5oavYn4UnNk2SVDMUEnQ4yD80FERV74wM1IvwvGjM
svluZP92GSHr+0f6nUpTksndPwKNEL21JlMmhR2et7cNncyVJBSf6tdXLNPrnWIK
roJ2KE/qvibfKTC+td70C9K41xuj25MCNQR6hri3IVnpjzfq1Cdnii/Z0q8ypjDi
V2i3usUp+cguDLYoPSr8i89dLi897RyzdVDto9aCGIC6E0Gq1+HofqWp/I/I7NXZ
h0xcstmzUGQIKuYXn9JcrUHv1I7iSdKlAWzhoD6cgqfenB4A++DetedHb0mlAP8Q
LpAypcAc5guRdHnKIewlyUznSyfmmVxmxfMUKCZWqGve1o5Onm5sk41mR/905y8C
GXH6aAK0fKKNK336q0ss+apZeSBgYMKPafCLUhTUZQjKxsp/TPuxHrf4SWCxUOxo
r9BrRqRa72ZtPmfrcD3KCSTW3m4mV2PbbH/ZhDJz89gp8XmCwiKEgT/1vSgro9WM
JB33eBSfhMAbVbczlvjQYu1GXES08BuVjNg3Oam021Kbhhty0O8l2xwoFFahMQdL
ydQFaxT8w19c13KLL8zT3p6ipJeD57S16NomPwzHzNtdwQT5jWGbBXAniOx4A8Ye
Qq4OCV/DHBoGbC3z4DPxkv3Zzq1qvEo8G8Xro5f95Y2UoWJT7GcCAwEAAaOBozCB
oDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB/wQEAwIBBjAdBgNVHQ4EFgQUqpHl
KOZcY6qqXQKswgjLwOnQJCQwXgYIKwYBBQUHAQsEUjBQME4GCCsGAQUFBzAFhkJo
dHRwOi8vcmVwby5jaXRlLmZwa2ktbGFiLmdvdi9mY3BjYS9jYUNlcnRzSXNzdWVk
QnlUZXN0ZmNwY2FnMi5wN2MwDQYJKoZIhvcNAQEMBQADggIBAASXdqBEnnTZZ7NH
1mTXnc5hRYYQptDvTGdam5r1D3fXN3NBuVwMSN7xfoa0Lp0Fw3ACkxgqycCvDrHL
Rn+vU3nZcCFroNrXVxgSwV66KfZS2ToouViqoXI4OWM16oX8NY7m+eQ39tM9YQYG
52Z8QVKEss1sXfRmN32WRyLiYsIEbh5w08PwJZO18BWoCbLnpa8VuEJO9srxcD7j
0ZeHcMFKnI4TKm/j0SI/BizQ+Qd9PzoKjsqfsQtMwN/OSxorqVVOGnOdvfueXCOe
VZNgRP8oKYGv8glwtkV2XUvgLBksZDYvaGcVBs8015NJiDKOYpQ9GNkZHfOFL20Q
tnl9KKDuhd+RB6yfLO7RGmVugOTEErNh8gv2RQNlODCHqgBpnxEU2qL9WmafiiXo
H6oP2uKoOACBP2tlUu9TCOYpoKTL0+7EvbppZNqUxF7h+fHTbZoIRy4PFYySvAL2
8ad6YM5E7wyYO7PBhzeUVIaIDFoTgRA1hPo6qdW2gdfGdJ0K5HjVRzi9RJh0xw8J
icJJDgE5/OpzEZDf0gPqNE/8G0qYVXHsV805KHz5rqLxfqzWpEnBeQjwzRVq2H45
Pw5CoKDciNE937/UeJmt1RFu+W7bikaJ9A3xETJ/bHDralo6nZX4G1vOMLifElLN
i4OPfxTf9eteFay9eJLnf6uAeOs9pgMDAQADAgTQMA8wDQYJKoZIhvcNAQELBQAw
DzANBgkqhkiG9w0BAQsFADAzBglghkgBZQMEAgEGBSsOAwIaBglghkgBZQMEAgQG
CWCGSAFlAwQCAgYJYIZIAWUDBAIDoIIFSjCCBUYwggMuoAMCAQICCQDCoK98nM7Z
3DANBgkqhkiG9w0BAQsFADCBmzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4g
R292ZXJubWVudDEjMCEGA1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkx
HDAaBgNVBAsTE1ZhbGlkYXRpb24gU2VydmljZXMxLzAtBgNVBAMTJkRldmVsb3Bt
ZW50IFZhbGlkYXRpb24gU2VydmljZXMgQ0EgRzAxMB4XDTIwMDkyNDE2MDMzOVoX
DTIzMDkyNDE2MDMzOVowgasxCzAJBgNVBAYTAlVTMRgwFgYDVQQKDA9VLlMuIEdv
dmVybm1lbnQxIzAhBgNVBAsMGkRlcGFydG1lbnQgb2YgdGhlIFRyZWFzdXJ5MSgw
JgYDVQQLDB9EZXZlbG9wbWVudCBWYWxpZGF0aW9uIFNlcnZpY2VzMTMwMQYDVQQD
DCpEZXZlbG9wbWVudCBWYWxpZGF0aW9uIFNlcnZpY2VzIFNpZ25lciBHMDEwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvzZY6FD1uOEn0mQLptviTYTII
vwhYt/8yt0+MBixwo8wUuqEJUcWvYTOqqTcBeLOLwPUITIQKn68P++wwm98LJluP
StHhcbOmG8wEHd9/vKpItR9iA6gb3tOQO6DHvfjoYVr9TiblTR0NtW9OkbdM5emi
fV5AeHMiW/S6SEzxgrYwYIm/H/r1fuJ2Rdfyr6zYNHndHziBJOuwgA2EFNGijjBe
QSFso0raA8YsIOPoJAj3/YKbIF1G2zTK1K6qLPHVU/h/TeX6aDVpO8AG739Mnsj6
TgNajSvvnYKorkh3Y5pYFdNoCIjR6UjbDYHgI4qE1s0v/Nb3Ug23j0gxHjmRAgMB
AAGjezB5MA4GA1UdDwEB/wQEAwIHgDAnBgNVHSUEIDAeBggrBgEFBQcDAQYIKwYB
BQUHAwkGCCsGAQUFBwMPMB8GA1UdIwQYMBaAFDbMff5Rm3sirTjWNwjPeLvKK3pK
MB0GA1UdDgQWBBQQTQ0AcrhI00sxRs2X5eSDkos+BDANBgkqhkiG9w0BAQsFAAOC
AgEAANPSLHg58JJ2Lw6AkIhbwamwvpqb0t4p+HjrtHh8OywIeNb36B9GTZVCrxJa
EOQgr9Pki1BoOqVv1Yp1Cft/8R1cxxqsav03V1gN05oYDwYwhOcxBPyz7gChcAxv
ahma7Bp1XS1ODy34/MP9LsvTsFuVELwwDabH3l56ijjlZpilaJoL73PQNwRd5FV3
BE5BpxjVLc597hVrvsrT0iS/OTLjeMR28MPfxk11ujByQdcI0N+zsH2gYNHrMvMY
0M+IJR9gmAYGpkkSXAccHICZ3/haXLi4fJh3YdqJjZ39ZnEGNdDVxnbf/s93b16N
Rxowl7rkUCCmvL8LTVfPYA5MGw1pwAfrHprxbLD2NXZFIMhE1huCKZmEhSLavsYR
tFDDghCuyEOg+PPQDEMvcnwpH4uXSeM+oGmhv92UGDiIqrxP0J20iRmkBCuCwvg8
BsHy+AYVBxtHKL9ZGYMPahKvzZeKcqio9vvIOLQMqhYwless4KG0I04lEdqM6dAe
ksRUc5tZV016Aebl96vdiLz2ImAql4FWRBl5MmBNB3YiKEBt3wXm/CAOOo8yK6qk
wZjDpV7dzuFOqhuOFxIfZEORrO9RCybz5OxDRdupt5R5cMX0J+xrLYThZYgjKKNj
gVwdb+N1TEsIqozh55fOCkltbFv17TUZAaQERZmSz3zahIcxggJAMIICPAIBATCB
qTCBmzELMAkGA1UEBhMCVVMxGDAWBgNVBAoTD1UuUy4gR292ZXJubWVudDEjMCEG
A1UECxMaRGVwYXJ0bWVudCBvZiB0aGUgVHJlYXN1cnkxHDAaBgNVBAsTE1ZhbGlk
YXRpb24gU2VydmljZXMxLzAtBgNVBAMTJkRldmVsb3BtZW50IFZhbGlkYXRpb24g
U2VydmljZXMgQ0EgRzAxAgkAwqCvfJzO2dwwCwYJYIZIAWUDBAIBoGswGgYJKoZI
hvcNAQkDMQ0GCyqGSIb3DQEJEAENMBwGCSqGSIb3DQEJBTEPFw0yMTAyMDMxODUw
NDVaMC8GCSqGSIb3DQEJBDEiBCBNe4gMf/CK0YfMMwpfQDY+aAd/sHof7E9Fqzte
OVqCLzANBgkqhkiG9w0BAQEFAASCAQB6fl0h9synmcZVe9JIvlcu8y5j3QR89Tb8
LJohW2XCporoWa5YSbpBe24RY+lLUcuivqMOZI7oLrsYi5mys7W5V0PXe7JKkIxd
ypjuIwJ4gVZwDKf5En3hXEEtyvZO21JaeS700vbON25PdyvYagkj3GW+669UbnZ1
EBej/AyuYetWPssYijwSnff6hMXe32rAw8EO6xNJAFlSF4tok46y+hjIqLKa4Iv/
jebhte+biL9MxdHVTOLjn7OU6MWiAgahv0UJNKEX5+2QpxCBf0FFMEHXmb5x5D+o
Y8yBvZcgq9UK6oRgyI81bE26Fo7mDVvhfb40vehuJ9ql22CoFMm0
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc5055.id_ct_scvp_valPolResponse, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        substrate = pem.readBase64fromText(self.valpolresponse_pem_text)

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(10, asn1Object['clockSkew'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.valpolresponse_pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        substrate = asn1Object['content']['encapContentInfo']['eContent']
        oid = asn1Object['content']['encapContentInfo']['eContentType']
        asn1Spec = rfc5652.cmsContentTypesMap[oid]
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(10, asn1Object['clockSkew'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
