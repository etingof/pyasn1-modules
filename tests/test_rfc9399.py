#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9399
from pyasn1_alt_modules import opentypemap


class CertificateLogotypeURLTestCase(unittest.TestCase):
    pem_text = """\
MIIC9zCCAn2gAwIBAgIJAKWzVCgbsG46MAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMTkwNTE0MTAwMjAwWhcNMjAwNTEzMTAwMjAwWjBlMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xGzAZBgNVBAoTElZp
Z2lsIFNlY3VyaXR5IExMQzEaMBgGA1UEAxMRbWFpbC52aWdpbHNlYy5jb20wdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAATwUXZUseiOaqWdrClDCMbp9YFAM87LTmFirygp
zKDU9cfqSCg7zBDIphXCwMcS9zVWDoStCbcvN0jw5CljHcffzpHYX91P88SZRJ1w
4hawHjOsWxvM3AkYgZ5nfdlL7EajggEdMIIBGTALBgNVHQ8EBAMCB4AwQgYJYIZI
AYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9y
IGFueSBwdXJwb3NlLjAdBgNVHQ4EFgQU8jXbNATapVXyvWkDmbBi7OIVCMEwHwYD
VR0jBBgwFoAU8jXbNATapVXyvWkDmbBi7OIVCMEwgYUGCCsGAQUFBwEMBHkwd6J1
oHMwcTBvMG0WCWltYWdlL3BuZzAzMDEwDQYJYIZIAWUDBAIBBQAEIJtBNrMSSNo+
6Rwqwctmcy0qf68ilRuKEmlf3GLwGiIkMCsWKWh0dHA6Ly93d3cudmlnaWxzZWMu
Y29tL3ZpZ2lsc2VjX2xvZ28ucG5nMAoGCCqGSM49BAMDA2gAMGUCMGhfLH4kZaCD
H43A8m8mHCUpYt9unT0qYu4TCMaRuOTYEuqj3qtuwyLcfAGuXKp/oAIxAIrPY+3y
Pj22pmfmQi5w21UljqoTj/+lQLkU3wfy5BdVKBwI0GfEA+YL3ctSzPNqAA==
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

            if extn['extnID'] == rfc9399.id_pe_logotype:
                s = extn['extnValue']
                logotype, rest = der_decoder(s, rfc9399.LogotypeExtn())
                self.assertFalse(rest)
                self.assertTrue(logotype.prettyPrint())
                self.assertEqual(s, der_encoder(logotype))

                im0 = logotype['subjectLogo']['direct']['image'][0]
                mt = im0['imageDetails']['mediaType']
                self.assertEqual( "image/png", mt)

                expected = 'http://www.vigilsec.com/vigilsec_logo.png'
                url = im0['imageDetails']['logotypeURI'][0]
                self.assertEqual(expected, url)

        self.assertIn(rfc9399.id_pe_logotype, extn_list)

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] in certificateExtensionsMap:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))


class CertificateLogotypeDataTestCase(unittest.TestCase):
    pem_text = """\
MIIJJDCCCAygAwIBAgIRAPIGo/5ScWbpAAAAAFwQBqkwDQYJKoZIhvcNAQELBQAw
gbkxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQL
Ex9TZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykg
MjAxOCBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxLTAr
BgNVBAMTJEVudHJ1c3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5IC0gVk1DMTAeFw0x
OTA4MzAxNDMyMzlaFw0yMDAyMjUxNTAyMzZaMIIBjTEOMAwGA1UEERMFMTAwMTcx
CzAJBgNVBAYTAlVTMREwDwYDVQQIEwhOZXcgWW9yazERMA8GA1UEBxMITmV3IFlv
cmsxGDAWBgNVBAkTDzI3MCBQYXJrIEF2ZW51ZTETMBEGCysGAQQBgjc8AgEDEwJV
UzEZMBcGCysGAQQBgjc8AgECEwhEZWxhd2FyZTEfMB0GA1UEChMWSlBNb3JnYW4g
Q2hhc2UgYW5kIENvLjEdMBsGA1UEDxMUUHJpdmF0ZSBPcmdhbml6YXRpb24xNzA1
BgNVBAsTLkpQTUMgRmlyc3QgVmVyaWZpZWQgTWFyayBDZXJ0aWZpY2F0ZSBXb3Js
ZHdpZGUxDzANBgNVBAUTBjY5MTAxMTEXMBUGCisGAQQBg55fAQQTBzIwMTUzODkx
EjAQBgorBgEEAYOeXwEDEwJVUzEmMCQGCisGAQQBg55fAQITFmh0dHBzOi8vd3d3
LnVzcHRvLmdvdi8xHzAdBgNVBAMTFkpQTW9yZ2FuIENoYXNlIGFuZCBDby4wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCNLY+etlX06q1MxA1VT/P20h1i
eFGTzX4fqSQNG+ypmjNfLa8YXraO1v1hahenkRUWrVPW0Hq3zKNJcCDmosox6+tB
59u0b1xgN8y8D05AEC7qoVVdbaWKENMxCN4CDfST6d3YOqApjqEFAGZ71s39tRRG
kmWGJb4jKXcUX8FWV8w/vjKrpipZ8JsX2tuOp2uxFLkmi+V7gvN8tpbHUipP5K7L
190VOBytSWPudXefnYG3UWRfwah7Fq1bKYT/cCwStUm8XlfA8nUumeVsAiyC6phs
adn26MYiSddsBU08TGthmunLAO0+shaBy6jHYZxMa37S67vVlDpxbeF+TPVXAgMB
AAGjggROMIIESjATBgorBgEEAdZ5AgQDAQH/BAIFADCCArAGCCsGAQUFBwEMBIIC
ojCCAp6iggKaoIICljCCApIwggKOMIICihYNaW1hZ2Uvc3ZnK3htbDAzMDEwDQYJ
YIZIAWUDBAIBBQAEIBnwW6ChGgWWIRn3qn/xGAOlhDflA3z5jhZcZTNDlxF5MIIC
QhaCAj5kYXRhOmltYWdlL3N2Zyt4bWw7YmFzZTY0LEg0c0lBQUFBQUFBQUFJV1Iz
V3JqTUJCR3I1dW5tR3F2Rml4NUpQODBObkZLRTVhbTRFSmhJYmVMazZpT1dhOXRa
TWQyOXVrN2NsTG9SV25CMHNENGNPYVR0TGdmLzVYUWE5TVdkWlV3S1pDQnJ2YjFv
YWp5aEoyNlZ6NW45OHZaNHBaemVOU1ZObGxYbXhnZUR2Vk93MU5abnRwdWFvRlNB
b1YwNFBmMkVYNk5UVzA2ZUNsUE9YK3FRRXpON1dWR0RLRkFoTldwS0ErQVB3RTRK
MzNiNXg5REtBYTdyTlV2cG40dFNwMndycWpPRElwRHd0THNyTTBmeVlCaVYyM0Nq
bDNYeEs0N0RJTVlQRkdiM0ZXSTZKTHZpc1JqV1ZSL1B3TmxGRVh1OUpmTmJtQk1H
RFlqZy9PMTlvVWVWclh0QWtJWTBEY0o0N2JKOXBTb01iclZwdGVNd3VmTDJjMml5
Ym9qVU5veVlUOFFnL1VxWWtCNW41VW5QQWZYU2pub0tPbEl1eW5oOVRJVTh1Z3JF
YVMrVC9lRzZRWDh6OXl2YkdIZ0VLZjJ5S1h3dU9Sa2VsOGJQeFJoUHhtSnN0TDBT
bi9qOUtXWU8yR3dsM2EremNhbmhOYTV0YzZORkdHcVVFUUVwVmY0R3lVNnhOMnRx
WGgwWXQrM1BpcEhlK2l0cElRMGg0VHBoWnRrQ3plM0d6M2NjdllHbkp0cjZKVUNB
QUE9MCIGA1UdEQQbMBmCF2V4Y2hhZGRldi5sYWJtb3JnYW4uY29tMBMGA1UdJQQM
MAoGCCsGAQUFBwMfMA4GA1UdDwEB/wQEAwIHgDBmBggrBgEFBQcBAQRaMFgwIwYI
KwYBBQUHMAGGF2h0dHA6Ly9vY3NwLmVudHJ1c3QubmV0MDEGCCsGAQUFBzAChiVo
dHRwOi8vYWlhLmVudHJ1c3QubmV0L3ZtYzEtY2hhaW4uY2VyMDIGA1UdHwQrMCkw
J6AloCOGIWh0dHA6Ly9jcmwuZW50cnVzdC5uZXQvdm1jMWNhLmNybDBPBgNVHSAE
SDBGMDYGCmCGSAGG+mwKAQswKDAmBggrBgEFBQcCARYaaHR0cDovL3d3dy5lbnRy
dXN0Lm5ldC9ycGEwDAYKKwYBBAGDnl8BATAfBgNVHSMEGDAWgBSLtjl20DSQpj9i
4WTqPrz0fEahczAdBgNVHQ4EFgQUxAJ+yoDhzpPUzAPWKBYxg108dU0wCQYDVR0T
BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAnqdB/vcwxFcxAlyCK0W5HOthXUdXRg9a
GwPDupqmLq2rKfyysZXonJJfr8jqO0f3l6TWTTJlXHljAwwXMtg3T3ngLyEzip5p
g0zH7s5eXjmWRhOeuHt21o611bXDbUNFTF0IpbYBTgOwAz/+k3XLVehf8dW7Y0Lr
VkzxJ6U82NxmqjaAnkm+H127x5/jPAr4LLD4gZfqFaHzw/ZLoS+fXFGs+dpuYE4s
n+xe0msYMu8qWABiMGA+MCKl45Dp5di+c2fyXtKyQ3rKI8XXZ0nN4bXK7DZd+3E3
kbpmR6cDliloU808Bi/erMkrfUHRoZ2d586lkmwkLcoDkJ/yPD+Jhw==
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

            if extn['extnID'] == rfc9399.id_pe_logotype:
                s = extn['extnValue']
                logotype, rest = der_decoder(s, rfc9399.LogotypeExtn())
                self.assertFalse(rest)
                self.assertTrue(logotype.prettyPrint())
                self.assertEqual(s, der_encoder(logotype))

                im0 = logotype['subjectLogo']['direct']['image'][0]
                mt = im0['imageDetails']['mediaType']
                self.assertEqual("image/svg+xml", mt)

                expected = 'data:image/svg+xml;base64'
                url25 = im0['imageDetails']['logotypeURI'][0][0:25]
                self.assertEqual(expected, url25)

        self.assertIn(rfc9399.id_pe_logotype, extn_list)

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] in certificateExtensionsMap:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))


class CertificateLogotypeMultipleTestCase(unittest.TestCase):
    # From Appendix B.5
    pem_text = """\
MIIFpTCCBI2gAwIBAgITN0EFee11f0Kpolw69Phqzpqx1zANBgkqhkiG9w0BAQ0F
ADBVMQ0wCwYDVQQKEwRJRVRGMREwDwYDVQQLEwhMQU1QUyBXRzExMC8GA1UEAxMo
U2FtcGxlIExBTVBTIFJTQSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAgFw0yMjA2
MTUxODE4MThaGA8yMDUyMDkyNzA2NTQxOFowOzENMAsGA1UEChMESUVURjERMA8G
A1UECxMITEFNUFMgV0cxFzAVBgNVBAMTDkFsaWNlIExvdmVsYWNlMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtPSJ6Fg4Fj5Nmn9PkrYo0jTkfCv4TfA/
pdO/KLpZbJOAEr0sI7AjaO7B1GuMUFJeSTulamNfCwDcDkY63PQWl+DILs7GxVwX
urhYdZlaV5hcUqVAckPvedDBc/3rz4D/esFfs+E7QMFtmd+K04s+A8TCNO12DRVB
DpbP4JFD9hsc8prDtpGmFk7rd0q8gqnhxBW2RZAeLqzJOMayCQtws1q7ktkNBR2w
ZX5ICjecF1YJFhX4jrnHwp/iELGqqaNXd3/Y0pG7QFecN7836IPPdfTMSiPR+peC
rhJZwLSewbWXLJe3VMvbvQjoBMpEYlaJBUIKkO1zQ1Pq90njlsJLOwIDAQABo4IC
hDCCAoAwDAYDVR0TAQH/BAIwADAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMAEwHgYD
VR0RBBcwFYETYWxpY2VAc21pbWUuZXhhbXBsZTATBgNVHSUEDDAKBggrBgEFBQcD
BDAOBgNVHQ8BAf8EBAMCBsAwHQYDVR0OBBYEFLv2zLItHQYSHJeuKWqQENMgZmZz
MB8GA1UdIwQYMBaAFJEwjnwHFwyn8QkoZTYaZxxodvRZMIIB0AYIKwYBBQUHAQwE
ggHCMIIBvqCB4zCB4KBvMG0wazBpFgppbWFnZS9qcGVnMDEwLzALBglghkgBZQME
AgEEIK/8EBZGy1YltJl95Yk+rjqEb1oC04LW2o7U7vh8vR3tMCgWJmh0dHA6Ly93
d3cuZXhhbXBsZS5uZXQvaW1hZ2VzL2xvZ28uanBnoG0wazBpMGcWCWltYWdlL2dp
ZjAxMC8wCwYJYIZIAWUDBAIBBCCIkIGBrftmri9m0EmgTY6g7E6oZEI4WzZKvyyL
0unpZjAnFiVodHRwOi8vd3d3LmV4YW1wbGUub3JnL2xvZ28taW1hZ2UuZ2lmooHV
oIHSMIHPMGUwYxYJaW1hZ2UvZ2lmMDEwLzALBglghkgBZQMEAgEEIGpYUC5ZZ/nd
0Yr+vQ2x/mClExvfD7K+8LVzRVC6G78ZMCMWIWh0dHA6Ly93d3cuc21pbWUuZXhh
bXBsZS9sb2dvLmdpZjBmMGQWCmltYWdlL2pwZWcwMTAvMAsGCWCGSAFlAwQCAQQg
vct7dXJtjBszpCzerHly2krZ8nmEClhYas4vAoDq16UwIxYhaHR0cDovL3d3dy5z
bWltZS5leGFtcGxlL2xvZ28uanBnMA0GCSqGSIb3DQEBDQUAA4IBAQBbjdCNVFA/
emCc5uKX5WSPrdvRFZSs57SEhE0odxvhTrOs13VM8Om0TxhNJ0Pl6d9CJdbUxtFw
SSnSu9fnghDO7OZDJnPiIYLNY5eTTzY6sx85mde9TLaBTE7RZf0W7NV0hqDqcfM+
9HnQrU4TtPSvtPS5rr5SvqkaMM0k89bpbkgZlh9HH14+x+DIeT0dLythiXJvkVod
qEfyZTcdplQHQ4szWO7lsjmvHrUIbS1tdAJnah8AZRZfqiJEFeiUp06hvAWnPc3y
1TMwYI8onfwPIVzyT6YLgjiT6PuLwSB/wtlhI+vWfdINaHdotegjawLm/3jZ+ceN
tu39FvbV0uKJ
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

            if extn['extnID'] == rfc9399.id_pe_logotype:
                s = extn['extnValue']
                logotype, rest = der_decoder(s, rfc9399.LogotypeExtn())
                self.assertFalse(rest)
                self.assertTrue(logotype.prettyPrint())
                self.assertEqual(s, der_encoder(logotype))

                self.assertTrue(logotype['communityLogos'].hasValue())
                self.assertEqual(2, len(logotype['communityLogos']))
                for clti in logotype['communityLogos']:
                    clti_id = clti['direct']['image'][0]['imageDetails']
                    url19 = clti_id['logotypeURI'][0][0:19]
                    self.assertEqual('http://www.example.', url19)

                self.assertTrue(logotype['subjectLogo'].hasValue())
                self.assertEqual(2, len(logotype['subjectLogo']['direct']['image']))
                for slti in logotype['subjectLogo']['direct']['image']:
                    url29 = slti['imageDetails']['logotypeURI'][0][0:29]
                    self.assertEqual('http://www.smime.example/logo', url29)

        self.assertIn(rfc9399.id_pe_logotype, extn_list)

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] in certificateExtensionsMap:
                extnValue, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))


class ExtnLogotypeOtherDataTestCase(unittest.TestCase):
    # From Appendix B.4
    pem_text = """\
MIILVgYIKwYBBQUHAQwEggtIMIILRKOCC0Awggs8MIILOAYIKwYBBQUHFAOgggsq
MIILJjCCCyIwggseFhJpbWFnZS9zdmcreG1sK2d6aXAwMTAvMAsGCWCGSAFlAwQC
AQQggxSzJpvTiwsq5m5CdOKnV3pAt+EuU0JEzHyuFGgbDrYwggrTFoIKz2RhdGE6
aW1hZ2Uvc3ZnK3htbCtnemlwO2Jhc2U2NCxINHNJQ0xYdXRVMEFBME5sY25SSmJX
Rm5aVVJsYlc4dWMzWm5BTlZhVzIvYk9CWituMTlCcUJpZ3dkb1M3eEs5am1lYXBC
MEVXSFFIemV6MldaWm9SMXRaTWlRNWp2dnI5NUNTTDdHbDFFbThDOWQ5aUVSU1BP
ZDg1K081RUIzKzlqaEwwWU11eWlUUExoM2lZZ2ZwTE1yakpKdGVPdi82NjFNL2NG
QlpoVmtjcG5tbUw1MHNkMzRiL1RJc0g2WW9pUytkYTExVXlTU0p3a3FqMjFrNDFR
NkNEYk55VU1TVFMrZStxdVlEejFzdWwrNlN1WGt4OVloU3lzUFVvN1FQSy9ybEtx
dkN4MzVXdm11K2EvdUdZb3c5RU9pZ2gwUXZyL0xIU3djampEakdpR0hROTE0bjAv
c0tsTWY0VndjdGs3aTZYNy9zR0VZZE5BNUwvV2VSVDVJVURLbVNiTFZXTm9vMmNx
TkNoMVh5b0tOOE5zdXowaXF3Vlc4UWIxZk9GMFZxcCtQSTA2bWU2YXdxUGVJU3p4
bjlnb1l6WFlWeFdJVVdwZldMQ013Y0dvTHBneTgzbjh3ekdrYlI0R3RlZkVObU1C
em5DN0RFcm9LcE9CcE04bUlXVnFQRVlHdEErQnZvTWZTMkU1dUYxV3F1N1I2Rkx2
TkZFZWxXUmVOb2xwaVYzbDJWcEdudE1XOW5rNlJLZGYwKzlCckZyTWJlVnVXaHR6
Ykh2TVI2VWxvYlB5VnBCV2pYQms3c2l4MnZINW5Dd1k2blhDbzV4YjdZdXN2RlZQ
cUNPR2gxNmZTeFN4Z2xtUGtTY0xmdm1ERG1DNEZsRGMxd292OElGMldaaE5sVnVt
Z0VQUmxpaW1ERDNQaEdQeVRnVVVNQzZsS3FLQWp4YXB0cTFib1VKdlFGc3ZpK0xP
Snl4WmtQRS92Q3dIdUFtWG1vajFBYXJuUkJhdHpxa2J2N2NLNUxzMk9SZndNL3Zz
T0c1bFVSWnFYeE9uRFhQS1p3NXQ1alZ6SWhGS08wQjZENmhBUlNYRFI2RnpxcTdI
N21RZUpBT1FpVVNQdkZJclVIT2Z1dWkzenJGSTVkWVZlQW1wY09jT2I5dTYzdkxq
YWU0a1lYNHlSaWZZUHJUYTJTbE1pZ1lkTytjRVdlR0FETUxaTEg5NlNINFI5eFJZ
QXBsNnEzWTAyZitOemxSQWwrY1pTS2hCNnFTSVZhODBmc3FNbldPcVpKcG1zWHdB
UG95TmFROTV1TklHYXNLUHdoeEd6UXpPWHpNSUl6QkthYm1MSWlsNDcwemZTaldX
bitrdnB2TFE5ZzFsM3lSSWM4Z3VrejB1eXNFY2FrY0RmeTNLTWsrbDBTT1hsT29w
bHRKTDdFUHRVbHpaZlA0dG5NNzBrOHhrS0N5U3Q5Mk13ZklYUG9UZTBwbnU0ZFli
cDdoSi9reFd5U04wZXkwby8xcWJpQ3N4RFhKTVdXbzM3UWVrQmNBVUZQU0drUENu
VUpGNXd3QmFjREs1Y0dsRXA0QkMybFlvSmNyTk5HVmM3RHpJcXhUNENLc1BsckFH
OG1MOHdoUmVqaVFlOUVtSW1JQW96M3NkczlOeFA0UlpFenVncXpiN2MzUTg5dTNX
UUtZOWFlZ2JzQS9BVUpCL2JKczZwZkp0OUJIRkV1azVEV0lUek9INXVaU1RoTFVz
RGpRNUdFNlJNc3lpaE1UYVFMZkE2QklpQVFNQWhuSEhOMXNkNjFXdFVoRFZKaXVo
a3JkQlhkNzQwK2hMQjlWbTFIalFlNHl3TE9CTFdPTU1peVFBWE5COHNtOUd4MnFk
R2dHa01HNndZOGFMZnFnSDRkZm5tclZjK3BQckUvWi9RblpPczhDMU9rYjIvZ2d3
TGR4bERDMUQ2REZQWkREOTh0eHY4eFFmNVRFYzdBeDZaeWFEZjZCQzRTeWxXS0NN
cXRpenA4MCtVTWNoQVRhbDYzcUhxME0zWlRzODNPYi9YTzZMWXNGenBHVlk1K2lM
eGRXdndZK05hS29SLzBpSklYTDNkQmpUMmhHK3dPK05YbTUzWFN0U2gxZW9nZmVv
alYzNUJUT2FxaC9jbVBVZTJNZHA5MXBRcDJDaldPTzJrN09hbWhqVTFIQjNETEdt
NjZuNmlhano0YnFuMm9JQ21ORnhEUi94Mm1DNXMrcktobGtVQTNOZTNQOGxnUDBx
SmZqZjl1dnUrSFdYU2ZGd05vSDR1cUdVbVRhZFlNdE9jN3lqRUVkOUVVaGt3RUVP
Y0RTSEtRK3loblN2VVlSSDhtaVFvMkZLNVRDaldaWkdXS0I4aUhQdWQxNndBcG5D
dlRPempJRkFqOVRRZEN4YStkZE9UaXphYTF4SnZEMHFNckt4K1lkYWo2aXdKUUcw
dmFTZFlXcFR2NEh3VlJBUDNaNk9Oak9KdW5FSWVLUlZtaHVqcEEyK3dQbVFSOVdG
UUFGaGg5YkdRekZFWFgrV3dPblhxOHBWMzVQMkFjZG4wcEdlYmNNZzdPZ1FLYUVk
T0tFQWtGbGsvOUh1RUtHQlZ3dWNjNEFqbkovTEJZVTA5aFZ3V1kxRjBIbEJVQzJs
YnlJdVlGNThPOHArYWRNd1V0OVlBb1gvSXdSdEFDOU5BZEJBeUd1RUIzVlI1OXU4
L1RHWXg5L1hqejhiUEIvWi9GOUIwU2doQksrNHh4Zml3dHIwR1hFQ3FlZFFROVBS
VnBFQVErMjZNaWRiR1NtUG04UndSemNRc1QxN0VQU21vb3JIMythdjRKY2o3OE8v
dklwL3V6TUVrSEtBRTYvRjdWSEhTajhIZGRSMFEzeW1jR1pmUlZqd2ZtT25ObjNH
dVdSK0Z6aGNQbVBxaXB0SGNheWFjVDI4VDhqM0NzMC9MUUN3bzZKMmlZeFA0UjU4
QXNvYmpGZWd1c29KaHVxN1ZOUzJldlJQY3FBU3ZRa2krZ2JrQll3RVROUHQvMUEy
cFQ2VUVyUjF6TXpVSVRaUnZGNUxwNWJhc08xZmsyVTRhQlNqa2ppOHF1TDNjRHlX
N1RwSTN1bnhlek1jU1ROaFFKaGZwR2N0S2dLTjJBbW83LzdTaFNldjRvWGljUFNZ
Uys2R2tDbTlhMVF3M1ZFY2hDVUErejVIdFRjYlFoSzZGMTRZRlVwK1luN1dnbXp3
cFpDRGY1RERpWFQ5QjdVNlJkSEFIcGRiN0lxbUxWanFaU0xuVFc2MXpqUTcvRzdE
M2htOUU4NDZ1VERab05NQURtTGxtN0lHMmllWGZVdHUxVVM5VGVOR1VIaWJFOU52
Ly8yalJKR1pmUW1LM3Y3eWtKSk92MUlYakJzRENQcG1nV3BwZTZzSHhSM0tWU1FL
cXArV0lxYW1tdUpidHFreFptTUhyeTRvUy85cExoZENYS3E4dVIwUitMREVxQ0tS
eHFjNVZYZHZQdklQK2dnd1IwUmt5QmZPOWlLWnZyV0dBS1ZkejMxY3VvY3ZvTy9x
ZW1DbEZNWUVGRUg3b0krdnBrZWs0czRiQ01CcUsrNW1IUVVsRHBFL295bHB5KzIv
NnBXWEszMVBFWWFnUDA0ZXBWMWNFNTBVTXk2SVFaZVFNNytPbDc0WitlSGZwSE5j
N09qZmZRL0hlVjBYOEJvcG9Ea0dFa0FBQT0=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9399.id_pe_logotype, asn1Object['extnID'])

        s = asn1Object['extnValue']
        logotype, rest = der_decoder(s, asn1Spec=rfc9399.LogotypeExtn())
        self.assertFalse(rest)
        self.assertTrue(logotype.prettyPrint())
        self.assertEqual(s, der_encoder(logotype))

        self.assertTrue(logotype['otherLogos'].hasValue())
        self.assertEqual(1, len(logotype['otherLogos']))
        oltt = logotype['otherLogos'][0]['logotypeType']
        self.assertEqual(rfc9399.id_logo_certImage, oltt)
        olti = logotype['otherLogos'][0]['info']['direct']['image'][0]
        url31 = olti['imageDetails']['logotypeURI'][0][0:31]
        self.assertEqual('data:image/svg+xml+gzip;base64,', url31)


class ExtnLogotyeDataTestCase(unittest.TestCase):
    # From Appendix B.3
    pem_text = """\
MIIIZAYIKwYBBQUHAQwEgghWMIIIUqKCCE6ggghKMIIIRjCCCEIwggg+FhJpbWFn
ZS9zdmcreG1sK2d6aXAwMTAvMAsGCWCGSAFlAwQCAQQgxayUGgolH7MWb5fFUkCb
SZ57kmFasKJsGb+52AnF2ecwggfzFoIH72RhdGE6aW1hZ2Uvc3ZnK3htbCtnemlw
O2Jhc2U2NCxINHNJQ0lHcHkyRUFBMnh2WjI4dFkyOXdlUzV6ZG1jQXBWYmJiaHMz
RUgzblYweTNMdzJROWZLMkpMZXdIRFJPVUJSbzJpQnhXK1JSbFRhMlVGa3lwSVdW
NXV0N3psQjJVcUY5Y3VMbFVrdHlMbWZPelBEOHhhZmJ0ZHlQdS8xcXU1azE3c3cy
c3AvbW0rVjh2ZDJNczJhemJWNWNtUE52WHYxNmVmWGg3V3ZaMzEvTDI5OWUvdnpU
cFRSdDEvMFJMcnZ1MWRVcmVmLzdqK0t0ZFhhd3NldGUvOUlZYVc2bTZlNzdyanNj
RG1lSGNMYmRYWGRYN3pwdTZ0Njl2bXh4b24wOEFSRWRSRHQ3dHB5V0RSUlN6Nyt0
Z3AyYi9ldy9oRUtJNVdHb1BLeVcwODJzOFNtZVdmMTNOelZ5TTY2dWI2WlprK3hY
SCs5WDQrSGw5dE9zc1dMbHkzNTUzQVJwZDd0eFArN3V4eC8yZCtOaWVqZWZWdHRa
OCtuTmF2a0JqOXlPNDBSTGI4ZHB2cHhQOHd0enVSdm4wN2lVUC8rV3UrMjBteTlH
Y1dmT1BwZkRialZONDRZTGI4ZHAzTW43Y2IzYVhHTkNBSUNDYythOCt5TG8vRnB3
ZkxQL3VOM2R6aHFkcmlINXV3ZmJuajlhK1V6MmkvbWFLNjZ1dEErelo0MzV1RnF2
WjgyM1IzOFExdDMyTHczcFpxVGhkL1BwUnBhejVvMkxOa29jdkN6YUltMHZyUXZT
cG9nMzU5bEx5M215MGdhK2UzSHArQjRJbmpWRlBEOWF3ZGhuckdFRlczMFNsL1Bu
cHZ0YTJRQlZ4VUVWeEZiSjJWVUZmWUMwMXBVcytPNEdLODRWL2s2Q0hVRnlodmhp
RFZRRjhZNWFQRGJtbnNyWGJTNzREQU5qZ3V3Z0VOWkxQd2pVWVZUUkpRZ0VwaUxS
MGN0aVdqK0lnOHJDdlpBQXJ4S0V4RUVXTUpMcU1BMUYrZ2duc1FEWGdwUWVvbUpQ
Q1ZodENSeWNOckFXeGdBSStnMVFzcjZJVXhsb21Cc3dqeWRZQkVnT2VWQ0RvUnJl
QmppRmpYMlNkU0E2MEJQNURnUU02M3hvUGxXSGJOcStlZ0FFZUF6eHlOQWRDUXor
c0RFTU9oYUdpc0tKZFNsUzZndFdXbTRNMXJRd1AwZWdFQkloaEZMb1h1Q0poUjRt
VDVSSkJhaUxLcXFGUk9VRXpZcjFpZEcwZ2Fod0N6RW5rK0FNSkxkcDBGZXZRUTZW
WitTS093R2xPSUpPaDFNVmpvMGVCNkRSQTEwU1JwU1k2aWwvZUZGS0FtK01LU0lX
TkZxU280T0ZuT1Jmd0g1d0pIQ01OTTBxbERSbGNJd1VFa0RsZ2lTQmhpRXBCZ01L
T3g1RmRBWXFJM0tZZXdLS2tBSXRUQUJUa3A1a2hJODZrZ2JPZ1J5d0VCUjBWR2N3
QWpmOHQ5d3F2ZFVNRzZnTEFiSTBRUThDYnpDVHRDU24vREVoQ2JtKytkdVFhaVJH
MW1Ra2RXSG5taW5IQStyNXdwTHZzSmJDQUxVS3NEVzVOQWo0M0orQUQ1dnBmYW1V
ekpxaVJKQUNtQ1d3SU1oUXE0SG1ZR0thaWlKUG1JdnBTODBVelR0QWpkU3JhQXBR
Wm9nc2xnRmNKSHcweTVXb0VYRFlyL2FUcWZ4azJxaGNnM3o2RVRRTCtTMThsbHZI
T1pRdmxFT1ZFVnB6cUNvekU5VjZKWmhoL2xDc2xnN21VRlk0QVI3SWxjQXBtZ1Y2
Z3ozRENTRGU1NmZRMFNSUzdlbDBOSldPOG1RNm1rYzZ5bFBwYUw3UVVaNUlSL00v
ZEV3b0ppRXArTDZpVDRjZFN5SXA0bGpEa29hWnBRbGdNb3owQXBhaGpUaVRXYlpZ
dTl2K01VcVZqWTYxajJCeHI2OGJQRjN1UzEyMzJxQXlBUURNaHI0TVJ5VlpxNWwy
UWN1d2dZL29Ub3piZ29JS3ljSCt5UXhoelFzUEpRL25lOU9tUkt2WUgxQWVLQS9F
UVJ0enJtYVlVaUhVaHBKT1c0YnJlU2F4Wi9UVmMzWkFRSktPYWdBSml3NnBSSFZr
Qk1JQmE1RStTVU1XaTBaTlcxUmZuL3hRWHl3SFh5TUhONUc4V0Y2Z1oySVZqQU5I
TUlKUTFsQUpRRThNSmpaSEppVXRRWkFXem1raXNEeXdUVldTcUxra1FHMk5OQjN3
d3lhZXJxUkdMTktwdndVT2hhUUZpWWNxdmlTanZwMW44V25SUnpYRnM5SVhEeGlp
RGQ4SFUvUk9vQUduOStRZ1RQRVZ1NkhhTjZpMFZQdXYxU0N6d3laZUh3QkExRWpG
WW9BazJqSjNPRmVKNUdwMUUrM0RsZjNBajcwYmJ2bWFnNW95S0h1blZ5R1BxNitF
bnZUdWEvSlVuM2lhZE1IbHFVYXBzSzJUOFN3Q0JKVUYxSm5FbWh1MG50QnRoSm9R
cFpxdW1zQms1bUExaFJjMExSNVpGZXJkamtzYUNxdDNJVVdYY1hXMTZ2YjZ4ZFd5
SExUZ0NhS1hXS1VLSzFrT3A5SEs1QjNFTGpTZFhiMGxvQjVSWXRTMDFMNmg5eVRQ
VzUxV3Bxd2dvc3I1STkyN2F3NjQwMStZZndEcmlhNFdvUXdBQUE9PQ==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9399.id_pe_logotype, asn1Object['extnID'])

        s = asn1Object['extnValue']
        logotype, rest = der_decoder(s, asn1Spec=rfc9399.LogotypeExtn())
        self.assertFalse(rest)
        self.assertTrue(logotype.prettyPrint())
        self.assertEqual(s, der_encoder(logotype))

        self.assertTrue(logotype['subjectLogo'].hasValue())
        self.assertEqual(1, len(logotype['subjectLogo']['direct']['image']))
        slti = logotype['subjectLogo']['direct']['image'][0]
        url31 = slti['imageDetails']['logotypeURI'][0][0:31]
        self.assertEqual('data:image/svg+xml+gzip;base64,', url31)


class ExtnLogotyeIssuerJPEGTestCase(unittest.TestCase):
    # From Appendix B.2
    pem_text = """\
MHwGCCsGAQUFBwEMBHAwbqFsoGowaDBmMGQWCmltYWdlL2pwZWcwMTAvMAsGCWCG
SAFlAwQCAQQgHo+W/dNQU+/GHJ/88AAuU7ScJJoyxekMLDk5061tqQkwIxYhaHR0
cDovL2xvZ28uZXhhbXBsZS5jb20vbG9nby5qcGVn
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9399.id_pe_logotype, asn1Object['extnID'])

        s = asn1Object['extnValue']
        logotype, rest = der_decoder(s, asn1Spec=rfc9399.LogotypeExtn())
        self.assertFalse(rest)
        self.assertTrue(logotype.prettyPrint())
        self.assertEqual(s, der_encoder(logotype))

        self.assertTrue(logotype['issuerLogo'].hasValue())
        self.assertEqual(1, len(logotype['issuerLogo']['direct']['image']))
        ilti = logotype['issuerLogo']['direct']['image'][0]
        url = ilti['imageDetails']['logotypeURI'][0]
        self.assertEqual('http://logo.example.com/logo.jpeg', url)


class ExtnLogotyeIssuerGIFTestCase(unittest.TestCase):
    # From Appendix B.1
    pem_text = """\
MGoGCCsGAQUFBwEMBF4wXKFaoFgwVjBUMFIWCWltYWdlL2dpZjAhMB8wBwYFKw4D
AhoEFI/l0xqGrI2Oa8PPgGrUSBgsexkuMCIWIGh0dHA6Ly9sb2dvLmV4YW1wbGUu
Y29tL2xvZ28uZ2lm
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc9399.id_pe_logotype, asn1Object['extnID'])

        s = asn1Object['extnValue']
        logotype, rest = der_decoder(s, asn1Spec=rfc9399.LogotypeExtn())
        self.assertFalse(rest)
        self.assertTrue(logotype.prettyPrint())
        self.assertEqual(s, der_encoder(logotype))

        self.assertTrue(logotype['issuerLogo'].hasValue())
        self.assertEqual(1, len(logotype['issuerLogo']['direct']['image']))
        ilti = logotype['issuerLogo']['direct']['image'][0]
        url = ilti['imageDetails']['logotypeURI'][0]
        self.assertEqual('http://logo.example.com/logo.gif', url)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
