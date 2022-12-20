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
from pyasn1_alt_modules import rfc9310


class NFTypesCertificateExtensionTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIC0DCCAlagAwIBAgIUbZoY923zOE0+ZIkjG4ehhCGoVXYwCgYIKoZIzj0EAwMw
FTETMBEGA1UECgwKRXhhbXBsZSBDQTAeFw0yMjEwMTkxNjMyMzZaFw0yMzEwMTkx
NjMyMzZaMDkxCzAJBgNVBAYTAlVTMSowKAYDVQQKEyE1Z2MubW5jNDAwLm1jYzMx
MS4zZ3BwbmV0d29yay5vcmcwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATJ6IFHI683
q/JJjsJUfEiRFqGQ6uKDGJ0oqDP6wEhRAuvyEyz5pgRmz/7Mze1+s1qcnPU9mo1v
rIW9rjKhb/Hm8H9TPvnMQwCRCtKvCD90MkWvc/G8qyCBpCms3zNOJOijggFBMIIB
PTATBggrBgEFBQcBIgQHMAUWA0FNRjAXBgNVHSAEEDAOMAwGCmCGSAFlAwIBMDAw
DgYDVR0PAQH/BAQDAgeAMBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBRM
Z5KgwYlYn885mKID55ZcEznIBzAfBgNVHSMEGDAWgBSIf6IE6QtqjXR2+p/xCtRh
4PqzNTAxBgNVHR8EKjAoMCagJKAihiBodHRwOi8vZXhhbXBsZS5jb20vZXhhbXBs
ZWNhLmNybDB1BgNVHREBAf8EazBpgjhhbWYxLmNsdXN0ZXIxLm5ldDIuYW1mLjVn
Yy5tbmM0MDAubWNjMzExLjNncHBuZXR3b3JrLm9yZ4YtdXJuOnV1aWQ6ZjgxZDRm
YWUtN2RlYy0xMWQwLWE3NjUtMDBhMGM5MWU2YmY2MAoGCCqGSM49BAMDA2gAMGUC
MQDCBp4Fb/1/ffZGEVDWdx1XeFjg1KEmfnBGkNC+GHtan1gbnBnDIfD1MD0ctWWf
/zQCMDUmAAk2gM3QohfVsfhGQBm1N2hRz34oHSfhIH+EJFW1rSIG/93r27j09x5C
SG8e0g==
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
                self.assertTrue(extnValue.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(extnValue))

                if extn['extnID'] == rfc9310.id_pe_nftype:
                    self.assertEqual("AMF", extnValue[0])
                    found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
