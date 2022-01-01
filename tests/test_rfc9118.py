#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc9118
from pyasn1_alt_modules import opentypemap


class CertificateExtnTestCase(unittest.TestCase):
    pem_text = """\
MIICpzCCAk2gAwIBAgIUH7Zd3rQ5AsvOlzLnzUHhrVhDSlswCgYIKoZIzj0EAwIw
KTELMAkGA1UEBhMCVVMxGjAYBgNVBAMMEUJPR1VTIFNIQUtFTiBST09UMB4XDTIx
MDcxNTIxNTIxNVoXDTIyMDcxNTIxNTIxNVowbDELMAkGA1UEBhMCVVMxCzAJBgNV
BAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMR4wHAYDVQQKDBVCb2d1cyBFeGFtcGxl
IFRlbGVjb20xDTALBgNVBAsMBFZvSVAxDzANBgNVBAMMBlNIQUtFTjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABNR6C6nBWRA/fXTglV03aXkXy8hx9oBttVLhsTZ1
IYVRBao4OZhVf/Xv1a3xLsZ6KfdhuylSeAKuCoSbVGojYDGjggEOMIIBCjAMBgNV
HRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUDlG3dxHyzKL/FZfS
PI7rpuueRbswHwYDVR0jBBgwFoAUlToKtrQeFrwwyXpMj1qu3TQEeoEwQgYJYIZI
AYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9y
IGFueSBwdXJwb3NlLjAWBggrBgEFBQcBGgQKMAigBhYEMTIzNDBOBggrBgEFBQcB
IQRCMECgDjAMFgpjb25maWRlbmNloSAwHjAcFgpjb25maWRlbmNlMA4MBGhpZ2gM
Bm1lZGl1baIMMAoWCHByaW9yaXR5MAoGCCqGSM49BAMCA0gAMEUCIQCbNR4QK1um
+0vq2CE1B1/W3avYeREsPi/7RKHffL+5eQIgarHot+X9Rl7SOyNBq5X5JyEMx0SQ
hRLkCY3Zoz2OCNQ=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc9118.id_pe_eJWTClaimConstraints:
                ev, rest = der_decoder(extn['extnValue'],
                    asn1Spec=rfc9118.EnhancedJWTClaimConstraints())
                self.assertFalse(rest)
                self.assertTrue(ev.prettyPrint())
                self.assertEqual(extn['extnValue'], der_encoder(ev))
    
                self.assertIn('confidence', ev['mustInclude'])
                self.assertIn('medium', ev['permittedValues'][0]['values'])
                found = True

        self.assertTrue(found)

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc9118.id_pe_eJWTClaimConstraints:
                ev, rest = der_decoder(extn['extnValue'],
                    asn1Spec=certificateExtensionsMap[extn['extnID']])
                self.assertEqual(extn['extnValue'], der_encoder(ev))


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
