#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley
# Copyright (c) 2019, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#

import sys

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

from pyasn1.type import univ

from pyasn1_modules import pem
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc5751

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class SignedMessageTestCase(unittest.TestCase):
    pem_text = """\
MIIH/wYJKoZIhvcNAQcCoIIH8DCCB+wCAQExCTAHBgUrDgMCGjArBgkqhkiG9w0BBwGgHgQc
VGhpcyBpcyBzb21lIHNhbXBsZSBjb250ZW50LqCCAuAwggLcMIICm6ADAgECAgIAyDAJBgcq
hkjOOAQDMBIxEDAOBgNVBAMTB0NhcmxEU1MwHhcNOTkwODE3MDExMDQ5WhcNMzkxMjMxMjM1
OTU5WjATMREwDwYDVQQDEwhBbGljZURTUzCCAbYwggErBgcqhkjOOAQBMIIBHgKBgQCBjc3t
g+oKnjk+wkgoo+RHk90O16gO7FPFq4QIT/+U4XNIfgzW80RI0f6fr6ShiS/h2TDINt4/m7+3
TNxfaYrkddA3DJEIlZvep175/PSfL91DqItU8T+wBwhHTV2Iw8O1s+NVCHXVOXYQxHi9/52w
hJc38uRRG7XkCZZc835b2wIVAOJHphpFZrgTxtqPuDchK2KL95PNAoGAJjjQFIkyqjn7Pm3Z
S1lqTHYjOQQCNVzyyxowwx5QXd2bWeLNqgU9WMB7oja4bgevfYpCJaf0dc9KCF5LPpD4beqc
ySGKO3YU6c4uXaMHzSOFuC8wAXxtSYkRiTZEvfjIlUpTVrXi+XPsGmE2HxF/wr3t0VD/mHTC
0YFKYDm6NjkDgYQAAoGAXOO5WnUUlgupet3jP6nsrF7cvbcTETSmFokoESPZNIZndXUTEj1D
W2/lUb/6ifKiGz4kfT0HjVtjyLtFpaBK44XWzgaAP+gjfhryJKtTGrgnDR7vCL9mFIBcYqxl
+hWL8bs01NKWN/ZhR7LEMoTwfkFA/UanY04z8qXi9PKD5bijgYEwfzAMBgNVHRMBAf8EAjAA
MA4GA1UdDwEB/wQEAwIGwDAfBgNVHSMEGDAWgBRwRD6CLm+H3krTdeM9ILxDK5PxHzAdBgNV
HQ4EFgQUvmyhs+PB9+1DcKTOEwHi/eOX/s0wHwYDVR0RBBgwFoEUQWxpY2VEU1NAZXhhbXBs
ZS5jb20wCQYHKoZIzjgEAwMwADAtAhRVDKQZH0IriXEiM42DarU9Z2u/RQIVAJ9hU1JUC1yy
3drndh3iEFJbQ169MYIEyTCCBMUCAQEwGDASMRAwDgYDVQQDEwdDYXJsRFNTAgIAyDAHBgUr
DgMCGqCCBF8wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAjBgkqhkiG9w0BCQQxFgQUQGrs
CFJ5um4WAi2eBinAIpaH3UgwOAYDKqszMTEEL1RoaXMgaXMgYSB0ZXN0IEdlbmVyYWwgQVNO
IEF0dHJpYnV0ZSwgbnVtYmVyIDEuMD4GCyqGSIb3DQEJEAIEMS8wLQwgQ29udGVudCBIaW50
cyBEZXNjcmlwdGlvbiBCdWZmZXIGCSqGSIb3DQEHATBKBgkqhkiG9w0BCQ8xPTA7MAcGBSoD
BAUGMDAGBioDBAUGTQQmU21pbWUgQ2FwYWJpbGl0aWVzIHBhcmFtZXRlcnMgYnVmZmVyIDIw
bQYLKoZIhvcNAQkQAgIxXjFcAgEBBgcqAwQFBgcIExtUSElTIElTIEEgUFJJVkFDWSBNQVJL
IFRFU1QxMTAvgAgqAwQFBgeGeKEjEyFUSElTIElTIEEgVEVTVCBTRUNVUklUWS1DQVRFR09S
WS4wbwYLKoZIhvcNAQkQAgoxYDBeBgUqAwQFBgQrQ29udGVudCBSZWZlcmVuY2UgQ29udGVu
dCBJZGVudGlmaWVyIEJ1ZmZlcgQoQ29udGVudCBSZWZlcmVuY2UgU2lnbmF0dXJlIFZhbHVl
IEJ1ZmZlcjBzBgsqhkiG9w0BCRACCzFkoGIwWjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDVVT
IEdvdmVybm1lbnQxETAPBgNVBAsTCFZEQSBTaXRlMQwwCgYDVQQLEwNWREExEjAQBgNVBAMT
CURhaXN5IFJTQQIEClVEMzCB/AYLKoZIhvcNAQkQAgMxgewwgekwgeYEBzU3MzgyOTkYDzE5
OTkwMzExMTA0NDMzWqGByTCBxqRhMF8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1VUyBHb3Zl
cm5tZW50MREwDwYDVQQLEwhWREEgU2l0ZTEMMAoGA1UECxMDVkRBMRcwFQYDVQQDEw5CdWdz
IEJ1bm55IERTQaRhMF8xCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1VUyBHb3Zlcm5tZW50MREw
DwYDVQQLEwhWREEgU2l0ZTEMMAoGA1UECxMDVkRBMRcwFQYDVQQDEw5FbG1lciBGdWRkIERT
QTCCAQIGCyqGSIb3DQEJEAIJMYHyMIHvMXICAQEGByoDBAUGBwkTJkVRVUlWQUxFTlQgVEhJ
UyBJUyBBIFBSSVZBQ1kgTUFSSyBURVNUMTwwOoAIKgMEBQYHhnihLhMsRVFVSVZBTEVOVCBU
SElTIElTIEEgVEVTVCBTRUNVUklUWS1DQVRFR09SWS4xeQIBAQYHKgMEBQYHChMtRVFVSVZB
TEVOVCBUSElTIElTIEEgU0VDT05EIFBSSVZBQ1kgTUFSSyBURVNUMTwwOoAIKgMEBQYHhnih
LhMsRVFVSVZBTEVOVCBUSElTIElTIEEgVEVTVCBTRUNVUklUWS1DQVRFR09SWS4wCQYHKoZI
zjgEAwQvMC0CFQC8MzdlxPdwXBdJE6pMhcq7UpFIWQIUY5aiFIvPV96wSF9sZN2EBElfHMo=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        openTypeMap = {
            univ.ObjectIdentifier('1.2.3.4.5.6.77'): univ.OctetString(),
        }

        substrate = pem.readBase64fromText(pem_text)
        asn1Object, rest = der_decode (substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        assert asn1Object['content']['version'] == 1

        for si in asn1Object['content']['signerInfos']:
            assert si['version'] == 1
            for attr in si['signedAttrs']:
                if attr['attrType'] == rfc5751.smimeCapabilities:
                    scaps, rest = der_decode(attr['attrValues'][0],
                        asn1Spec=rfc5751.SMIMECapabilities())
                    assert not rest
                    assert scaps.prettyPrint()
                    assert der_encode(scaps) == attr['attrValues'][0]

                    for scap in scaps:
                        if scap['capabilityID'] in openTypeMap.keys():
                            scap_p, rest = der_decode(scap['parameters'],
                                asn1Spec=openTypeMap[scap['capabilityID']])
                            assert not rest
                            assert scap_p.prettyPrint()
                            assert der_encode(scap_p) == scap['parameters']
                            assert 'parameters' in scap_p

                if attr['attrType'] == rfc5751.id_aa_encrypKeyPref:
                    ekp, rest = der_decode(attr['attrValues'][0],
                        asn1Spec=rfc5751.SMIMEEncryptionKeyPreference())
                    assert not rest
                    assert ekp.prettyPrint()
                    assert der_encode(ekp) == attr['attrValues'][0]
                    assert ekp['issuerAndSerialNumber']['serialNumber'] == 173360179


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
