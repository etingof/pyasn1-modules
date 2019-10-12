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

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc7633

try:
    import unittest2 as unittest

except ImportError:
    import unittest


class TLSFeaturesExtnTestCase(unittest.TestCase):
    pem_text = """\
MIIEbTCCBBOgAwIBAgIRAO5f2N8q74GBATjTMXQCjlgwCgYIKoZIzj0EAwIwgZYx
CzAJBgNVBAYTAkdCMRswGQYDVQQIExJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNV
BAcTB1NhbGZvcmQxGjAYBgNVBAoTEUNPTU9ETyBDQSBMaW1pdGVkMTwwOgYDVQQD
EzNDT01PRE8gRUNDIE9yZ2FuaXphdGlvbiBWYWxpZGF0aW9uIFNlY3VyZSBTZXJ2
ZXIgQ0EwHhcNMTYwMTE1MDAwMDAwWhcNMTgwMTE0MjM1OTU5WjCBwjELMAkGA1UE
BhMCUlUxDzANBgNVBBETBjExNzY0NzEUMBIGA1UECBMLTW9zY293IENpdHkxDzAN
BgNVBAcTBk1vc2NvdzE4MDYGA1UECRMvQWthZGVtaWthIEthcGljeSBzdHJlZXQs
IGhvdXNlIDQsIGFwYXJ0bWVudCAxNjYxGDAWBgNVBAoTD0FuZHJleSBDaHVyYW5v
djETMBEGA1UECxMKSW5zdGFudFNTTDESMBAGA1UEAxMJYWRtc2VsLmVjMHYwEAYH
KoZIzj0CAQYFK4EEACIDYgAEwrPPzgBO1vDNmV0UVvYSBnys9B7LVkGLiIBbKYf2
nNFRuJKo1gzNurI8pv4CbvqjkCX4Je/aSeYFHSCR9y82+zTwYQuJFt5LIL5f+Syp
xZ7aLH56bOiQ+QhCtIvWP4YWo4IB9TCCAfEwHwYDVR0jBBgwFoAUdr4iSO4/PvZG
A9mHGNBlfiKcC+EwHQYDVR0OBBYEFHTFQqV+H5a7+RVL+70Z6zqCbqq9MA4GA1Ud
DwEB/wQEAwIFgDAMBgNVHRMBAf8EAjAAMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggr
BgEFBQcDAjBQBgNVHSAESTBHMDsGDCsGAQQBsjEBAgEDBDArMCkGCCsGAQUFBwIB
Fh1odHRwczovL3NlY3VyZS5jb21vZG8uY29tL0NQUzAIBgZngQwBAgIwWgYDVR0f
BFMwUTBPoE2gS4ZJaHR0cDovL2NybC5jb21vZG9jYS5jb20vQ09NT0RPRUNDT3Jn
YW5pemF0aW9uVmFsaWRhdGlvblNlY3VyZVNlcnZlckNBLmNybDCBiwYIKwYBBQUH
AQEEfzB9MFUGCCsGAQUFBzAChklodHRwOi8vY3J0LmNvbW9kb2NhLmNvbS9DT01P
RE9FQ0NPcmdhbml6YXRpb25WYWxpZGF0aW9uU2VjdXJlU2VydmVyQ0EuY3J0MCQG
CCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wEQYIKwYBBQUHARgE
BTADAgEFMCMGA1UdEQQcMBqCCWFkbXNlbC5lY4INd3d3LmFkbXNlbC5lYzAKBggq
hkjOPQQDAgNIADBFAiAi6TXl76FTKPP1AhqtEjU5BjAj9Ju7CSKChHZSmzxeXQIh
AOQSxhs011emVxyBIXT0ZGbmBY8LFRh6eGIOCAJbkM5T
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        extn_list = [ ]
        for extn in asn1Object['tbsCertificate']['extensions']:
            extn_list.append(extn['extnID'])
            if extn['extnID'] == rfc7633.id_pe_tlsfeature:
                s = extn['extnValue']
                features, rest = der_decode(s,
                    rfc5280.certificateExtensionsMap[extn['extnID']])
                assert not rest
                assert features.prettyPrint()
                assert s == der_encode(features)

                assert len(features) == 1
                assert features[0] == 5

        assert rfc7633.id_pe_tlsfeature in extn_list


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
