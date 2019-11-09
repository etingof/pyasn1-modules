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
from pyasn1_modules import rfc5755
from pyasn1_modules import rfc3114

try:
    import unittest2 as unittest

except ImportError:
    import unittest


class AttributeCertificateTestCase(unittest.TestCase):
    pem_text = """\
MIIDBTCCAm4CAQEwgY+gUTBKpEgwRjEjMCEGA1UEAwwaQUNNRSBJbnRlcm1lZGlh
dGUgRUNEU0EgQ0ExCzAJBgNVBAYTAkZJMRIwEAYDVQQKDAlBQ01FIEx0ZC4CAx7N
WqE6pDgwNjETMBEGA1UEAwwKQUNNRSBFQ0RTQTELMAkGA1UEBhMCRkkxEjAQBgNV
BAoMCUFDTUUgTHRkLqA9MDukOTA3MRQwEgYDVQQDDAtleGFtcGxlLmNvbTELMAkG
A1UEBhMCRkkxEjAQBgNVBAoMCUFDTUUgTHRkLjANBgkqhkiG9w0BAQsFAAIEC63K
/jAiGA8yMDE2MDEwMTEyMDAwMFoYDzIwMTYwMzAxMTIwMDAwWjCB8jA8BggrBgEF
BQcKATEwMC6GC3VybjpzZXJ2aWNlpBUwEzERMA8GA1UEAwwIdXNlcm5hbWUECHBh
c3N3b3JkMDIGCCsGAQUFBwoCMSYwJIYLdXJuOnNlcnZpY2WkFTATMREwDwYDVQQD
DAh1c2VybmFtZTA1BggrBgEFBQcKAzEpMCegGKQWMBQxEjAQBgNVBAMMCUFDTUUg
THRkLjALDAlBQ01FIEx0ZC4wIAYIKwYBBQUHCgQxFDASMBAMBmdyb3VwMQwGZ3Jv
dXAyMCUGA1UESDEeMA2hC4YJdXJuOnJvbGUxMA2hC4YJdXJuOnJvbGUyMGowHwYD
VR0jBBgwFoAUgJCMhskAsEBzvklAX8yJBOXO500wCQYDVR04BAIFADA8BgNVHTcB
Af8EMjAwMB2gCoYIdXJuOnRlc3SgD4INKi5leGFtcGxlLmNvbTAPoA2GC3Vybjph
bm90aGVyMA0GCSqGSIb3DQEBCwUAA4GBACygfTs6TkPurZQTLufcE3B1H2707OXK
sJlwRpuodR2oJbunSHZ94jcJHs5dfbzFs6vNfVLlBiDBRieX4p+4JcQ2P44bkgyi
UTJu7g1b6C1liB3vO6yH5hOZicOAaKd+c/myuGb9uJ4n6y2oLNxnk/fDzpuZUe2h
Q4eikPk4LQey
"""

    def setUp(self):
        self.asn1Spec = rfc5755.AttributeCertificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        assert asn1Object['acinfo']['version'] == 1

        count = 0
        for attr in asn1Object['acinfo']['attributes']:
            assert attr['type'] in rfc5280.certificateAttributesMap.keys()
            av, rest = der_decode(attr['values'][0],
                asn1Spec=rfc5280.certificateAttributesMap[attr['type']])
            assert not rest
            assert av.prettyPrint()
            assert der_encode(av) == attr['values'][0]
            count += 1

        assert count == 5

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        assert asn1Object['acinfo']['version'] == 1

        count = 0
        for attr in asn1Object['acinfo']['attributes']:
            assert attr['type'] in rfc5280.certificateAttributesMap.keys()
            count += 1
            if attr['type'] == rfc5755.id_aca_authenticationInfo:
                assert attr['values'][0]['authInfo'] == 'password'

        assert count == 5

class CertificateWithClearanceTestCase(unittest.TestCase):
    cert_pem_text = """\
MIID1DCCA1qgAwIBAgIUUc1IQGJpeYQ0XwOS2ZmVEb3aeZ0wCgYIKoZIzj0EAwMw
ZjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQHEwdIZXJuZG9uMRAw
DgYDVQQKEwdFeGFtcGxlMQwwCgYDVQQLEwNQQ0ExGDAWBgNVBAMTD3BjYS5leGFt
cGxlLmNvbTAeFw0xOTExMDUyMjIwNDZaFw0yMDExMDQyMjIwNDZaMIGSMQswCQYD
VQQGEwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xEDAOBgNVBAoT
B0V4YW1wbGUxIjAgBgNVBAsTGUh1bWFuIFJlc291cmNlIERlcGFydG1lbnQxDTAL
BgNVBAMTBEZyZWQxHzAdBgkqhkiG9w0BCQEWEGZyZWRAZXhhbXBsZS5jb20wdjAQ
BgcqhkjOPQIBBgUrgQQAIgNiAAQObFslQ2EBP0xlDJ3sRnsNaqm/woQgKpBispSx
XxK5bWUVpfnWsZnjLWhtDuPcu1BcBlM2g7gwL/aw8nUSIK3D8Ja9rTUQQXc3zxnk
cl8+8znNXHMGByRjPUH87C+TOrqjggGaMIIBljAdBgNVHQ4EFgQU5m711OqFDNGR
SWMOSzTXjpTLIFUwbwYDVR0jBGgwZoAUJuolDwsyICik11oKjf8t3L1/VGWhQ6RB
MD8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjER
MA8GA1UECgwIQm9ndXMgQ0GCCQCls1QoG7BuRjAPBgNVHRMBAf8EBTADAQH/MAsG
A1UdDwQEAwIBhjBCBglghkgBhvhCAQ0ENRYzVGhpcyBjZXJ0aWZpY2F0ZSBjYW5u
b3QgYmUgdHJ1c3RlZCBmb3IgYW55IHB1cnBvc2UuMBUGA1UdIAQOMAwwCgYIKwYB
BQUHDQIwCgYDVR02BAMCAQIwfwYDVR0JBHgwdjBJBgNVBDcxQjBABgsqhkiG9w0B
CRAHAwMCBeAxLTArgAsqhkiG9w0BCRAHBIEcMBoMGEhVTUFOIFJFU09VUkNFUyBV
U0UgT05MWTApBglghkgBZQIBBUQxHAwaSHVtYW4gUmVzb3VyY2VzIERlcGFydG1l
bnQwCgYIKoZIzj0EAwMDaAAwZQIwVh/RypULFgPpAN0I7OvuMomRWnm/Hea3Hk8P
tTRz2Zai8iYat7oeAmGVgMhSXy2jAjEAuJW4l/CFatBy4W/lZ7gS3weBdBa5WEDI
FFMC7GjGtCeLtXYqWfBnRdK26dOaHLB2
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        clearance_found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectDirectoryAttributes:
                assert extn['extnID'] in rfc5280.certificateExtensionsMap.keys()
                ev, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                assert not rest
                assert ev.prettyPrint()
                assert der_encode(ev) == extn['extnValue']

                for attr in ev:
                    if attr['type'] == rfc5755.id_at_clearance:
                        assert attr['type'] in rfc5280.certificateAttributesMap.keys()
                        av, rest = der_decode(attr['values'][0],
                            asn1Spec=rfc5280.certificateAttributesMap[attr['type']])
                        assert av['policyId'] == rfc3114.id_tsp_TEST_Whirlpool
                        for cat in av['securityCategories']:
                            assert cat['type'] == rfc3114.id_tsp_TEST_Whirlpool_Categories
                            assert cat['type'] in rfc5755.securityCategoryMap.keys()
                            catv, rest = der_decode(cat['value'],
                                asn1Spec=rfc5755.securityCategoryMap[cat['type']])
                            assert u'USE ONLY' in catv[0]
                            clearance_found = True

        assert clearance_found

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        clearance_found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectDirectoryAttributes:
                assert extn['extnID'] in rfc5280.certificateExtensionsMap.keys()
                ev, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']],
                    decodeOpenTypes=True)
                assert not rest
                assert ev.prettyPrint()
                assert der_encode(ev) == extn['extnValue']

                for attr in ev:
                    if attr['type'] == rfc5755.id_at_clearance:
                        spid = rfc3114.id_tsp_TEST_Whirlpool
                        catid = rfc3114.id_tsp_TEST_Whirlpool_Categories
                        assert attr['values'][0]['policyId'] == spid
                        for cat in attr['values'][0]['securityCategories']:
                            assert cat['type'] == catid
                            assert u'USE ONLY' in cat['value'][0]
                            clearance_found = True

        assert clearance_found


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
