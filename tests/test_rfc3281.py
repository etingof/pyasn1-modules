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
from pyasn1_modules import rfc3281

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
        self.asn1Spec = rfc3281.AttributeCertificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['acinfo']['version'] == 1

        attributeMap = {
            rfc3281.id_at_role: rfc3281.RoleSyntax(),
            rfc3281.id_aca_authenticationInfo: rfc3281.SvceAuthInfo(),
            rfc3281.id_aca_accessIdentity: rfc3281.SvceAuthInfo(),
            rfc3281.id_aca_chargingIdentity: rfc3281.IetfAttrSyntax(),
            rfc3281.id_aca_group: rfc3281.IetfAttrSyntax(),
        }

        count = 0
        for attr in asn1Object['acinfo']['attributes']:
            assert attr['type'] in attributeMap
            av, rest = der_decode(attr['values'][0],
                asn1Spec=attributeMap[attr['type']])
            assert not rest
            assert av.prettyPrint()
            assert der_encode(av) == attr['values'][0]
            count += 1

        assert count == 5


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
