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
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6210

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class AuthenticatedDataTestCase(unittest.TestCase):
    pem_text = """\
MIICRQYLKoZIhvcNAQkQAQKgggI0MIICMAIBADGBwDCBvQIBADAmMBIxEDAOBgNVBAMMB0
NhcmxSU0ECEEY0a8eAAFa8EdNuLs1dcdAwDQYJKoZIhvcNAQEBBQAEgYCH70EpEikY7deb
859YJRAWfFondQv1D4NFltw6C1ceheWnlAU0C2WEXr3LUBXZp1/PSte29FnJxu5bXCTn1g
elMm6zNlZNWNd0KadVBcaxi1n8L52tVM5sWFGJPO5cStOyAka2ucuZM6iAnCSkn1Ju7fgU
5j2g3bZ/IM8nHTcygjAKBggrBgEFBQgBAqFPBgsqhkiG9w0BCRADDQRAAQIDBAUGBwgJCg
sMDQ4PEBESEwQVFhcYGRobHB0eHyAhIiMEJSYnKCkqKywtLi8wMTIzBDU2Nzg5Ojs8PT4/
QDArBgkqhkiG9w0BBwGgHgQcVGhpcyBpcyBzb21lIHNhbXBsZSBjb250ZW50LqKBxzAYBg
kqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0wOTEyMTAyMzI1MDBa
MB8GCSqGSIb3DQEJBDESBBCWaa5hG1eeg+oQK2tJ3cD5MGwGCSqGSIb3DQEJNDFfMF0wTw
YLKoZIhvcNAQkQAw0EQAECAwQFBgcICQoLDA0ODxAREhMEFRYXGBkaGxwdHh8gISIjBCUm
JygpKissLS4vMDEyMwQ1Njc4OTo7PD0+P0CiCgYIKwYBBQUIAQIEFLjUxQ9PJFzFnWraxb
EIbVbg2xql
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode (substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_ct_authData
        ad, rest = der_decode (asn1Object['content'], asn1Spec=rfc5652.AuthenticatedData())
        assert not rest
        assert ad.prettyPrint()
        assert der_encode(ad) == asn1Object['content']

        assert ad['version'] == 0
        assert ad['digestAlgorithm']['algorithm'] == rfc6210.id_alg_MD5_XOR_EXPERIMENT

        mac_alg_p, rest = der_decode (ad['digestAlgorithm']['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[ad['digestAlgorithm']['algorithm']])
        assert not rest
        assert mac_alg_p.prettyPrint()
        assert der_encode(mac_alg_p) == ad['digestAlgorithm']['parameters']

        assert mac_alg_p.prettyPrint()[:10] == "0x01020304"


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
