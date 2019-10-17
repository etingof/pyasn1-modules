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
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc6960

try:
    import unittest2 as unittest

except ImportError:
    import unittest


class OCSPRequestTestCase(unittest.TestCase):
    ocsp_req_pem_text = """\
MGowaDBBMD8wPTAJBgUrDgMCGgUABBS3ZrMV9C5Dko03aH13cEZeppg3wgQUkqR1LKSevoFE63n8
isWVpesQdXMCBDXe9M+iIzAhMB8GCSsGAQUFBzABAgQSBBBjdJOiIW9EKJGELNNf/rdA
"""

    def setUp(self):
        self.asn1Spec = rfc6960.OCSPRequest()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.ocsp_req_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['tbsRequest']['version'] == 0

        count = 0
        for extn in asn1Object['tbsRequest']['requestExtensions']:
            assert extn['extnID'] in rfc5280.certificateExtensionsMap.keys()
            ev, rest = der_decode(extn['extnValue'],
                asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
            assert not rest
            assert ev.prettyPrint()
            assert der_encode(ev) == extn['extnValue']
            count += 1

        assert count == 1

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.ocsp_req_pem_text)
        asn1Object, rest = der_decode(substrate,
           asn1Spec=self.asn1Spec,
           decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['tbsRequest']['version'] == 0
        for req in  asn1Object['tbsRequest']['requestList']:
            ha = req['reqCert']['hashAlgorithm']
            assert ha['algorithm'] == rfc4055.id_sha1
            assert ha['parameters'] == univ.Null("")


class OCSPResponseTestCase(unittest.TestCase):
    ocsp_resp_pem_text = """\
MIIEvQoBAKCCBLYwggSyBgkrBgEFBQcwAQEEggSjMIIEnzCCAQ+hgYAwfjELMAkGA1UEBhMCQVUx
EzARBgNVBAgTClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEV
MBMGA1UEAxMMc25tcGxhYnMuY29tMSAwHgYJKoZIhvcNAQkBFhFpbmZvQHNubXBsYWJzLmNvbRgP
MjAxMjA0MTExNDA5MjJaMFQwUjA9MAkGBSsOAwIaBQAEFLdmsxX0LkOSjTdofXdwRl6mmDfCBBSS
pHUspJ6+gUTrefyKxZWl6xB1cwIENd70z4IAGA8yMDEyMDQxMTE0MDkyMlqhIzAhMB8GCSsGAQUF
BzABAgQSBBBjdJOiIW9EKJGELNNf/rdAMA0GCSqGSIb3DQEBBQUAA4GBADk7oRiCy4ew1u0N52QL
RFpW+tdb0NfkV2Xyu+HChKiTThZPr9ZXalIgkJ1w3BAnzhbB0JX/zq7Pf8yEz/OrQ4GGH7HyD3Vg
PkMu+J6I3A2An+bUQo99AmCbZ5/tSHtDYQMQt3iNbv1fk0yvDmh7UdKuXUNSyJdHeg27dMNy4k8A
oIIC9TCCAvEwggLtMIICVqADAgECAgEBMA0GCSqGSIb3DQEBBQUAMH4xCzAJBgNVBAYTAkFVMRMw
EQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxFTAT
BgNVBAMTDHNubXBsYWJzLmNvbTEgMB4GCSqGSIb3DQEJARYRaW5mb0Bzbm1wbGFicy5jb20wHhcN
MTIwNDExMTMyNTM1WhcNMTMwNDExMTMyNTM1WjB+MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29t
ZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMRUwEwYDVQQDEwxzbm1w
bGFicy5jb20xIDAeBgkqhkiG9w0BCQEWEWluZm9Ac25tcGxhYnMuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDDDU5HOnNV8I2CojxB8ilIWRHYQuaAjnjrETMOprouDHFXnwWqQo/I3m0b
XYmocrh9kDefb+cgc7+eJKvAvBqrqXRnU38DmQU/zhypCftGGfP8xjuBZ1n23lR3hplN1yYA0J2X
SgBaAg6e8OsKf1vcX8Es09rDo8mQpt4G2zR56wIDAQABo3sweTAJBgNVHRMEAjAAMCwGCWCGSAGG
+EIBDQQfFh1PcGVuU1NMIEdlbmVyYXRlZCBDZXJ0aWZpY2F0ZTAdBgNVHQ4EFgQU8Ys2dpJFLMHl
yY57D4BNmlqnEcYwHwYDVR0jBBgwFoAU8Ys2dpJFLMHlyY57D4BNmlqnEcYwDQYJKoZIhvcNAQEF
BQADgYEAWR0uFJVlQId6hVpUbgXFTpywtNitNXFiYYkRRv77McSJqLCa/c1wnuLmqcFcuRUK0oN6
8ZJDP2HDDKe8MCZ8+sx+CF54eM8VCgN9uQ9XyE7x9XrXDd3Uw9RJVaWSIezkNKNeBE0lDM2jUjC4
HAESdf7nebz1wtqAOXE1jWF/y8g=
"""

    def setUp(self):
        self.asn1Spec = rfc6960.OCSPResponse()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.ocsp_resp_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['responseStatus'] == 0
        rb = asn1Object['responseBytes']
        assert rb['responseType'] in rfc6960.ocspResponseMap.keys()
        resp, rest = der_decode(rb['response'],
                asn1Spec=rfc6960.ocspResponseMap[rb['responseType']])
        assert not rest
        assert resp.prettyPrint()
        assert der_encode(resp) == rb['response']

        resp['tbsResponseData']['version'] == 0
        count = 0
        for extn in resp['tbsResponseData']['responseExtensions']:
            assert extn['extnID'] in rfc5280.certificateExtensionsMap.keys()
            ev, rest = der_decode(extn['extnValue'],
                asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
            assert not rest
            assert ev.prettyPrint()
            assert der_encode(ev) == extn['extnValue']
            count += 1

        assert count == 1

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.ocsp_resp_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['responseStatus'] == 0
        rb = asn1Object['responseBytes']
        assert rb['responseType'] in rfc6960.ocspResponseMap.keys()
        resp, rest = der_decode(rb['response'],
                asn1Spec=rfc6960.ocspResponseMap[rb['responseType']],
                decodeOpenTypes=True)
        assert not rest
        assert resp.prettyPrint()
        assert der_encode(resp) == rb['response']

        resp['tbsResponseData']['version'] == 0
        for rdn in resp['tbsResponseData']['responderID']['byName']['rdnSequence']:
            for attr in rdn:
                if attr['type'] == rfc5280.id_emailAddress:
                    assert attr['value'] == 'info@snmplabs.com'

        for r in resp['tbsResponseData']['responses']:
            ha = r['certID']['hashAlgorithm']
            assert ha['algorithm'] == rfc4055.id_sha1
            assert ha['parameters'] == univ.Null("")


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
