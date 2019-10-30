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
from pyasn1_modules import rfc6120

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class XMPPCertificateTestCase(unittest.TestCase):
    xmpp_server_cert_pem_text = """\
MIIC6DCCAm+gAwIBAgIJAKWzVCgbsG5DMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMTkxMDI0MjMxNjA0WhcNMjAxMDIzMjMxNjA0WjBNMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xHzAdBgNVBAoTFkV4
YW1wbGUgUHJvZHVjdHMsIEluYy4wdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQZzQlk
03nJRPF6+w1NxFELmQ5vJTjTRz3eu03CRtahK4Wnwd4GwbDe8NVHAEG2qTzBXFDu
p6RZugsBdf9GcEZHG42rThYYOzIYzVFnI7tQgA+nTWSWZN6eoU/EXcknhgijggEn
MIIBIzAdBgNVHQ4EFgQUkQpUMYcbUesEn5buI03POFnktJgwHwYDVR0jBBgwFoAU
8jXbNATapVXyvWkDmbBi7OIVCMEwCwYDVR0PBAQDAgeAMIGPBgNVHREEgYcwgYSg
KQYIKwYBBQUHCAegHRYbX3htcHAtY2xpZW50LmltLmV4YW1wbGUuY29toCkGCCsG
AQUFBwgHoB0WG194bXBwLXNlcnZlci5pbS5leGFtcGxlLmNvbaAcBggrBgEFBQcI
BaAQDA5pbS5leGFtcGxlLmNvbYIOaW0uZXhhbXBsZS5jb20wQgYJYIZIAYb4QgEN
BDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRydXN0ZWQgZm9yIGFueSBw
dXJwb3NlLjAKBggqhkjOPQQDAwNnADBkAjAEo4mhDGC6/R39HyNgzLseNAp36qBH
yQJ/AWsBojN0av8akeVv9IuM45yqLKdiCzcCMDCjh1lFnCvurahwp5D1j9pAZMsg
nOzhcMpnHs2U/eN0lHl/JNgnbftl6Dvnt59xdA==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.xmpp_server_cert_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        count = 0
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                extnValue, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName())
                assert not rest
                assert extnValue.prettyPrint()
                assert der_encode(extnValue) == extn['extnValue']
                for gn in extnValue:
                    if gn['otherName'].hasValue():
                        gn_on = gn['otherName']
                        if gn_on['type-id'] == rfc6120.id_on_xmppAddr:
                            assert gn_on['type-id'] in rfc5280.anotherNameMap.keys()
                            spec = rfc5280.anotherNameMap[gn['otherName']['type-id']]
                            on, rest = der_decode(gn_on['value'], asn1Spec=spec)
                            assert not rest
                            assert on.prettyPrint()
                            assert der_encode(on) == gn_on['value']
                            assert on == u'im.example.com'
                            count += 1

        assert count == 1

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.xmpp_server_cert_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        count = 0
        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                extnValue, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName(), decodeOpenTypes=True)
                assert not rest
                assert extnValue.prettyPrint()
                assert der_encode(extnValue) == extn['extnValue']
                for gn in extnValue:
                    if gn['otherName'].hasValue():
                        if gn['otherName']['type-id'] == rfc6120.id_on_xmppAddr:
                            assert gn['otherName']['value'] == u'im.example.com'
                            count += 1

        assert count == 1


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
