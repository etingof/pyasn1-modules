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

from pyasn1.compat.octets import str2octs

from pyasn1_modules import pem
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc4334

try:
    import unittest2 as unittest
except ImportError:
    import unittest

class CertificateTestCase(unittest.TestCase):
    cert_pem_text = """\
MIICqzCCAjCgAwIBAgIJAKWzVCgbsG4/MAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMTkwNzE5MTk0MjQ3WhcNMjAwNzE4MTk0MjQ3WjBjMQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xGzAZBgNVBAoTElZp
Z2lsIFNlY3VyaXR5IExMQzEYMBYGA1UEAxMPZWFwLmV4YW1wbGUuY29tMHYwEAYH
KoZIzj0CAQYFK4EEACIDYgAEMMbnIp2BUbuyMgH9HhNHrh7VBy7ql2lBjGRSsefR
Wa7+vCWs4uviW6On4eem5YoP9/UdO7DaIL+/J9/3DJHERI17oFxn+YWiE4JwXofy
QwfSu3cncVNMqpiDjEkUGGvBo4HTMIHQMAsGA1UdDwQEAwIHgDBCBglghkgBhvhC
AQ0ENRYzVGhpcyBjZXJ0aWZpY2F0ZSBjYW5ub3QgYmUgdHJ1c3RlZCBmb3IgYW55
IHB1cnBvc2UuMB0GA1UdDgQWBBSDjPGr7M742rsE4oQGwBvGvllZ+zAfBgNVHSME
GDAWgBTyNds0BNqlVfK9aQOZsGLs4hUIwTAeBggrBgEFBQcBDQQSMBAEB0V4YW1w
bGUEBUJvZ3VzMB0GA1UdJQQWMBQGCCsGAQUFBwMOBggrBgEFBQcDDTAKBggqhkjO
PQQDAwNpADBmAjEAmCPZnnlUQOKlcOIIOgFrRCkOqO0ESs+dobYwAc2rFCBtQyP7
C3N00xkX8WZZpiAZAjEAi1Z5+nGbJg5eJTc8fwudutN/HNwJEIS6mHds9kfcy26x
DAlVlhox680Jxy5J8Pkx
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        extn_list = [ ]
        for extn in asn1Object['tbsCertificate']['extensions']:
            extn_list.append(extn['extnID'])
            if extn['extnID'] in rfc5280.certificateExtensionsMap.keys():
                extnValue, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                assert der_encode(extnValue) == extn['extnValue']

                if extn['extnID'] == rfc4334.id_pe_wlanSSID:
                    assert str2octs('Example') in extnValue
            
                if extn['extnID'] == rfc5280.id_ce_extKeyUsage:
                     assert rfc4334.id_kp_eapOverLAN in extnValue
                     assert rfc4334.id_kp_eapOverPPP in extnValue

        assert rfc4334.id_pe_wlanSSID in extn_list
        assert rfc5280.id_ce_extKeyUsage in extn_list


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
