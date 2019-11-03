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
from pyasn1_modules import rfc5916

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class DeviceCertTestCase(unittest.TestCase):
    cert_pem_text = """\
MIICpzCCAiygAwIBAgIJAKWzVCgbsG5FMAoGCCqGSM49BAMDMD8xCzAJBgNVBAYT
AlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRvbjERMA8GA1UECgwIQm9n
dXMgQ0EwHhcNMTkxMDMxMTQwMDE1WhcNMjAxMDMwMTQwMDE1WjB4MQswCQYDVQQG
EwJVUzELMAkGA1UECBMCVkExEDAOBgNVBAcTB0hlcm5kb24xEDAOBgNVBAoTB0V4
YW1wbGUxGjAYBgNVBAsTEURldmljZSBPcGVyYXRpb25zMRwwGgYDVQQDExNleDEy
MzQ1LmV4YW1wbGUuY29tMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE7Lje3glS2qYl
5x6N9TOlD4CbnzfFeJQfbDaCa3vexEiwE0apuAP+4L5fqOsYeZC970iNW+z3PdUs
GzkKDC2cCVy8nIxQ3mWhNQDvavT3iz5OGSwa1GjSXRFbGn2x9QjNo4G6MIG3MEIG
CWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0cnVzdGVk
IGZvciBhbnkgcHVycG9zZS4wHQYDVR0OBBYEFPTQN1kXEM5Rd4hNvQL5HyA+o2No
MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMAsGA1UdDwQEAwIHgDAk
BgNVHQkEHTAbMBkGCWCGSAFlAgEFRTEMBgorBgEEAYGsYDAYMAoGCCqGSM49BAMD
A2kAMGYCMQCt6AceOEIwXFKFHIV8+wTK/vgs7ZYSA6jhXUpzNtzZw1xh9NxVUhmx
pogu5Q9Vp28CMQC5YVF8dShC1tk9YImRftiVl8C6pbj//1K/+MwmR6nRk/WU+hKl
+Qsc5Goi6At471s=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        found_dev_owner = False
        der_dev_own_oid = der_encode(univ.ObjectIdentifier('1.3.6.1.4.1.22112.48.24'))

        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectDirectoryAttributes:
                assert extn['extnID'] in rfc5280.certificateExtensionsMap.keys()
                ev, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
                assert not rest
                assert ev.prettyPrint()
                assert der_encode(ev) == extn['extnValue']

                for attr in ev:
                    if attr['type'] == rfc5916.id_deviceOwner:
                        assert attr['values'][0] == der_dev_own_oid
                        found_dev_owner = True

        assert found_dev_owner

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        found_dev_owner = False
        dev_own_oid = univ.ObjectIdentifier('1.3.6.1.4.1.22112.48.24')

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
                    if attr['type'] == rfc5916.id_deviceOwner:
                        assert attr['values'][0] == dev_own_oid
                        found_dev_owner = True

        assert found_dev_owner


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
