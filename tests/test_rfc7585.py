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
from pyasn1_modules import rfc7585

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class NAIRealmCertTestCase(unittest.TestCase):
    cert_pem_text = """\
MIIEZzCCA0+gAwIBAgIBBzANBgkqhkiG9w0BAQsFADCBkjELMAkGA1UEBhMCRlIx
DzANBgNVBAgMBlJhZGl1czESMBAGA1UEBwwJU29tZXdoZXJlMRQwEgYDVQQKDAtF
eGFtcGxlIEluYzEgMB4GCSqGSIb3DQEJARYRYWRtaW5AZXhhbXBsZS5vcmcxJjAk
BgNVBAMMHUV4YW1wbGUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MB4XDTE5MTExMTE4
MDQyMVoXDTIwMDExMDE4MDQyMVowezELMAkGA1UEBhMCRlIxDzANBgNVBAgMBlJh
ZGl1czEUMBIGA1UECgwLRXhhbXBsZSBJbmMxIzAhBgNVBAMMGkV4YW1wbGUgU2Vy
dmVyIENlcnRpZmljYXRlMSAwHgYJKoZIhvcNAQkBFhFhZG1pbkBleGFtcGxlLm9y
ZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAM9HqbuyWpsTMKo739Dm
DwmQo2HUkNdQYbvsB+e7ILsw8fWa2qnsF1CoRr/1bcZqXUR1To/QbHse7xSMZH9t
F7rdlDMc7QtgdwVfn8TiL3hCg5LSE8iaBzfJUjrts/V5WOByP1DwJVM7W3Va/5dN
oOiceVeC7ThghMlwIx/wN5cy78a8fPYV2FvPR6e+U2HG35zaIv2PizYcliF/QmZG
gnw4Q9dYC1Lw/ogVBZBALlv+/MuGheb/xIuL8lu1PFZ0YbW65WLD9Cx4wvytAke7
tKlhL/Kd4OBSeOY3OYmpxbc1gEUmFoLTlZesY2NP9Jyl5mGsIHtPdvVkh/tSBy8o
VLUCAwEAAaOB3TCB2jAJBgNVHRMEAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUEDDAK
BggrBgEFBQcDATA2BgNVHR8ELzAtMCugKaAnhiVodHRwOi8vd3d3LmV4YW1wbGUu
Y29tL2V4YW1wbGVfY2EuY3JsMDcGCCsGAQUFBwEBBCswKTAnBggrBgEFBQcwAYYb
aHR0cDovL3d3dy5leGFtcGxlLm9yZy9vY3NwMDoGA1UdEQQzMDGCEnJhZGl1cy5l
eGFtcGxlLm9yZ6AbBggrBgEFBQcICKAPDA0qLmV4YW1wbGUuY29tMA0GCSqGSIb3
DQEBCwUAA4IBAQBOhtH2Jpi0b0MZ8FBKTqDl44rIHL1rHG2mW/YYmRI4jZo8kFhA
yWm/T8ZpdaotJgRqbQbeXvTXIg4/JNFheyLG4yLOzS1esdMAYDD5EN9/dXE++jND
/wrfPU+QtTgzAjkgFDKuqO7gr1/vSizxLYTWLKBPRHhiQo7GGlEC6/CPb38x4mfQ
5Y9DsKCp6BEZu+LByCho/HMDzcIPCdtXRX7Fs8rtX4/zRpVIdm6D+vebuo6CwRKp
mIljfssCvZjb9YIxSVDmA/6Lapqsfsfo922kb+MTXvPrq2ynPx8LrPDrxKc8maYc
Jiw8B0yjkokwojxyRGftMT8uxNjWQVsMDbxl
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        nai_realm_oid = rfc7585.id_on_naiRealm
        nai_realm_found = False

        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                extnValue, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName())
                assert not rest
                assert extnValue.prettyPrint()
                assert der_encode(extnValue) == extn['extnValue']

                for gn in extnValue:
                    if gn['otherName'].hasValue():
                        assert gn['otherName']['type-id'] == nai_realm_oid
                        onValue, rest = der_decode(gn['otherName']['value'],
                            asn1Spec=rfc7585.NAIRealm())
                        assert not rest
                        assert onValue.prettyPrint()
                        assert der_encode(onValue) == gn['otherName']['value']
                        assert 'example' in onValue
                        nai_realm_found = True

        assert nai_realm_found

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.cert_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        nai_realm_oid = rfc7585.id_on_naiRealm
        nai_realm_found = False

        for extn in asn1Object['tbsCertificate']['extensions']:
            if extn['extnID'] == rfc5280.id_ce_subjectAltName:
                extnValue, rest = der_decode(extn['extnValue'],
                    asn1Spec=rfc5280.SubjectAltName(),
                    decodeOpenTypes=True)
                assert not rest
                assert extnValue.prettyPrint()
                assert der_encode(extnValue) == extn['extnValue']

                for gn in extnValue:
                    if gn['otherName'].hasValue():
                        assert gn['otherName']['type-id'] == nai_realm_oid
                        assert 'example' in gn['otherName']['value']
                        nai_realm_found = True

        assert nai_realm_found


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
