#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2019, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
import sys

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

from pyasn1.type import univ

from pyasn1_modules import pem
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc5126

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class SignedAttributesTestCase(unittest.TestCase):
    pem_text = """\
MYIBUzAYBgkqhkiG9w0BCQMxCwYJKoZIhvcNAQcBMCsGCSqGSIb3DQEJNDEeMBww
DQYJYIZIAWUDBAIBBQChCwYJKoZIhvcNAQELMC8GCSqGSIb3DQEJBDEiBCCyqtCC
Gosj/GT4YPPAqKheze4A1QBU5O3tniTsVPGr7jBBBgsqhkiG9w0BCRACETEyMDCg
BBMCVVOhBBMCVkGiIjAgExExMjMgU29tZXBsYWNlIFdheRMLSGVybmRvbiwgVkEw
RgYLKoZIhvcNAQkQAi8xNzA1MDMwMTANBglghkgBZQMEAgEFAAQgJPmqUmGQnQ4q
RkVtUHecJXIkozOzX8+pZQj/UD5JcnQwTgYLKoZIhvcNAQkQAg8xPzA9BgorBgEE
AYGsYDAUMC8wCwYJYIZIAWUDBAIBBCDWjjVmAeXgZBkE/rG8Pf8pTCs4Ikowc8Vm
l+AOeKdFgg==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.SignedAttributes()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        found_spid_oid = False
        for attr in asn1Object:
            if attr['attrType'] in rfc5652.cmsAttributesMap.keys():
                av, rest = der_decode (attr['attrValues'][0],
                    asn1Spec=rfc5652.cmsAttributesMap[attr['attrType']])
                assert not rest
                assert av.prettyPrint()
                assert der_encode(av) == attr['attrValues'][0]

                if attr['attrType'] == rfc5126.id_aa_ets_sigPolicyId:
                    spid_oid = rfc5126.SigPolicyId('1.3.6.1.4.1.22112.48.20')
                    assert av['signaturePolicyId']['sigPolicyId'] == spid_oid
                    found_spid_oid = True

        assert found_spid_oid

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        attr_type_list = [ ]
        spid_oid = rfc5126.SigPolicyId('1.3.6.1.4.1.22112.48.20')

        for attr in asn1Object:
            if attr['attrType'] == rfc5126.id_aa_ets_sigPolicyId:
                spid = attr['attrValues'][0]['signaturePolicyId']
                assert spid['sigPolicyId'] == spid_oid
                attr_type_list.append(rfc5126.id_aa_ets_sigPolicyId)

            if attr['attrType'] == rfc5126.id_aa_ets_signerLocation:
                cn = attr['attrValues'][0]['countryName']
                assert cn['printableString'] == 'US'
                attr_type_list.append(rfc5126.id_aa_ets_signerLocation)

            if attr['attrType'] == rfc5126.id_aa_signingCertificateV2:
                ha = attr['attrValues'][0]['certs'][0]['hashAlgorithm']
                assert ha['algorithm'] == rfc4055.id_sha256
                attr_type_list.append(rfc5126.id_aa_signingCertificateV2)

        assert rfc5126.id_aa_ets_sigPolicyId in attr_type_list
        assert rfc5126.id_aa_ets_signerLocation in attr_type_list
        assert rfc5126.id_aa_signingCertificateV2 in attr_type_list


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
