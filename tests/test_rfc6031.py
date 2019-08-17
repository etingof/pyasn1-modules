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
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6031

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class SymmetricKeyPkgTestCase(unittest.TestCase):
    key_pkg_pem_text = """\
MIG7BgsqhkiG9w0BCRABGaCBqzCBqKBEMCMGCyqGSIb3DQEJEAwBMRQMElZpZ2ls
IFNlY3VyaXR5IExMQzAdBgsqhkiG9w0BCRAMAzEODAxQcmV0ZW5kIDA0OEEwYDBe
MFYwGwYLKoZIhvcNAQkQDBsxDAwKZXhhbXBsZUlEMTAVBgsqhkiG9w0BCRAMCjEG
DARIT1RQMCAGCyqGSIb3DQEJEAwLMREMD2t0YS5leGFtcGxlLmNvbQQEMTIzNA==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.key_pkg_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
    
        assert asn1Object['contentType'] in rfc5652.cmsContentTypesMap
        asn1Spec = rfc5652.cmsContentTypesMap[asn1Object['contentType']]
        skp, rest = der_decode(asn1Object['content'], asn1Spec=asn1Spec)
        assert not rest
        assert skp.prettyPrint()
        assert der_encode(skp) == asn1Object['content']

        for attr in skp['sKeyPkgAttrs']:
            assert attr['attrType'] in rfc6031.sKeyPkgAttributesMap.keys()

        for osk in skp['sKeys']:
            for attr in osk['sKeyAttrs']:
                assert attr['attrType'] in rfc6031.sKeyAttributesMap.keys()

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.key_pkg_pem_text)
        asn1Object, rest = der_decode(substrate, 
                                      asn1Spec=self.asn1Spec,
                                      decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] in rfc5652.cmsContentTypesMap
        assert asn1Object['content'].hasValue()
        keypkg = asn1Object['content']
        assert keypkg['version'] == rfc6031.KeyPkgVersion().subtype(value='v1')

        for attr in keypkg['sKeyPkgAttrs']:
            assert attr['attrType'] in rfc6031.sKeyPkgAttributesMap.keys()
            assert attr['attrValues'][0].prettyPrint()[:2] != '0x'
            # decodeOpenTypes=True did not decode if the value is shown in hex ...
            if attr['attrType'] == rfc6031.id_pskc_manufacturer:
                attr['attrValues'][0] == 'Vigil Security LLC'

        for osk in keypkg['sKeys']:
            for attr in osk['sKeyAttrs']:
                assert attr['attrType'] in rfc6031.sKeyAttributesMap.keys()
                assert attr['attrValues'][0].prettyPrint()[:2] != '0x'
                # decodeOpenTypes=True did not decode if the value is shown in hex ...
                if attr['attrType'] == rfc6031.id_pskc_issuer:
                    attr['attrValues'][0] == 'kta.example.com'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
