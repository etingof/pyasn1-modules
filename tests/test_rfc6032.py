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
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc6032
from pyasn1_modules import rfc3565

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class EncryptedKeyPkgTestCase(unittest.TestCase):
    encrypted_key_pkg_pem_text = """\
MIIBBwYKYIZIAWUCAQJOAqCB+DCB9QIBAjCBzgYKYIZIAWUCAQJOAjAdBglghkgB
ZQMEASoEEN6HFteHMZ3DyeO35xIwWQOAgaCKTs0D0HguNzMhsLgiwG/Kw8OwX+GF
9/cZ1YVNesUTW/VsbXJcbTmFmWyfqZsM4DLBegIbrUEHQZnQRq6/NO4ricQdHApD
B/ip6RRqeN1yxMJLv1YN0zUOOIDBS2iMEjTLXZLWw3w22GN2JK7G+Lr4OH1NhMgU
ILJyh/RePmPseMwxvcJs7liEfkiSNMtDfEcpjtzA9bDe95GjhQRsiSByoR8wHQYJ
YIZIAWUCAQVCMRAEDnB0Zi1rZGMtODEyMzc0
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.encrypted_key_pkg_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        assert asn1Object['contentType'] == rfc6032.id_ct_KP_encryptedKeyPkg

        content, rest = der_decode(asn1Object['content'], rfc6032.EncryptedKeyPackage())
        assert not rest
        assert content.prettyPrint()
        assert der_encode(content) == asn1Object['content']
        assert content.getName() == 'encrypted'
        eci = content['encrypted']['encryptedContentInfo']
        assert eci['contentType'] == rfc6032.id_ct_KP_encryptedKeyPkg
        attrType = content['encrypted']['unprotectedAttrs'][0]['attrType']
        assert attrType == rfc6032.id_aa_KP_contentDecryptKeyID

        attrVal0 = content['encrypted']['unprotectedAttrs'][0]['attrValues'][0]
        keyid, rest = der_decode(attrVal0, rfc6032.ContentDecryptKeyID())
        assert not rest
        assert keyid.prettyPrint()
        assert der_encode(keyid) == attrVal0
        assert keyid == b'ptf-kdc-812374'

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.encrypted_key_pkg_pem_text)
        asn1Object, rest = der_decode(substrate,
                                      asn1Spec=self.asn1Spec,
                                      decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] in rfc5652.cmsContentTypesMap
        eci = asn1Object['content']['encrypted']['encryptedContentInfo']
        assert eci['contentType'] in rfc5652.cmsContentTypesMap

        for attr in asn1Object['content']['encrypted']['unprotectedAttrs']:
            assert attr['attrType'] in rfc5652.cmsAttributesMap.keys()
            assert attr['attrValues'][0].prettyPrint()[:2] != '0x'
            if attr['attrType'] == rfc6032.id_aa_KP_contentDecryptKeyID:
                assert attr['attrValues'][0] == str2octs('ptf-kdc-812374')


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
