#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2019, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
import sys

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

from pyasn1_modules import pem
from pyasn1_modules import rfc4055
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc8649

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class RootCertificateExtnTestCase(unittest.TestCase):
    extn_pem_text = """\
MGEGCisGAQQBg5IbAgEEUzBRMA0GCWCGSAFlAwQCAwUABEBxId+rK+WVDLOda2Yk
FFRbqQAztXhs91j/RxHjYJIv/3gleQg3Qix/yQy2rIg3xysjCvHWw8AuYOGVh/sL
GANG
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.extn_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        
        assert asn1Object['extnID'] == rfc8649.id_ce_hashOfRootKey
        hashed_root_key, rest = der_decode(asn1Object['extnValue'],
            rfc8649.HashedRootKey())
        assert not rest
        assert hashed_root_key.prettyPrint()
        assert der_encode(hashed_root_key) == asn1Object['extnValue']

        assert hashed_root_key['hashAlg']['algorithm'] == rfc4055.id_sha512

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.extn_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest

        assert asn1Object['extnID'] == rfc8649.id_ce_hashOfRootKey
        assert asn1Object['extnID'] in rfc5280.certificateExtensionsMap.keys()


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
