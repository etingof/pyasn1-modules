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
from pyasn1_modules import rfc2631

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class OtherInfoTestCase(unittest.TestCase):
    pem_text = "MB0wEwYLKoZIhvcNAQkQAwYEBAAAAAGiBgQEAAAAwA=="

    def setUp(self):
        self.asn1Spec = rfc2631.OtherInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        hex1 = univ.OctetString(hexValue='00000001')
        assert asn1Object['keyInfo']['counter'] == hex1


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
