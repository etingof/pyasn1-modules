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
from pyasn1_modules import rfc8018

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class PWRITestCase(unittest.TestCase):
    rfc3211_ex1_pem_text = """\
o1MCAQCgGgYJKoZIhvcNAQUMMA0ECBI0Vnh4VjQSAgEFMCAGCyqGSIb3DQEJEAMJMBEGBSsO
AwIHBAjv5ZjvIbM9bQQQuBslZe43PKbe3KJqF4sMEA==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.RecipientInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.rfc3211_ex1_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        alg_oid = asn1Object['pwri']['keyDerivationAlgorithm']['algorithm']
        assert alg_oid == rfc8018.id_PBKDF2

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.rfc3211_ex1_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate
        icount = asn1Object['pwri']['keyDerivationAlgorithm']['parameters']['iterationCount']
        assert icount == 5

suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
