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
from pyasn1_modules import rfc5990

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class RSAKEMTestCase(unittest.TestCase):
    pem_text = """\
MEcGCyqGSIb3DQEJEAMOMDgwKQYHKIGMcQICBDAeMBkGCiuBBRCGSAksAQIwCwYJ
YIZIAWUDBAIBAgEQMAsGCWCGSAFlAwQBBQ==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['algorithm'] == rfc5990.id_rsa_kem
        rsa_kem_p, rest = der_decode(asn1Object['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[rfc5990.id_rsa_kem])
        assert not rest
        assert rsa_kem_p.prettyPrint()
        assert der_encode(rsa_kem_p) == asn1Object['parameters']

        assert rsa_kem_p['kem']['algorithm'] == rfc5990.id_kem_rsa
        kem_rsa_p, rest = der_decode(rsa_kem_p['kem']['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[rfc5990.id_kem_rsa])
        assert not rest
        assert kem_rsa_p.prettyPrint()
        assert der_encode(kem_rsa_p) == rsa_kem_p['kem']['parameters']

        assert kem_rsa_p['keyLength'] == 16
        assert kem_rsa_p['keyDerivationFunction']['algorithm'] == rfc5990.id_kdf_kdf3
        kdf_p, rest = der_decode(kem_rsa_p['keyDerivationFunction']['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[rfc5990.id_kdf_kdf3])
        assert not rest
        assert kdf_p.prettyPrint()
        assert der_encode(kdf_p) == kem_rsa_p['keyDerivationFunction']['parameters']

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['algorithm'] == rfc5990.id_rsa_kem
        assert asn1Object['parameters']['kem']['algorithm'] == rfc5990.id_kem_rsa
        assert asn1Object['parameters']['kem']['parameters']['keyLength'] == 16


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys
	
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
