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
from pyasn1_modules import rfc8419

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class Ed25519TestCase(unittest.TestCase):
    alg_id_1_pem_text = "MAUGAytlcA=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.alg_id_1_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_Ed25519
        assert not asn1Object['parameters'].isValue
        assert der_encode(asn1Object) == substrate


class Ed448TestCase(unittest.TestCase):
    alg_id_2_pem_text = "MAUGAytlcQ=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.alg_id_2_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_Ed448
        assert not asn1Object['parameters'].isValue
        assert der_encode(asn1Object) == substrate


class SHA512TestCase(unittest.TestCase):
    alg_id_3_pem_text = "MAsGCWCGSAFlAwQCAw=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.alg_id_3_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_sha512
        assert not asn1Object['parameters'].isValue
        assert der_encode(asn1Object) == substrate


class SHAKE256TestCase(unittest.TestCase):
    alg_id_4_pem_text = "MAsGCWCGSAFlAwQCDA=="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.alg_id_4_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_shake256
        assert not asn1Object['parameters'].isValue
        assert der_encode(asn1Object) == substrate


class SHAKE256LENTestCase(unittest.TestCase):
    alg_id_5_pem_text = "MA8GCWCGSAFlAwQCEgICAgA="

    def setUp(self):
        self.asn1Spec = rfc5280.AlgorithmIdentifier()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.alg_id_5_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_shake256_len
        assert asn1Object['parameters'].isValue
        assert der_encode(asn1Object) == substrate

        param, rest = der_decode(asn1Object['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[asn1Object['algorithm']])
        assert not rest
        assert param.prettyPrint()
        assert der_encode(param) == asn1Object['parameters']
        assert param == 512

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.alg_id_5_pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert asn1Object['algorithm'] == rfc8419.id_shake256_len
        assert asn1Object['parameters'] == 512
        assert der_encode(asn1Object) == substrate


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
