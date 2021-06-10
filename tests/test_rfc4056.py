#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc4056


class PSSSignedDataTestCase(unittest.TestCase):
    pem_text = """\
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
6lQ=
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)

        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            if layer == rfc5652.id_signedData:
                alg = asn1Object['signerInfos'][0]['signatureAlgorithm']

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        self.assertEqual(rfc4056.id_RSASSA_PSS, alg['algorithm'])
        param, rest = der_decoder(alg['parameters'],
            asn1Spec=rfc4056.RSASSA_PSS_params())
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(alg['parameters'], der_encoder(param))

        self.assertEqual(222, param['saltLength'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        alg = asn1Object['content']['signerInfos'][0]['signatureAlgorithm']
        self.assertEqual(rfc4056.id_RSASSA_PSS, alg['algorithm'])
        self.assertEqual(222, alg['parameters']['saltLength'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
