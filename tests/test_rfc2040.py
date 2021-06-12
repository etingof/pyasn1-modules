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
from pyasn1_alt_modules import rfc2040


class RC5EncryptedDataTestCase(unittest.TestCase):
    pem_text = """\
MEoGCSqGSIb3DQEHBqA9MDsCAQAwNgYJKoZIhvcNAQcBMB8GCCqGSIb3DQMIMBMC
ARACARACAUAECAECAwQFBgcIgAja1r2p3+j36A==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        self.assertEqual(rfc5652.id_encryptedData, asn1Object['contentType'])
        ed, rest = der_decoder(
            asn1Object['content'], asn1Spec=rfc5652.EncryptedData())
        self.assertFalse(rest)
        self.assertTrue(ed.prettyPrint())
        self.assertEqual(asn1Object['content'], der_encoder(ed))

        ai = ed['encryptedContentInfo']['contentEncryptionAlgorithm']
        self.assertEqual(rfc2040.rc5_CBC, ai['algorithm'])
        param, rest = der_decoder(
            ai['parameters'], asn1Spec=rfc2040.RC5_CBC_Parameters())
        self.assertFalse(rest)
        self.assertTrue(param.prettyPrint())
        self.assertEqual(ai['parameters'], der_encoder(param))

        self.assertEqual(16, param['rounds'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)

        eci = asn1Object['content']['encryptedContentInfo']
        ai = eci['contentEncryptionAlgorithm']
        self.assertEqual(rfc2040.rc5_CBC, ai['algorithm'])
        self.assertEqual(16, ai['parameters']['rounds'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
