#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc8018
from pyasn1_alt_modules import rfc9337


class PWRITestCase(unittest.TestCase):
    pem_text = """\
o4GQAgEAoEgGCSqGSIb3DQEFDDA7BCRzYWx0U0FMVHNhbHRTQUxUc2FsdFNBTFRz
YWx0U0FMVHNhbHQCAhAAAgFAMAwGCCqFAwcBAQQCBQAwHwYJKoUDBwEBBQIBMBIE
EFVLTUt1em55ZWNoaWtVS00EIBPiK5fM8IYJyZXfT/Q3bh/x9Vd1tEy2taP1MuvD
EVGT
"""

    def setUp(self):
        self.asn1Spec = rfc5652.RecipientInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        kdf_oid = asn1Object['pwri']['keyDerivationAlgorithm']['algorithm']
        enc_oid = asn1Object['pwri']['keyEncryptionAlgorithm']['algorithm']
        self.assertEqual(kdf_oid, rfc8018.id_PBKDF2)
        self.assertEqual(enc_oid,
            rfc9337.id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        kdfp = asn1Object['pwri']['keyDerivationAlgorithm']['parameters']
        self.assertEqual(4096, kdfp['iterationCount'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
