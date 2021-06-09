#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2020-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5751
from pyasn1_alt_modules import rfc4490
from pyasn1_alt_modules import rfc4357
from pyasn1_alt_modules import rfc7836


class SMimeCapabilitiesTestCase(unittest.TestCase):
    pem_text = """\
MFwwCgYIKoUDBwEBBAEwCgYIKoUDBwEBBAIwIAYHKoUDAgINADAVBAgAAAAAAAAA
AAYJKoUDBwECBQEBMCAGByqFAwICDQEwFQQIAAAAAAAAAAAGCSqFAwcBAgUBAQ==
"""

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        kw_oid_list = (
            rfc4490.id_Gost28147_89_None_KeyWrap,
            rfc4490.id_Gost28147_89_CryptoPro_KeyWrap,
        )

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        for algid in asn1Object:
            if algid['capabilityID'] in kw_oid_list:
                kw_param, rest = der_decoder(algid['parameters'],
                    asn1Spec=rfc4357.Gost28147_89_Parameters())
                self.assertFalse(rest)
                self.assertTrue(kw_param.prettyPrint())
                self.assertEqual(algid['parameters'], der_encoder(kw_param))
                self.assertEqual(rfc7836.id_tc26_gost_28147_param_Z,
                    kw_param['encryptionParamSet'])
            count += 1

        self.assertEqual(4, count)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
