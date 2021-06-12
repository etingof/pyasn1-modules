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

from pyasn1.type import univ

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc3217
from pyasn1_alt_modules import rfc5751


class WrapSMIMECapabilitiesTestCase(unittest.TestCase):
    pem_text = "MCMwDwYLKoZIhvcNAQkQAwYFADAQBgsqhkiG9w0BCRADBwIBOg=="

    def setUp(self):
        self.asn1Spec = rfc5751.SMIMECapabilities()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        wrap_alg_count = 0
        for cap in asn1Object:
            if cap['capabilityID'] in rfc5751.smimeCapabilityMap.keys():
                if cap['capabilityID'] == rfc3217.id_alg_CMS3DESwrap:
                    wrap_alg_count += 1
                if cap['capabilityID'] == rfc3217.id_alg_CMSRC2wrap:
                    wrap_alg_count += 1
                    asn1Spec = rfc5751.smimeCapabilityMap[cap['capabilityID']]
                    param, rest = der_decoder(cap['parameters'],
                        asn1Spec=asn1Spec)
                    self.assertFalse(rest)
                    self.assertTrue(param.prettyPrint())
                    self.assertEqual(cap['parameters'], der_encoder(param))

        self.assertEqual(2, wrap_alg_count)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(
            substrate, asn1Spec=self.asn1Spec, decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found_wrap_alg_param = False
        for cap in asn1Object:
            if cap['capabilityID'] == rfc3217.id_alg_CMSRC2wrap:
                self.assertEqual(58, cap['parameters'])
                found_wrap_alg_param = True

        self.assertTrue(found_wrap_alg_param)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())

