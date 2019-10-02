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
from pyasn1_modules import rfc5280
from pyasn1_modules import rfc8398

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class EAITestCase(unittest.TestCase):
    pem_text = "oCAGCCsGAQUFBwgJoBQMEuiAgeW4q0BleGFtcGxlLmNvbQ=="

    def setUp(self):
        self.asn1Spec = rfc5280.GeneralName()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['otherName']['type-id'] in rfc5280.anotherNameMap.keys()
        assert asn1Object['otherName']['type-id'] == rfc8398.id_on_SmtpUTF8Mailbox

        eai, rest = der_decode(asn1Object['otherName']['value'],
            asn1Spec=rfc5280.anotherNameMap[asn1Object['otherName']['type-id']])
        assert not rest
        assert eai.prettyPrint()
        assert der_encode(eai) == asn1Object['otherName']['value']

        assert eai[0] == u'\u8001'
        assert eai[1] == u'\u5E2B'

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['otherName']['type-id'] == rfc8398.id_on_SmtpUTF8Mailbox
        assert asn1Object['otherName']['value'][0] == u'\u8001'
        assert asn1Object['otherName']['value'][1] ==  u'\u5E2B'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
