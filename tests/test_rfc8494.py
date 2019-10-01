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
from pyasn1_modules import rfc8494

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class CompresssedDataTestCase(unittest.TestCase):
    pem_text = """\
MIIBNqADAgEAMIIBLaADAgEZoIIBJASCASB4nG2P0U7CQBBF3/cr5l2K3YpSF5YA
bYmbWArtQsJjKVuogd1mO0T8e0ti1IjJZB4md07OHZbWnMbqkp/qo+oW5jSCWDqL
VCSpkBveg2kSbrg/FTIWcQRpJPlLmGYQzdci5MvlA+3Rx2cyREO/KVrhCOaJFLMN
n03E6yqNIEmDheS2LHzPG0zNdqw0dn89XAnev4RsFQRRlnW+SITMWmMGf72JNAyk
oXCj0mnPHtzwSZijYuD1YVJb8FzaB/rE2n3nUtcl2Xn7pgpkkAOqBsm1vrNWtqmM
ZkC7LgmMxraFgx91y0F1wfv6mFd6AMUht41CfsbS8X9yNtdNqayjdGF2ld4z8LcV
EiIPVQPtvBuLBxjW5qx3TbXXo6vHJ1OhhLY=

"""

    def setUp(self):
        self.asn1Spec = rfc8494.CompressedData()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['compressionAlgorithm']['algorithmID-ShortForm'] == 0
        cci = asn1Object['compressedContentInfo']
        assert cci['unnamed']['contentType-ShortForm'] == 25
        assert cci['compressedContent'].prettyPrint()[:12] == '0x789c6d8fd1'


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
