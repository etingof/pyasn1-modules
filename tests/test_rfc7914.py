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
from pyasn1_modules import rfc5958
from pyasn1_modules import rfc7914
from pyasn1_modules import rfc8018

try:
    import unittest2 as unittest

except ImportError:
    import unittest


# From RFC 7914, Section 13

class MultiprimeRSAPrivateKeyTestCase(unittest.TestCase):
    pem_text = """\
MIHiME0GCSqGSIb3DQEFDTBAMB8GCSsGAQQB2kcECzASBAVNb3VzZQIDEAAAAgEI
AgEBMB0GCWCGSAFlAwQBKgQQyYmguHMsOwzGMPoyObk/JgSBkJb47EWd5iAqJlyy
+ni5ftd6gZgOPaLQClL7mEZc2KQay0VhjZm/7MbBUNbqOAXNM6OGebXxVp6sHUAL
iBGY/Dls7B1TsWeGObE0sS1MXEpuREuloZjcsNVcNXWPlLdZtkSH6uwWzR0PyG/Z
+ZXfNodZtd/voKlvLOw5B3opGIFaLkbtLZQwMiGtl42AS89lZg==
"""

    def setUp(self):
        self.asn1Spec = rfc5958.EncryptedPrivateKeyInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        ea = asn1Object['encryptionAlgorithm']
        assert ea['algorithm'] == rfc8018.id_PBES2
        assert ea['algorithm'] in rfc5280.algorithmIdentifierMap.keys()

        params, rest = der_decode(ea['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[ea['algorithm']])
        assert not rest
        assert params.prettyPrint()
        assert der_encode(params) == ea['parameters']

        kdf = params['keyDerivationFunc']
        assert kdf['algorithm'] == rfc7914.id_scrypt
        assert kdf['algorithm'] in rfc5280.algorithmIdentifierMap.keys()

        kdfp, rest = der_decode(kdf['parameters'],
            asn1Spec=rfc5280.algorithmIdentifierMap[kdf['algorithm']])
        assert not rest
        assert kdfp.prettyPrint()
        assert der_encode(kdfp) == kdf['parameters']

        assert kdfp['costParameter'] == 1048576

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        ea = asn1Object['encryptionAlgorithm']
        assert ea['algorithm'] == rfc8018.id_PBES2

        params = asn1Object['encryptionAlgorithm']['parameters']
        assert params['keyDerivationFunc']['algorithm'] == rfc7914.id_scrypt

        kdfp = params['keyDerivationFunc']['parameters']
        assert kdfp['costParameter'] == 1048576


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
