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
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc7030

from pyasn1.type import univ

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class CSRAttrsTestCase(unittest.TestCase):
    pem_text = """\
MEEGCSqGSIb3DQEJBzASBgcqhkjOPQIBMQcGBSuBBAAiMBYGCSqGSIb3DQEJDjEJ
BgcrBgEBAQEWBggqhkjOPQQDAw==
"""

    the_oids = (univ.ObjectIdentifier('1.2.840.113549.1.9.7'),
                univ.ObjectIdentifier('1.2.840.10045.4.3.3'),
    )

    the_attrTypes = (univ.ObjectIdentifier('1.2.840.10045.2.1'),
                     univ.ObjectIdentifier('1.2.840.113549.1.9.14'),
    )

    the_attrVals = ('1.3.132.0.34',
                    '1.3.6.1.1.1.1.22',
    )


    def setUp(self):
        self.asn1Spec = rfc7030.CsrAttrs()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        for attr_or_oid in asn1Object:
            if attr_or_oid.getName() == 'oid':
                assert attr_or_oid['oid'] in self.the_oids

            if attr_or_oid.getName() == 'attribute':
                assert attr_or_oid['attribute']['attrType'] in self.the_attrTypes

    def testOpenTypes(self):
        openTypesMap = { }
        openTypesMap.update(rfc5652.cmsAttributesMap)
        for at in self.the_attrTypes:
            openTypesMap.update({ at: univ.ObjectIdentifier(), })

        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decode(substrate,
            asn1Spec=self.asn1Spec,
            openTypes=openTypesMap,
            decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        for attr_or_oid in asn1Object:
            if attr_or_oid.getName() == 'attribute':
                valString = attr_or_oid['attribute']['attrValues'][0].prettyPrint()
        
                if attr_or_oid['attribute']['attrType'] == self.the_attrTypes[0]:
                    assert valString == self.the_attrVals[0]
            
                if attr_or_oid['attribute']['attrType'] == self.the_attrTypes[1]:
                    assert valString == self.the_attrVals[1]


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
