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
from pyasn1_modules import rfc6010

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class UnconstrainedCCCExtensionTestCase(unittest.TestCase):
    unconstrained_pem_text = "MB0GCCsGAQUFBwESBBEwDzANBgsqhkiG9w0BCRABAA=="

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.unconstrained_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['extnID'] == rfc6010.id_pe_cmsContentConstraints
        evalue, rest = der_decode(asn1Object['extnValue'],
            asn1Spec=rfc6010.CMSContentConstraints())
        assert not rest
        assert evalue.prettyPrint()
        assert der_encode(evalue) == asn1Object['extnValue']

        assert evalue[0]['contentType'] == rfc6010.id_ct_anyContentType


class ConstrainedCCCExtensionTestCase(unittest.TestCase):
    constrained_pem_text = """\
MIG7BggrBgEFBQcBEgSBrjCBqzA0BgsqhkiG9w0BCRABEDAlMCMGCyqGSIb3DQEJ
EAwBMRQMElZpZ2lsIFNlY3VyaXR5IExMQzAwBgpghkgBZQIBAk4CMCIwIAYLKoZI
hvcNAQkQDAsxEQwPa3RhLmV4YW1wbGUuY29tMDEGCyqGSIb3DQEJEAEZMCIwIAYL
KoZIhvcNAQkQDAsxEQwPa3RhLmV4YW1wbGUuY29tMA4GCSqGSIb3DQEHAQoBAQ==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Extension()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.constrained_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['extnID'] == rfc6010.id_pe_cmsContentConstraints
        evalue, rest = der_decode(asn1Object['extnValue'],
            asn1Spec=rfc6010.CMSContentConstraints())
        assert not rest
        assert evalue.prettyPrint()
        assert der_encode(evalue) == asn1Object['extnValue']

        constraint_count = 0
        attribute_count = 0
        cannot_count = 0
        for ccc in evalue:
            constraint_count += 1
            if ccc['canSource'] == 1:
                cannot_count += 1
            if ccc['attrConstraints'].hasValue():
                for attr in ccc['attrConstraints']:
                    attribute_count += 1
        assert constraint_count == 4
        assert attribute_count == 3
        assert cannot_count == 1

    def testExtensionsMap(self):
        substrate = pem.readBase64fromText(self.constrained_pem_text)
        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)
        assert asn1Object['extnID'] in rfc5280.certificateExtensionsMap.keys()


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
