#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2019, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
import sys

from pyasn1.codec.der.decoder import decode as der_decode
from pyasn1.codec.der.encoder import encode as der_encode

from pyasn1.type import univ

from pyasn1_modules import pem
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc4108

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class CMSFirmwareWrapperTestCase(unittest.TestCase):
    pem_text = """\
MIIEdwYJKoZIhvcNAQcCoIIEaDCCBGQCAQExDTALBglghkgBZQMEAgEwggIVBgsq
hkiG9w0BCRABEKCCAgQEggIA3ntqPr5kDpx+//pgWGfHCH/Ht4pbenGwXv80txyE
Y0I2mT9BUGz8ILkbhD7Xz89pBS5KhEJpthxH8WREJtvS+wL4BqYLt23wjWoZy5Gt
5dPzWgaNlV/aQ5AdfAY9ljmnNYnK8D8r8ur7bQM4cKUdxry+QA0nqXHMAOSpx4Um
8impCc0BICXaFfL3zBrNxyPubbFO9ofbYOAWaNmmIAhzthXf12vDrLostIqmYrP4
LMRCjTr4LeYaVrAWfKtbUbByN6IuBef3Qt5cJaChr74udz3JvbYFsUvCpl64kpRq
g2CT6R+xE4trO/pViJlI15dvJVz04BBYQ2jQsutJwChi97/DDcjIv03VBmrwRE0k
RJNFP9vpDM8CxJIqcobC5Kuv8b0GqGfGl6ouuQKEVMfBcrupgjk3oc3KL1iVdSr1
+74amb1vDtTMWNm6vWRqh+Kk17NGEi2mNvYkkZUTIHNGH7OgiDclFU8dSMZd1fun
/D9dmiFiErDB3Fzr4+8Qz0aKedNE/1uvM+dhu9qjuRdkDzZ4S7txTfk6y9pG9iyk
aEeTV2kElKXblgi+Cf0Ut4f5he8rt6jveHdMo9X36YiUQVvevj2cgN7lFivEnFYV
QY0xugpP7lvEFDfsi2+0ozgP8EKOLYaCUKpuvttlYJ+vdtUFEijizEZ4cx02RsXm
EesxggI1MIICMQIBA4AUnutnybladNRNLxY5ZoDoAbXLpJwwCwYJYIZIAWUDBAIB
oHgwGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEQMCkGCyqGSIb3DQEJEAIkMRoG
CysGAQQBjb9BAQEqBgsrBgEEAY2/QQEBMDAvBgkqhkiG9w0BCQQxIgQgAJfvuasB
4P6WDLOkOyvj33YPgZW4olHbidzyh1EKP9YwCwYJKoZIhvcNAQELBIIBgDn0y+4B
cCX7ICovWcyWf0IxNXx7+1VlYneAZ8pMBaKu+6q7jRFZ+QsQFFbQ1yPO/3Pr2wVb
UJSJAL4QCJDurJ42LdPQIOGIV2aWq70vl6B9yt6svEdjxJ3XkopwcCBXLcB1Hp9b
6wYZzSFCujOlsABJiz2gMD6wUT4lq7RJO31LEPxx/Va4Ftp1F4okmgL8VpMemihU
atRXpIhedfli+TWEtMmoxcX3paLcU7MmJFUAwkHmb8rSRF5VBy5QWcNgzzskof0W
mCR/8bZjqR/g3VlFPyz7zOCxG/wIdZVAb4O/QP8fC0GhyHNE+NX6d+GI8RPpRyMf
5RfCCsHwbApCv8+tpFslYzwvUTIFx0y9zVrnkz/UrDjZtrKxLC0oRJlnlnKR1unm
lbolB9c2p60/mZHwQhLM5CjeYcMX3mMVJo4jqag+8o48CibW50h8y21usKaeA9b0
9EMxfG3KaaP5mMEOZMpeGdUKQSJYweDstxlrY5ajPbeOycdMv7tRNoLpyw==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decode(substrate, asn1Spec=self.asn1Spec)

        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        inner, rest = der_decode(asn1Object['content'], asn1Spec=rfc5652.SignedData())

        assert inner['encapContentInfo']['eContentType'] == rfc4108.id_ct_firmwarePackage
        assert inner['encapContentInfo']['eContent']

        found_target_hardware_identifier_attribute = False
        for attr in inner['signerInfos'][0]['signedAttrs']:
            if attr['attrType'] == rfc4108.id_aa_targetHardwareIDs:
                found_target_hardware_identifier_attribute = True
        assert found_target_hardware_identifier_attribute


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
