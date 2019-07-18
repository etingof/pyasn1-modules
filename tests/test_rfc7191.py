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

from pyasn1.type import univ

from pyasn1_modules import pem
from pyasn1_modules import rfc5652
from pyasn1_modules import rfc7191

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class ReceiptRequestTestCase(unittest.TestCase):
    message1_pem_text = """\
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
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.message1_pem_text)
        asn1Object, rest = der_decode (substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        sd, rest = der_decode (asn1Object['content'], 
            asn1Spec=rfc5652.SignedData())

        for sa in sd['signerInfos'][0]['signedAttrs']:
            sat = sa['attrType']
            sav0 = sa['attrValues'][0]

            if sat == rfc7191.id_aa_KP_keyPkgIdAndReceiptReq:
                sav, rest = der_decode(sav0, 
                    asn1Spec=rfc7191.KeyPkgIdentifierAndReceiptReq())
                assert not rest
                assert sav.prettyPrint()
                assert der_encode(sav) == sav0
 
                package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
                package_id = pem.readBase64fromText(package_id_pem_text)
                assert sav['pkgID'] == package_id

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.message1_pem_text)
        rfc5652.cmsAttributesMap.update(rfc7191.cmsAttributesMapUpdate)
        asn1Object, rest = der_decode (substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        v3 = rfc5652.CMSVersion().subtype(value='v3')
        assert asn1Object['content']['version'] == v3

        for sa in asn1Object['content']['signerInfos'][0]['signedAttrs']:
            if sa['attrType'] == rfc7191.id_aa_KP_keyPkgIdAndReceiptReq:
                package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
                package_id = pem.readBase64fromText(package_id_pem_text)
                assert sa['attrValues'][0]['pkgID'] == package_id


class ReceiptTestCase(unittest.TestCase):
    message2_pem_text = """\
MIIEdAYJKoZIhvcNAQcCoIIEZTCCBGECAQMxDTALBglghkgBZQMEAgIwgawGCmCGSAFlAgEC
TgOggZ0EgZowgZcEFCe4nFY7FiJRnReHHHm/rIht3/g9MH8GCWCGSAFlAgEQAARyMHAxCzAJ
BgNVBAYTAlVTMQswCQYDVQQIEwJWQTEQMA4GA1UEBxMHSGVybmRvbjEQMA4GA1UEChMHRXhh
bXBsZTEOMAwGA1UEAxMFQWxpY2UxIDAeBgkqhkiG9w0BCQEWEWFsaWNlQGV4YW1wbGUuY29t
oIICfDCCAngwggH+oAMCAQICCQCls1QoG7BuOzAKBggqhkjOPQQDAzA/MQswCQYDVQQGEwJV
UzELMAkGA1UECAwCVkExEDAOBgNVBAcMB0hlcm5kb24xETAPBgNVBAoMCEJvZ3VzIENBMB4X
DTE5MDUyOTE0NDU0MVoXDTIwMDUyODE0NDU0MVowcDELMAkGA1UEBhMCVVMxCzAJBgNVBAgT
AlZBMRAwDgYDVQQHEwdIZXJuZG9uMRAwDgYDVQQKEwdFeGFtcGxlMQ4wDAYDVQQDEwVBbGlj
ZTEgMB4GCSqGSIb3DQEJARYRYWxpY2VAZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQA
IgNiAAT4zZ8HL+xEDpXWkoWp5xFMTz4u4Ae1nF6zXCYlmsEGD5vPu5hl9hDEjd1UHRgJIPoy
3fJcWWeZ8FHCirICtuMgFisNscG/aTwKyDYOFDuqz/C2jyEwqgWCRyxyohuJXtmjgZQwgZEw
CwYDVR0PBAQDAgeAMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBi
ZSB0cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wHQYDVR0OBBYEFMS6Wg4+euM8gbD0Aqpouxbg
lg41MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMAoGCCqGSM49BAMDA2gAMGUC
MGO5H9E1uAveRGGaf48lN4pov2yH+hCAc5hOAuZKe/f40MKSF8q4w2ij+0euSaKFiAIxAL3g
xp6sMitCmLQgOH6/RBIC/2syJ97y0KVp9da0PDAvwxLugCHTKZPjjpSLPHHc9TGCARwwggEY
AgEDgBTEuloOPnrjPIGw9AKqaLsW4JYONTALBglghkgBZQMEAgKgejAZBgkqhkiG9w0BCQMx
DAYKYIZIAWUCAQJOAzAcBgkqhkiG9w0BCQUxDxcNMTkwNjEzMTYxNjA4WjA/BgkqhkiG9w0B
CQQxMgQwQSWYpq4jwhMkmS0as0JL3gjYxKLgDfzP2ndTNsAY0m9p8Igp8ZcK4+5n9fXJ43vU
MAoGCCqGSM49BAMDBGgwZgIxAMfq2EJ5pSl9tGOEVJEgZitc266ljrOg5GDjkd2d089qw1A3
bUcOYuCdivgxVuhlAgIxAPR9JavxziwCbVyBUWOAiKKYfglTgG3AwNmrKDj0NtXUQ9qDmGAc
6L+EAY2P5OVB8Q==
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.message2_pem_text)
        asn1Object, rest = der_decode (substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        sd, rest = der_decode (asn1Object['content'],
            asn1Spec=rfc5652.SignedData())
        assert not rest
        assert sd.prettyPrint()
        assert der_encode(sd) == asn1Object['content']

        oid = sd['encapContentInfo']['eContentType']
        assert oid == rfc7191.id_ct_KP_keyPackageReceipt
        receipt, rest = der_decode(sd['encapContentInfo']['eContent'],
            asn1Spec=rfc7191.KeyPackageReceipt())
        assert not rest
        assert receipt.prettyPrint()
        assert der_encode(receipt) == sd['encapContentInfo']['eContent']

        package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
        package_id = pem.readBase64fromText(package_id_pem_text)
        assert receipt['receiptOf']['pkgID'] == package_id

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.message2_pem_text)
        rfc5652.cmsContentTypesMap.update(rfc7191.cmsContentTypesMapUpdate)
        rfc5652.cmsAttributesMap.update(rfc7191.cmsAttributesMapUpdate)
        asn1Object, rest = der_decode (substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        v3 = rfc5652.CMSVersion().subtype(value='v3')
        assert asn1Object['content']['version'] == v3

        for sa in asn1Object['content']['signerInfos'][0]['signedAttrs']:
            assert sa['attrType'] in rfc5652.cmsAttributesMap.keys()
            if sa['attrType'] == rfc5652.id_messageDigest:
                assert '0x412598a6ae2' in sa['attrValues'][0].prettyPrint()

        ct_oid = asn1Object['content']['encapContentInfo']['eContentType']
        assert ct_oid in rfc5652.cmsContentTypesMap
        assert ct_oid == rfc7191.id_ct_KP_keyPackageReceipt

        # Since receipt is inside an OCTET STRING, decodeOpenTypes=True cannot
        # automatically decode it
        sd_eci = asn1Object['content']['encapContentInfo']
        receipt, rest = der_decode(sd_eci['eContent'],
            asn1Spec=rfc5652.cmsContentTypesMap[sd_eci['eContentType']])
        package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
        package_id = pem.readBase64fromText(package_id_pem_text)
        assert receipt['receiptOf']['pkgID'] == package_id

class ErrorTestCase(unittest.TestCase):
    message3_pem_text = """\
MIIEbwYJKoZIhvcNAQcCoIIEYDCCBFwCAQMxDTALBglghkgBZQMEAgIwga0GCmCGSAFlAgEC
TgaggZ4EgZswgZigFgQUJ7icVjsWIlGdF4cceb+siG3f+D0wewYJYIZIAWUCARAABG4wbDEL
MAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQHEwdIZXJuZG9uMRAwDgYDVQQKEwdF
eGFtcGxlMQwwCgYDVQQDEwNCb2IxHjAcBgkqhkiG9w0BCQEWD2JvYkBleGFtcGxlLmNvbQoB
CqCCAncwggJzMIIB+qADAgECAgkApbNUKBuwbjwwCgYIKoZIzj0EAwMwPzELMAkGA1UEBhMC
VVMxCzAJBgNVBAgMAlZBMRAwDgYDVQQHDAdIZXJuZG9uMREwDwYDVQQKDAhCb2d1cyBDQTAe
Fw0xOTA1MjkxOTIwMTNaFw0yMDA1MjgxOTIwMTNaMGwxCzAJBgNVBAYTAlVTMQswCQYDVQQI
EwJWQTEQMA4GA1UEBxMHSGVybmRvbjEQMA4GA1UEChMHRXhhbXBsZTEMMAoGA1UEAxMDQm9i
MR4wHAYJKoZIhvcNAQkBFg9ib2JAZXhhbXBsZS5jb20wdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAQxpGJVLxa83xhyal+rvmMFs4xS6Q19cCDoAvQkkFe0gUC4glxlWWQuf/FvLCRwwscr877D
1FZRBrYKPD6Hxv/UKX6Aimou0TnnxsPk98zZpikn9gTrJn2cF9NCzvPVMfmjgZQwgZEwCwYD
VR0PBAQDAgeAMEIGCWCGSAGG+EIBDQQ1FjNUaGlzIGNlcnRpZmljYXRlIGNhbm5vdCBiZSB0
cnVzdGVkIGZvciBhbnkgcHVycG9zZS4wHQYDVR0OBBYEFMprZnLeLJtXf5iO4sMq02aOwhql
MB8GA1UdIwQYMBaAFPI12zQE2qVV8r1pA5mwYuziFQjBMAoGCCqGSM49BAMDA2cAMGQCMBVu
hLo58RhCiYsOLZFSR3vWHPDCJBnO1vE1uixqEjONHxlBoeGN2MmWs/9PppcHCwIwN9HB5jPc
J7gTjA9+ipCe+qkztmV+Gy2NBAY6xYC0gh+pb+X5OAI7y7HdctXp+PfrMYIBGzCCARcCAQOA
FMprZnLeLJtXf5iO4sMq02aOwhqlMAsGCWCGSAFlAwQCAqB6MBkGCSqGSIb3DQEJAzEMBgpg
hkgBZQIBAk4GMBwGCSqGSIb3DQEJBTEPFw0xOTA2MTMxNjE2MDhaMD8GCSqGSIb3DQEJBDEy
BDCgXFTUc3ZInjt+MWYkYmXYERk4FgErEZNILlWgVl7Z9pImgLObIpdrGqGPt06/VkwwCgYI
KoZIzj0EAwMEZzBlAjEAsjJ3iWRUteMKBVsjaYeN6TG9NITRTOpRVkSVq55DcnhwS9g9lu8D
iNF8uKtW/lk0AjA7z2q40N0lamXkSU7ECasiWOYV1X4cWGiQwMZDKknBPDqXqB6Es6p4J+qe
0V6+BtY=
"""

    def setUp(self):
        self.asn1Spec = rfc5652.ContentInfo()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.message3_pem_text)
        asn1Object, rest = der_decode (substrate, asn1Spec=self.asn1Spec)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        sd, rest = der_decode (asn1Object['content'],
            asn1Spec=rfc5652.SignedData())
        assert not rest
        assert sd.prettyPrint()
        assert der_encode(sd) == asn1Object['content']

        oid = sd['encapContentInfo']['eContentType']
        assert oid == rfc7191.id_ct_KP_keyPackageError
        kpe, rest = der_decode(sd['encapContentInfo']['eContent'],
            asn1Spec=rfc7191.KeyPackageError())
        assert not rest
        assert kpe.prettyPrint()
        assert der_encode(kpe) == sd['encapContentInfo']['eContent']

        package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
        package_id = pem.readBase64fromText(package_id_pem_text)
        assert kpe['errorOf']['pkgID'] == package_id
        assert kpe['errorCode'] == rfc7191.EnumeratedErrorCode(value=10)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.message3_pem_text)
        rfc5652.cmsContentTypesMap.update(rfc7191.cmsContentTypesMapUpdate)
        rfc5652.cmsAttributesMap.update(rfc7191.cmsAttributesMapUpdate)
        asn1Object, rest = der_decode (substrate,
                                       asn1Spec=self.asn1Spec,
                                       decodeOpenTypes=True)
        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encode(asn1Object) == substrate

        assert asn1Object['contentType'] == rfc5652.id_signedData
        v3 = rfc5652.CMSVersion().subtype(value='v3')
        assert asn1Object['content']['version'] == v3

        for sa in asn1Object['content']['signerInfos'][0]['signedAttrs']:
            assert sa['attrType'] in rfc5652.cmsAttributesMap.keys()
            if sa['attrType'] == rfc5652.id_messageDigest:
                assert '0xa05c54d4737' in sa['attrValues'][0].prettyPrint()

        ct_oid = asn1Object['content']['encapContentInfo']['eContentType']
        assert ct_oid in rfc5652.cmsContentTypesMap.keys()
        assert ct_oid == rfc7191.id_ct_KP_keyPackageError

        # Since receipt is inside an OCTET STRING, decodeOpenTypes=True cannot
        # automatically decode it
        sd_eci = asn1Object['content']['encapContentInfo']
        kpe, rest = der_decode(sd_eci['eContent'],
            asn1Spec=rfc5652.cmsContentTypesMap[sd_eci['eContentType']])
        package_id_pem_text = "J7icVjsWIlGdF4cceb+siG3f+D0="
        package_id = pem.readBase64fromText(package_id_pem_text)
        assert kpe['errorOf']['pkgID'] == package_id
        assert kpe['errorCode'] == rfc7191.EnumeratedErrorCode(value=10)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
