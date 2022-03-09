#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4357
from pyasn1_alt_modules import rfc9215

from pyasn1_alt_modules import opentypemap


class GostR34102001256CertificateTestCase(unittest.TestCase):
    gostR3410_2001_256_pem_text = """\
MIIBLTCB26ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwZjAfBggqhQMHAQEBATATBgcqhQMCAiMABggqhQMHAQECAgNDAARAC9hv
5djbiWaPeJtOHbqFhcVQi0XsW1nYkG3bcOJJK3/ad/+HGhD73ydm0pPF0WSvuzx7
lzpByIXRHXDWibTxJqMTMBEwDwYDVR0TAQH/BAUwAwEB/zAKBggqhQMHAQEDAgNB
AE1T8BL+CBd2UH1Nm7gfAO/bTu/Uq4O6xLrPc1Fzz6gcQaoo0vGrFIKAzZ7Vb+2k
GXQFNVSkJ2e4OtBD/TncBJM=
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.gostR3410_2001_256_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))
        
        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_256, spki_a['algorithm'])

        spki_a_p, rest = der_decoder(spki_a['parameters'],
            asn1Spec=rfc9215.GostR3410_2012_PublicKeyParameters())
        self.assertFalse(rest)
        self.assertTrue(spki_a_p.prettyPrint())
        self.assertEqual(spki_a['parameters'], der_encoder(spki_a_p))
        
        self.assertEqual(rfc4357.id_GostR3410_2001_TestParamSet,
            spki_a_p['publicKeyParamSet'])
        self.assertEqual(rfc9215.id_tc26_gost3411_12_256,
            spki_a_p['digestParamSet'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.gostR3410_2001_256_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec,
            openTypes=opentypemap.get('algorithmIdentifierMap'),
            decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_256, spki_a['algorithm'])
        spki_a_p = spki_a['parameters']
        self.assertEqual(rfc4357.id_GostR3410_2001_TestParamSet,
            spki_a_p['publicKeyParamSet'])
        self.assertEqual(rfc9215.id_tc26_gost3411_12_256,
            spki_a_p['digestParamSet'])

class GostR34102012256CertificateTestCase(unittest.TestCase):
    gostR3410_2012_256_pem_text = """\
MIIBJTCB06ADAgECAgEKMAoGCCqFAwcBAQMCMBIxEDAOBgNVBAMTB0V4YW1wbGUw
IBcNMDEwMTAxMDAwMDAwWhgPMjA1MDEyMzEwMDAwMDBaMBIxEDAOBgNVBAMTB0V4
YW1wbGUwXjAXBggqhQMHAQEBATALBgkqhQMHAQIBAQEDQwAEQHQnldS+6ITd8oUP
7APqP68YROAdnaYLZFCTpV4m38OZePWWz01NDGzx0YlD2UST0WuewKFtUS0uEnzE
aRpjGOKjEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoUDBwEBAwIDQQAUC02pEksJ
yw1c6Sjuh0JzoxASlJLsDik2njt5EkhXjB0OHaW+NHxvG1JWx66sIArWSsd6b1s6
DglzGOeubudp
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.gostR3410_2012_256_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_256, spki_a['algorithm'])

        spki_a_p, rest = der_decoder(spki_a['parameters'],
            asn1Spec=rfc9215.GostR3410_2012_PublicKeyParameters())
        self.assertFalse(rest)
        self.assertTrue(spki_a_p.prettyPrint())
        self.assertEqual(spki_a['parameters'], der_encoder(spki_a_p))
        
        self.assertEqual(rfc9215.id_tc26_gost_3410_2012_256_paramSetA,
            spki_a_p['publicKeyParamSet'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.gostR3410_2012_256_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec,
            openTypes=opentypemap.get('algorithmIdentifierMap'),
            decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_256, spki_a['algorithm'])
        spki_a_p = spki_a['parameters']
        self.assertEqual(rfc9215.id_tc26_gost_3410_2012_256_paramSetA,
            spki_a_p['publicKeyParamSet'])

class GostR34102012512CertificateTestCase(unittest.TestCase):
    gostR3410_2012_512_pem_text = """\
MIIBqjCCARagAwIBAgIBCzAKBggqhQMHAQEDAzASMRAwDgYDVQQDEwdFeGFtcGxl
MCAXDTAxMDEwMTAwMDAwMFoYDzIwNTAxMjMxMDAwMDAwWjASMRAwDgYDVQQDEwdF
eGFtcGxlMIGgMBcGCCqFAwcBAQECMAsGCSqFAwcBAgECAAOBhAAEgYDh7zDVLGEz
3dmdHVxBRVz3302LTJJbvGmvFDPRVlhRWt0hRoUMMlxbgcEzvmVaqMTUQOe5io1Z
SHsMdpa8xV0R7L53NqnsNX/y/TmTH04RTLjNo1knCsfw5/9D2UGUGeph/Sq3f12f
Y1I9O1CgT2PioM9Rt8E63CFWDwvUDMnHN6MTMBEwDwYDVR0TAQH/BAUwAwEB/zAK
BggqhQMHAQEDAwOBgQBBVwPYkvGl8/aMQ1MYmn7iB7gLVjHvnUlSmk1rVCws+hWq
LqzxH0cP3n2VSFaQPDX9j5Ve8wDZXHdTSnJKDu5wL4b6YKCBCRoj3XleHjxonuUS
o8gu4NzCZDx47qj8rNNUklWEhrIPHJ7Bl8kGmYUCYMk7y82cXDMX4ZNE4XOuNg==
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.gostR3410_2012_512_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_512, spki_a['algorithm'])

        spki_a_p, rest = der_decoder(spki_a['parameters'],
            asn1Spec=rfc9215.GostR3410_2012_PublicKeyParameters())
        self.assertFalse(rest)
        self.assertTrue(spki_a_p.prettyPrint())
        self.assertEqual(spki_a['parameters'], der_encoder(spki_a_p))
        
        self.assertEqual(rfc9215.id_tc26_gost_3410_2012_512_paramSetTest,
            spki_a_p['publicKeyParamSet'])

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.gostR3410_2012_512_pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec,
            openTypes=opentypemap.get('algorithmIdentifierMap'),
            decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        spki_a = asn1Object['tbsCertificate']['subjectPublicKeyInfo']['algorithm']
        self.assertEqual(rfc9215.id_tc26_gost3410_2012_512, spki_a['algorithm'])
        spki_a_p = spki_a['parameters']
        self.assertEqual(rfc9215.id_tc26_gost_3410_2012_512_paramSetTest,
            spki_a_p['publicKeyParamSet'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
