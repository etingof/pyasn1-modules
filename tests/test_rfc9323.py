#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1.codec.der.encoder import encode as der_encoder
from pyasn1.type import univ
from pyasn1.type import error

from pyasn1_alt_modules import pem
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc9323

class BadFileNameTestCase(unittest.TestCase):
    def testRaisesValueConstraintError(self):
        self.assertRaises(
            error.ValueConstraintError,
            rfc9323.PortableFilename, 'abc+'
        )

class RPKISignedChecklistTestCase(unittest.TestCase):
    pem_text = """\
MIIGjwYJKoZIhvcNAQcCoIIGgDCCBnwCAQMxDTALBglghkgBZQMEAgEwgZYGCyqG
SIb3DQEJEAEwoIGGBIGDMIGAMBWhEzARMA8EAgACMAkDBwAgAQZ8IIwwCwYJYIZI
AWUDBAIBMFowNBYQYjQyX2lwdjZfbG9hLnBuZwQglRbdZL58FyW5/KEXEg5Y6NhC
pSBoczmbPd/8kcS2rPAwIgQgCuE5RyIAXNkvTGqgJNXWs+LmfWKfEXINlHimM6EX
ocegggQfMIIEGzCCAwOgAwIBAgIBATANBgkqhkiG9w0BAQsFADAzMTEwLwYDVQQD
EygzOGUxNGY5MmZkYzdjY2ZiZmMxODIzNjE1MjNhZTI3ZDY5N2U5NTJmMB4XDTIy
MDUyNzE5NDUwMloXDTIzMDUyNzE5NDUwMlowDTELMAkGA1UEAwwCRUUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDk9EeZ+bni2y4wJlIbmP2YH+uVw5OP
ewTHQn93Zi4d6N+BUQxGYzJhGI7ZsarnK2iuYxs6E+bUtPXPYJzDx8NzGhfzOITt
GoJlim5isKIBBlPi37IY75swenSQOoPeY6VOLl3elNuUoIdL+S1jI9BksQSXX6LG
6YJCxxTDGg/27F+dDN9DKCAVB8ZxXG9hnOTzv8BCD/D0YU/irAuIZVj5xH3xjM/J
gOqzmxygsuJUGIcy5JcUhhYVQ5Kqx2FBpaaSklo/Rg9sDzbMsOIhwb6Ylk6W4d1j
3zMyORTdg9eL1KXBN8yfstjC0s81y3nbSgWPiWuprHnXPI+bmZi2j+7jAgMBAAGj
ggFeMIIBWjAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFKDCf75nJYStTKGtU/BK
BYMEgonnMB8GA1UdIwQYMBaAFDjhT5L9x8z7/BgjYVI64n1pfpUvMBgGA1UdIAEB
/wQOMAwwCgYIKwYBBQUHDgIwIgYIKwYBBQUHAQcBAf8EEzARMA8EAgACMAkDBwAg
AQZ8IIwwZAYIKwYBBQUHAQEEWDBWMFQGCCsGAQUFBzAChkhyc3luYzovL3Jwa2ku
cmlwZS5uZXQvcmVwb3NpdG9yeS9ERUZBVUxUL09PRlBrdjNIelB2OEdDTmhVanJp
ZldsLWxTOC5jZXIwZAYDVR0fBF0wWzBZoFegVYZTcnN5bmM6Ly9jaGxvZS5zb2Jv
cm5vc3QubmV0L3Jwa2kvUklQRS1ubGpvYnNuaWpkZXJzL09PRlBrdjNIelB2OEdD
TmhVanJpZldsLWxTOC5jcmwwDQYJKoZIhvcNAQELBQADggEBAJoDJvJxThQol9gB
n3MswmFk3LigqG3Sv2HeKRmyeEq8hPHudPo0MbHAbgps+lQPUi8RQaKyY69qW1lR
Mqej5eDOV164Yo7nRL9tSuBC1ne0kegApYNcq8nRZbH76Kb3TxgXVsG/D9o11AJF
6M32lSNlO+tbC7MMDhO0xNXjLpjXDmOpohg0wy3DZ+nbtIlK4UuWgKunz/iv36X6
uFakeVhtQLnFTncXdTvhRD+r8NwQqY34yW+q2ZFI4paNQPC8emXWIpqgVorISYmw
AusVcCpICedJrUsY+Drcc3o9Ib4zyvN4ldWe/T/oUtjA5ZIZoejjIIiBSVbnaGmz
eSkT31wxggGqMIIBpgIBA4AUoMJ/vmclhK1Moa1T8EoFgwSCiecwCwYJYIZIAWUD
BAIBoGswGgYJKoZIhvcNAQkDMQ0GCyqGSIb3DQEJEAEwMBwGCSqGSIb3DQEJBTEP
Fw0yMjA1MjcxOTQ1MzRaMC8GCSqGSIb3DQEJBDEiBCBErCuXeuq17Q+2ZRHu0qxP
onZIDG1nQIenPR762BFoDTANBgkqhkiG9w0BAQEFAASCAQDa9VOFllioS7jYxDxW
BbmTeVqWptuU71lBXD/Kggzb3JHhrqHFmzPYIJbJqKo5vu6g3BjT93xGO6zqB2eN
nXPsNKU7krThjCkjhg/8vmzEBEG7+iFdKcY5XrDqhhGY9y8TGQJgq00bCBAwbmMS
giDYfsT7hev6SUAvoC+x8fmT40rTMpc8bkR5mITpqaaRigxhUij2W/aYS+u9/cwH
l/Q7/nCdUBJe+x2ubsbHcGRSQ7EO1cXT1jiToYlfV+VHRUFtl+ud6nVgJ/Nln9Ob
pLpXzrBiy+/+b5KX87CXkMsjHKRYW92mMnXkC1GKj55YL8Eb6Zi3o81X5fHBmhqv
lj/4
"""

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        
        layers = { }
        layers.update(rfc5652.cmsContentTypesMap)
        self.assertIn(rfc9323.id_ct_signedChecklist, layers)

        getNextLayer = {
            rfc5652.id_ct_contentInfo: lambda x: x['contentType'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContentType'],
        }

        getNextSubstrate = {
            rfc5652.id_ct_contentInfo: lambda x: x['content'],
            rfc5652.id_signedData: lambda x: x['encapContentInfo']['eContent'],
        }

        layer = rfc5652.id_ct_contentInfo
        while layer in getNextLayer:
            asn1Object, rest = der_decoder(substrate, asn1Spec=layers[layer])
            self.assertFalse(rest)
            self.assertTrue(asn1Object.prettyPrint())
            self.assertEqual(substrate, der_encoder(asn1Object))

            substrate = getNextSubstrate[layer](asn1Object)
            layer = getNextLayer[layer](asn1Object)

        self.assertEqual(rfc9323.id_ct_signedChecklist, layer)

        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc9323.RpkiSignedChecklist())
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        filenames = [ ]
        for fnah in asn1Object['checkList']:
            count += 1
            if fnah['fileName'].hasValue():
                filenames.append(fnah['fileName'])

        self.assertEqual(2, count)
        self.assertIn('b42_ipv6_loa.png', filenames)

    def testOpenTypes(self):
        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc5652.ContentInfo(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        substrate = asn1Object['content']['encapContentInfo']['eContent']
        asn1Object, rest = der_decoder(substrate,
            asn1Spec=rfc9323.RpkiSignedChecklist(), decodeOpenTypes=True)
        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        count = 0
        filenames = [ ]
        for fnah in asn1Object['checkList']:
            count += 1
            if fnah['fileName'].hasValue():
                filenames.append(fnah['fileName'])

        self.assertEqual(2, count)
        self.assertIn('b42_ipv6_loa.png', filenames)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
