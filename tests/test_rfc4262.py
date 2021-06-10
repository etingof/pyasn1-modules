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
from pyasn1_alt_modules import rfc5480
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4262


class SMIMECapExtnTestCase(unittest.TestCase):
    pem_text = """\
MIIFPDCCBCSgAwIBAgIUC8V22Z7gvvK/kYZTdK4FIGv6H+wwDQYJKoZIhvcNAQEL
BQAwPzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlZBMRAwDgYDVQQHEwdIZXJuZG9u
MREwDwYDVQQKEwhCb2d1cyBDQTAeFw0yMTAxMTYyMjA4MTlaFw0yMjAxMTYyMjA4
MTlaME8xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJWQTEQMA4GA1UEBwwHSGVybmRv
bjEQMA4GA1UECgwHRXhhbXBsZTEPMA0GA1UEAwwGSXNhYmVsMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsX+fL6Im2hBNe86JHggN02FFPnKtpKqe3XmR
kCVoyEmfex4ljNUwDCEHpZIJ3ozusKZRpGkcBJ7m+6FxBBYqXmG/HAeCbgyRHWDT
Iw+Cvc1ZHcJs/Xy3/R06cVPx9KvJh85nNIFO4ydZY/U5gUdt+Tw6K7gJDWgisFHm
e6n1OuvyK5aAv5K7lIZQhfKxr9ZDyEBtLTMf9Ozdr5E5c1tansuPEXwxOaSa4CMc
TWZyC38lUCDmY3zRjdoXZ7tNKo6ol5PtmgqdxpdKMMCoOTOV6F1qfpUWnR68ZvBD
yGVwpFn1yJ4IEd3XTos6svSNoAJg1HlYv0PY6iMnaYTosw0ovwIDAQABo4ICHjCC
AhowHQYDVR0OBBYEFNMJbhHmGG1Nfm2BG5MT11vpGc7XMHoGA1UdIwRzMHGAFG8h
1hwqpWeNAfYpTYXw8VVg+pynoUOkQTA/MQswCQYDVQQGEwJVUzELMAkGA1UECBMC
VkExEDAOBgNVBAcTB0hlcm5kb24xETAPBgNVBAoTCEJvZ3VzIENBghRkeK3cclol
+9bjAtbPJYRhtuBruzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIF4DATBgNVHSUE
DDAKBggrBgEFBQcDBDAdBgNVHREEFjAUgRJpc2FiZWxAZXhhbXBsZS5jb20wNAYI
KwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5leGFtcGxlLmNv
bS8wQgYJYIZIAYb4QgENBDUWM1RoaXMgY2VydGlmaWNhdGUgY2Fubm90IGJlIHRy
dXN0ZWQgZm9yIGFueSBwdXJwb3NlLjCBswYJKoZIhvcNAQkPBIGlMIGiMA0GCWCG
SAFlAwQCAQUAMA0GCWCGSAFlAwQCAgUAMA0GCWCGSAFlAwQCAwUAMAsGCWCGSAFl
AwQBCTALBglghkgBZQMEAR0wCwYJYIZIAWUDBAExMAsGCWCGSAFlAwQBAjALBglg
hkgBZQMEARYwCwYJYIZIAWUDBAEqMAsGCWCGSAFlAwQBBTALBglghkgBZQMEARkw
CwYJYIZIAWUDBAEtMA0GCSqGSIb3DQEBCwUAA4IBAQA1HSKVIbdR6K2vhMIDxJFm
UpYtvUhYzX7NfxdfqikwyrSUZAKlsLEfxfrcew5XhRMVCptpA/lRmXbW7OfsxT4w
8RQTKcqa4hRe3LM2pQEa9x9GBog9CjezjWPedqW7REXT/jqMXkECPCiMGXryyqia
Te2hKpLjUj92gtZ89GTNmRnd50Gv8WgM3HKg4IqHBnXDNR1Wze6JoKVNsW+Cet3u
cMRTdrsqVIY4tgsw19WiO/vfyvWgtNeyjlbVfoqybnr3Gn8KHGe/oaHupAqyDs3J
Xr/lyFgYttd5n6E/AOW9cVjQojBhn6gYMzeciPTiEU9LLYKbTWO+qihZKmJYHxO1
"""

    def setUp(self):
        self.asn1Spec = rfc5280.Certificate()

    def testDerCodec(self):
        substrate = pem.readBase64fromText(self.pem_text)
        asn1Object, rest = der_decoder(substrate, asn1Spec=self.asn1Spec)

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, der_encoder(asn1Object))

        found = False
        for extn in asn1Object['tbsCertificate']['extensions']:
           if extn['extnID'] == rfc4262.smimeCapabilities:
               self.assertIn(extn['extnID'], rfc5280.certificateExtensionsMap)
               scap, rest = der_decoder(extn['extnValue'],
                   asn1Spec=rfc5280.certificateExtensionsMap[extn['extnID']])
               self.assertFalse(rest)
               self.assertTrue(scap.prettyPrint())
               self.assertEqual(extn['extnValue'], der_encoder(scap))

               for cap in scap:
                    if cap['capabilityID'] == rfc5480.id_sha256:
                        self.assertTrue(cap['parameters'].hasValue())
                        self.assertEqual(der_encoder(univ.Null("")),
                            cap['parameters'])
                        found = True

        self.assertTrue(found)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
