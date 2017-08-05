#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2017, Ilya Etingof <etingof@gmail.com>
# License: http://pyasn1.sf.net/license.html
#
import sys
from pyasn1.codec.der import decoder as der_decoder
from pyasn1.codec.der import encoder as der_encoder

from pyasn1_modules import rfc2560, pem

try:
    import unittest2 as unittest
except ImportError:
    import unittest


class OCSPRequestTestCase(unittest.TestCase):
    pem_text = """\
MGowaDBBMD8wPTAJBgUrDgMCGgUABBS3ZrMV9C5Dko03aH13cEZeppg3wgQUkqR1LKSevoFE63n8
isWVpesQdXMCBDXe9M+iIzAhMB8GCSsGAQUFBzABAgQSBBBjdJOiIW9EKJGELNNf/rdA
"""

    def setUp(self):
        self.asn1Spec = rfc2560.OCSPRequest()

    def testDerCodec(self):

        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decoder.decode(substrate, asn1Spec=self.asn1Spec)

        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encoder.encode(asn1Object) == substrate


class OCSPResponseTestCase(unittest.TestCase):
    pem_text = """\
MIIExAoBAKCCBL0wggS5BgkrBgEFBQcwAQEkggSqBIID6DCCBJ8wggEPoYGAMH4xCzAJBgNVBAYT
AkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBXaWRnaXRzIFB0eSBM
dGQxFTATBgNVBAMTDHNubXBsYWJzLmNvbTEgMB4GCSqGSIb3DQEJARYRaW5mb0Bzbm1wbGFicy5j
b20YDzIwMTIwNDExMTQwOTIyWjBUMFIwPTAJBgUrDgMCGgUABBS3ZrMV9C5Dko03aH13cEZeppg3
wgQUkqR1LKSevoFE63n8isWVpesQdXMCBDXe9M+CABgPMjAxMjA0MTExNDA5MjJaoSMwITAfBgkr
BgEFBQcwAQIEEgQQY3SToiFvRCiRhCzTX/63QDANBgkqhkiG9w0BAQUFAAOBgQA5O6EYgsuHsNbt
DedkC0RaVvrXW9DX5Fdl8rvhwoSok04WT6/WV2pSIJCdcNwQJ84WwdCV/86uz3/MhM/zq0OBhh+x
8g91YD5DLvieiNwNgJ/m1EKPfQJgm2ef7Uh7Q2EDELd4jW79X5NMrw5oe1HSrl1DUsiXR3oNu3TD
cuJPAKCCAvUwggLxMIIC7TCCAlagAwIBAgIBATANBgkqhkiG9w0BAQUFADB+MQswCQYDVQQGEwJB
VTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRk
MRUwEwYDVQQDEwxzbm1wbGFicy5jb20xIDAeBgkqhkiG9w0BCQEWEWluZm9Ac25tcGxhYnMuY29t
MB4XDTEyMDQxMTEzMjUzNVoXDTEzMDQxMTEzMjUzNVowfjELMAkGA1UEBhMCQVUxEzARBgNVBAgT
ClNvbWUtU3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEVMBMGA1UEAxMM
c25tcGxhYnMuY29tMSAwHgYJKoZIhvcNAQkBFhFpbmZvQHNubXBsYWJzLmNvbTCBnzANBgkqhkiG
9w0BAQEFAAOBjQAwgYkCgYEAww1ORzpzVfCNgqI8QfIpSFkR2ELmgI546xEzDqa6LgxxV58FqkKP
yN5tG12JqHK4fZA3n2/nIHO/niSrwLwaq6l0Z1N/A5kFP84cqQn7Rhnz/MY7gWdZ9t5Ud4aZTdcm
ANCdl0oAWgIOnvDrCn9b3F/BLNPaw6PJkKbeBts0eesCAwEAAaN7MHkwCQYDVR0TBAIwADAsBglg
hkgBhvhCAQ0EHxYdT3BlblNTTCBHZW5lcmF0ZWQgQ2VydGlmaWNhdGUwHQYDVR0OBBYEFPGLNnaS
RSzB5cmOew8EgbuATZpapxHGMB8GA1UdIwQYMBaAFPGLNnaSRSzB5cmOew+ATZpapxHGMA0GCSqG
SIb3DQEBBQUAA4GBAFkdLhSVZUCHeoVaVG4FxU6csLTYrTVxYmGJEUb++zHEiaiwmv3NcJ7i5qnB
XLkVCtKDevGSQz9hwwynvDAmfPrMfgheeHjPFQoDfbkPV8hO8fV61w3d1MPUSVWlkiHs5DSjXgRN
JQzNo1IwuBwBEnX+53m89cLagDlxNY1hf8vI
"""

    def setUp(self):
        self.asn1Spec = rfc2560.OCSPResponse()

    def testDerCodec(self):

        substrate = pem.readBase64fromText(self.pem_text)

        asn1Object, rest = der_decoder.decode(substrate, asn1Spec=self.asn1Spec)

        assert not rest
        assert asn1Object.prettyPrint()
        assert der_encoder.encode(asn1Object) == substrate


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
