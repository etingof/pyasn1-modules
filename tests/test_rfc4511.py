#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2021, Hisanobu Okuda <hisanobu.okuda@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import sys
import unittest
import base64

from pyasn1.codec.ber.decoder import decode as ber_decoder
from pyasn1.codec.ber.encoder import encode as ber_encoder

from pyasn1_modules import pem
from pyasn1_modules import rfc4511


class LDAPTestCaseBase():
    b64_text = None

    def testBerCodec(self):
        assert(self.__class__.b64_text is not None)
        substrate = pem.readBase64fromText(self.__class__.b64_text)

        asn1Object, rest = ber_decoder(
            substrate,
            asn1Spec=rfc4511.LDAPMessage()
        )

        self.assertFalse(rest)
        self.assertTrue(asn1Object.prettyPrint())
        self.assertEqual(substrate, ber_encoder(asn1Object))

    def testProtocolOpType(self):
        assert(self.b64_text is not None)
        substrate = pem.readBase64fromText(self.b64_text)

        asn1Object, rest = ber_decoder(
            substrate,
            asn1Spec=rfc4511.LDAPMessage()
        )

        protocolOp = next(asn1Object['protocolOp'].values())

        self.assertTrue(
            isinstance(protocolOp, self.__class__.expected_protocolop_class)
        )


class BindRequestSimpleTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MC8CAQFgKgIBAwQaQWRtaW5pc3RyYXRvckBFWEFNUExFMi5DT02ACVBhc3N3MHJkLg==
"""

    expected_protocolop_class = rfc4511.BindRequest


class BindRequestSaslTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MIIBOgIBAmCCATMCAQMEAKOCASoECkRJR0VTVC1NRDUEggEadXNlcm5hbWU9ImNuPURpcmVj
dG9yeSBNYW5hZ2VyIixyZWFsbT0iNzA3NjU3ZTQyZTUxIixub25jZT0iZUYrTEpIYWF2ak1k
Vk1vb2YvSkphaEY1R3N2WWxCeDJrYTVJOWtaZFg0bz0iLGNub25jZT0iRUo2R0FETm1ITGR6
RzBmMit6cFB5QkJzVEFuQm9SVXNCOE1jbGMwM1M5QT0iLG5jPTAwMDAwMDAxLHFvcD1hdXRo
LWNvbmYsY2lwaGVyPXJjNCxtYXhidWY9MTY3NzcyMTUsZGlnZXN0LXVyaT0ibGRhcC9sb2Nh
bGhvc3QiLHJlc3BvbnNlPTQ4OGE5YjUzMDE1YjE0MWUwMGI2MjUwOTZiODA2MjY0
"""

    expected_protocolop_class = rfc4511.BindRequest


class BindResponseSuccessTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAwCAQFhBwoBAAQABAA=
"""

    expected_protocolop_class = rfc4511.BindResponse


class BindResponseSaslBindInProgressTestCase(
        unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MIHLAgEBYYHFCgEOBAAEAIeBu25vbmNlPSJlRitMSkhhYXZqTWRWTW9vZi9KSmFoRjVHc3ZZ
bEJ4MmthNUk5a1pkWDRvPSIscmVhbG09IjcwNzY1N2U0MmU1MSIscW9wPSJhdXRoLGF1dGgt
aW50LGF1dGgtY29uZiIsY2lwaGVyPSJyYzQtNDAscmM0LTU2LHJjNCxkZXMsM2RlcyIsbWF4
YnVmPTIwOTcxNTIsY2hhcnNldD11dGYtOCxhbGdvcml0aG09bWQ1LXNlc3M=
"""

    expected_protocolop_class = rfc4511.BindResponse


class UnbindRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAUCAQNCAA==
"""

    expected_protocolop_class = rfc4511.UnbindRequest


class SearchRequestComplicatedFilterTestCase(
        unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MIIBeQIBA2OCAXIEEGRjPXJlZGhhdCxkYz1jb20KAQIKAQMCAQACAQABAQCggc2HA3VpZKGB
xaIToxEEA3VpZAQKbm9zdWNodXNlcqksgRsyLjE2Ljg0MC4xLjExMzczMC4zLjMuMi43LjGC
AnNugwZwYXNzaW6EAQGlIgQPY3JlYXRlVGltZXN0YW1wBA8yMDA3MDEwMTAwMDAwMFqmIgQP
Y3JlYXRlVGltZXN0YW1wBA8yMTAwMDEwMTAwMDAwMFqkCQQCY24wA4ABdaQJBAJjbjADggF1
pAkEAmNuMAOBAXWkDAQCY24wBoABdYEBc6gJBAJjbgQDc2VyMH8EB2VudHJ5ZG4EA3VpZAQL
b2JqZWN0Q2xhc3MECWdpdmVuTmFtZQQCc24ECG1lbWJlck9mBAV0aXRsZQQPY3JlYXRldGlt
ZXN0YW1wBAl1aWROdW1iZXIEAmNuBA5zYW1hY2NvdW50bmFtZQQGbWVtYmVyBApwd2RMYXN0
U2V0
"""

    expected_protocolop_class = rfc4511.SearchRequest


class SearchRequestSimpleFilterTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MC0CAQJjKAQQZGM9cmVkaGF0LGRjPWNvbQoBAgoBAAIBAAIBAAEBAIcDdWlkMAA=
"""

    expected_protocolop_class = rfc4511.SearchRequest


class SearchRequestWithControlTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MEACAQJjOwQQZGM9cmVkaGF0LGRjPWNvbQoBAgoBAAIBAAIBAAEBAIcDdWlkMBMEAmRuBAN1
aWQEAmNuBARtYWls
"""

    expected_protocolop_class = rfc4511.SearchRequest


class SearchResultEntryTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MFkCAQJkVAQpdWlkPWRlbW9fdXNlcixvdT1wZW9wbGUsZGM9ZXhhbXBsZSxkYz1jb20wJzAS
BAN1aWQxCwQJZGVtb191c2VyMBEEAmNuMQsECURlbW8gVXNlcg==
"""

    expected_protocolop_class = rfc4511.SearchResultEntry


class SearchResultDoneTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAwCAQJlBwoBAAQABAA=
"""

    expected_protocolop_class = rfc4511.SearchResultDone


class SearchResultReferenceTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MEECAQJzPAQ6bGRhcDovL2xkYXAyLmV4YW1wbGUuY29tL289Z3JvbW1ldHMsZGM9ZXhhbXBs
ZSxkYz1uZXQ/P3N1Yg==
"""

    expected_protocolop_class = rfc4511.SearchResultReference


class ModifyRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MEoCAQZmRQQnY249dGVtcHVzZXIsb3U9cGVvcGxlLGRjPWV4YW1wbGUsZGM9Y29tMBowGAoB
AjATBAJzbjENBAtzdl9yZXBsYWNlZA==
"""

    expected_protocolop_class = rfc4511.ModifyRequest


class ModifyResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MEwCAQdnRwoBQQQABEBtaXNzaW5nIGF0dHJpYnV0ZSAic24iIHJlcXVpcmVkIGJ5IG9iamVj
dCBjbGFzcyAiaW5ldE9yZ1BlcnNvbiIK
"""

    expected_protocolop_class = rfc4511.ModifyResponse


class AddRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MIGIAgECaIGCBCdjbj10ZW1wdXNlcixvdT1wZW9wbGUsZGM9ZXhhbXBsZSxkYz1jb20wVzAe
BAtvYmplY3RDbGFzczEPBA1pbmV0T3JnUGVyc29uMBEEA3VpZDEKBAh0ZW1wdXNlcjAQBAJz
bjEKBAh0ZW1wdXNlcjAQBAJjbjEKBAh0ZW1wdXNlcg==
"""

    expected_protocolop_class = rfc4511.AddRequest


class AddResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAwCAQJpBwoBAAQABAA=
"""

    expected_protocolop_class = rfc4511.AddResponse


class DelRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MCwCAQpKJ2NuPXRlbXB1c2VyLG91PXBlb3BsZSxkYz1leGFtcGxlLGRjPWNvbQ==
"""

    expected_protocolop_class = rfc4511.DelRequest


class DelResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MCcCAQprIgoBIAQbb3U9cGVvcGxlLGRjPWV4YW1wbGUsZGM9Y29tBAA=
"""

    expected_protocolop_class = rfc4511.DelResponse


class ModifyDNRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MF0CAQhsWAQnY249dGVtcHVzZXIsb3U9cGVvcGxlLGRjPWV4YW1wbGUsZGM9Y29tBA9jbj1u
ZXdfdGVtcHVzZXIBAf+AGW91PXBlb3BsZSxkYz1XUk9ORyxkYz1jb20=
"""

    expected_protocolop_class = rfc4511.ModifyDNRequest

    def setUp(self):
        """
        According to the chapter 8.2 in
        https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf,
        the boolean value true is encoded to any non-zero value.
        Since some of LDAP client like openldap ldapsearch command encode True
        to 0xff, and pyasn1 encodes True to 0x01, it is needed to replace FF to
        01 for testing purpose.
        """
        if sys.version_info[0] <= 2:
            substrate_ff = base64.b64decode(self.__class__.b64_text)
            substrate_01 = str(
                bytearray(substrate_ff).replace(b'\xff', b'\x01')
            )
            self.__class__.b64_text = base64.b64encode(substrate_01)
        else:
            substrate_ff = base64.b64decode(self.__class__.b64_text.encode())
            substrate_01 = substrate_ff.replace(b'\xff', b'\x01')
            self.__class__.b64_text = base64.b64encode(substrate_01).decode()


class ModifyDNResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MDACAQhtKwoBRwQABCRDYW5ub3QgbW92ZSBlbnRyaWVzIGFjcm9zcyBiYWNrZW5kcwo=
"""

    expected_protocolop_class = rfc4511.ModifyDNResponse


class CompareRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MEICAQJuPQQpdWlkPWRlbW9fdXNlcixvdT1wZW9wbGUsZGM9ZXhhbXBsZSxkYz1jb20wEAQC
Y24ECiBEZW1vIFVzZXI=
"""

    expected_protocolop_class = rfc4511.CompareRequest


class CompareResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAwCAQJvBwoBBgQABAA=
"""

    expected_protocolop_class = rfc4511.CompareResponse


class AbandonRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MAYCAQNQAQM=
"""

    expected_protocolop_class = rfc4511.AbandonRequest


class ExtendedRequestTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MB0CAQF3GIAWMS4zLjYuMS40LjEuMTQ2Ni4yMDAzNw==
"""

    expected_protocolop_class = rfc4511.ExtendedRequest


class ExtendedResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MF8CAQF4WgoBAAQABDtTdGFydCBUTFMgcmVxdWVzdCBhY2NlcHRlZC5TZXJ2ZXIgd2lsbGlu
ZyB0byBuZWdvdGlhdGUgU1NMLooWMS4zLjYuMS40LjEuMTQ2Ni4yMDAzNw==
"""

    expected_protocolop_class = rfc4511.ExtendedResponse


class IntermediateResponseTestCase(unittest.TestCase, LDAPTestCaseBase):
    b64_text = """\
MIGDAgECeXyAGDEuMy42LjEuNC4xLjQyMDMuMS45LjEuNIFgoV4EXGxvY2FsaG9zdC5sb2Nh
bGRvbWFpbjozODkjY249ZGlyZWN0b3J5IG1hbmFnZXI6b3U9cGVvcGxlLGRjPWV4YW1wbGUs
ZGM9Y29tOihvYmplY3RDbGFzcz0qKSMxoAA=
"""

    expected_protocolop_class = rfc4511.IntermediateResponse


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
