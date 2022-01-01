#
# This file is part of pyasn1-alt-modules software.
#
# Modified by Russ Housley to import from RFC 5280 instead of RFC 2459.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# PKCS#10 syntax
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc2314
#
# Sample captures could be obtained with "openssl req" command
#
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

Attribute = rfc5280.Attribute

Name = rfc5280.Name

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# PKCS#10

class Attributes(univ.SetOf):
    componentType = Attribute()


class Version(univ.Integer):
    pass


class CertificationRequestInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('subject', Name()),
        namedtype.NamedType('subjectPublicKeyInfo', SubjectPublicKeyInfo()),
        namedtype.NamedType('attributes',
                            Attributes().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )


class Signature(univ.BitString):
    pass


class SignatureAlgorithmIdentifier(AlgorithmIdentifier):
    pass


class CertificationRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certificationRequestInfo', CertificationRequestInfo()),
        namedtype.NamedType('signatureAlgorithm', SignatureAlgorithmIdentifier()),
        namedtype.NamedType('signature', Signature())
    )
