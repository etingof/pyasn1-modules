#
# This file is part of pyasn1-alt-modules software.
#
# Modified by Russ Housley to import from RFC 5280 instead of
#   RFC 2251 and RFC 2459.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# PKCS#8 syntax
#
# ASN.1 source from:
# http://tools.ietf.org/html/rfc5208
#
# Sample captures could be obtained with "openssl pkcs8 -topk8" command
#
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

Attribute = rfc5280.Attribute


# PKCS#8

class KeyEncryptionAlgorithms(AlgorithmIdentifier):
    pass


class PrivateKeyAlgorithms(AlgorithmIdentifier):
    pass


class EncryptedData(univ.OctetString):
    pass


class EncryptedPrivateKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptionAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('encryptedData', EncryptedData())
    )


class PrivateKey(univ.OctetString):
    pass


class Attributes(univ.SetOf):
    componentType = Attribute()


class Version(univ.Integer):
    namedValues = namedval.NamedValues(('v1', 0), ('v2', 1))


class PrivateKeyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('privateKeyAlgorithm', AlgorithmIdentifier()),
        namedtype.NamedType('privateKey', PrivateKey()),
        namedtype.OptionalNamedType('attributes', Attributes().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )
