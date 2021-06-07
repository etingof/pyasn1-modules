# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Elliptic Curve Private Key
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5915.txt

from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5480


class ECPrivateKey(univ.Sequence):
    pass

ECPrivateKey.componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', univ.Integer(
        namedValues=namedval.NamedValues(('ecPrivkeyVer1', 1)))),
    namedtype.NamedType('privateKey', univ.OctetString()),
    namedtype.OptionalNamedType('parameters', rfc5480.ECParameters().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('publicKey', univ.BitString().subtype(
        explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
)
