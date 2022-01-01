#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# GSS-API Tokens
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc2743.txt
#

from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

gssapiMechTypeMap = opentypemap.get('gssapiMechTypeMap')


class PerMsgToken(univ.Any):
    pass


class SealedMessage(univ.Any):
    pass


class SubsequentContextToken(univ.Any):
    pass


class MechType(univ.ObjectIdentifier):
    pass


class InitialContextToken(univ.Sequence):
    pass

InitialContextToken.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0)
)

InitialContextToken.componentType = namedtype.NamedTypes(
    namedtype.NamedType('thisMech', MechType()),
    namedtype.NamedType('innerContextToken', univ.Any(),
        openType=opentype.OpenType('thisMech', gssapiMechTypeMap)
    )
)


# For DASS (RFC 1507), the MechType is 1.3.12.2.1011.7.5.
# For Kerberos V5 (RFC 1964), the MechType is 1.2.840.113554.1.2.2.
# If modules are ever written for these RFCs, the module should add 
# entries for these object identifiers to gssapiMechTypeMap.
