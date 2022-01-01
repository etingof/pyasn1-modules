# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from the asn1ate tool, with manual
#   changes to AES_CCM_ICVlen.subtypeSpec and added comments
# Modified by Russ Housley to include the opentypemap manager, and drop use
#   of the _OID routine.
#
# Copyright (c) 2018-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
#  AES-CCM and AES-GCM Algorithms fo use with the Authenticated-Enveloped-Data
#  protecting content type for the Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5084.txt

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


# AES-CCM and AES-GCM Algorithm Paramaters

class AES_CCM_ICVlen(univ.Integer):
    pass


class AES_GCM_ICVlen(univ.Integer):
    pass


AES_CCM_ICVlen.subtypeSpec = constraint.SingleValueConstraint(4, 6, 8, 10, 12, 14, 16)

AES_GCM_ICVlen.subtypeSpec = constraint.ValueRangeConstraint(12, 16)


class CCMParameters(univ.Sequence):
    pass


CCMParameters.componentType = namedtype.NamedTypes(
    namedtype.NamedType('aes-nonce', univ.OctetString().subtype(subtypeSpec=constraint.ValueSizeConstraint(7, 13))),
    # The aes-nonce parameter contains 15-L octets, where L is the size of the length field. L=8 is RECOMMENDED.
    # Within the scope of any content-authenticated-encryption key, the nonce value MUST be unique.
    namedtype.DefaultedNamedType('aes-ICVlen', AES_CCM_ICVlen().subtype(value=12))
)


class GCMParameters(univ.Sequence):
    pass


GCMParameters.componentType = namedtype.NamedTypes(
    namedtype.NamedType('aes-nonce', univ.OctetString()),
    # The aes-nonce may have any number of bits between 8 and 2^64, but it MUST be a multiple of 8 bits.
    # Within the scope of any content-authenticated-encryption key, the nonce value MUST be unique.
    # A nonce value of 12 octets can be processed more efficiently, so that length is RECOMMENDED.
    namedtype.DefaultedNamedType('aes-ICVlen', AES_GCM_ICVlen().subtype(value=12))
)


# Object Identifiers

aes = univ.ObjectIdentifier((2, 16, 840, 1, 101, 3, 4, 1))

id_aes128_CCM = aes + (7,)

id_aes128_GCM = aes + (6,)

id_aes192_CCM = aes + (27,)

id_aes192_GCM = aes + (26,)

id_aes256_CCM = aes + (47,)

id_aes256_GCM = aes + (46,)


# Update the Algorithm Identifier Map and the S/MIME Capability Map

_algorithmIdentifierMapUpdate = {
    id_aes128_CCM: CCMParameters(),
    id_aes128_GCM: GCMParameters(),
    id_aes192_CCM: CCMParameters(),
    id_aes192_GCM: GCMParameters(),
    id_aes256_CCM: CCMParameters(),
    id_aes256_GCM: GCMParameters(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
