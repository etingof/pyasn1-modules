#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Signed Checklist (RSC)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9323.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc3779
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


# Imports from RFC 3779

ASIdOrRange = rfc3779.ASIdOrRange

IPAddressOrRange = rfc3779.IPAddressOrRange


# Imports from RFC 5652

Digest = rfc5652.Digest

DigestAlgorithmIdentifier = rfc5652.DigestAlgorithmIdentifier


# The RPKI Signed Checklist Content Type

id_ct_signedChecklist = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.48')


class ConstrainedIPAddressFamily(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressFamily', univ.OctetString().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(2, 2))),
        namedtype.NamedType('ipAddressChoice', univ.SequenceOf(
            componentType=IPAddressOrRange()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


class ConstrainedASIdentifiers(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('asnum', univ.SequenceOf(
            componentType=ASIdOrRange()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                    explicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 0)))
    )


class ConstrainedIPAddrBlocks(univ.SequenceOf):
    componentType = ConstrainedIPAddressFamily()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class ResourceBlock(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('asID',
            ConstrainedASIdentifiers().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('ipAddrBlocks',
            ConstrainedIPAddrBlocks().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1)))
    )
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.WithComponentsConstraint(
            ('asID', constraint.ComponentPresentConstraint())),
        constraint.WithComponentsConstraint(
            ('ipAddrBlocks', constraint.ComponentPresentConstraint()))
    )


class PortableFilename(char.IA5String):
    subtypeSpec = constraint.PermittedAlphabetConstraint(
        'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
        'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
        'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
        'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
        'W', 'X', 'Y', 'Z', '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', '.', '-', '_'
    )


class FileNameAndHash(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('fileName', PortableFilename()),
        namedtype.NamedType('hash', Digest())
    )


class RpkiSignedChecklist(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', univ.Integer().subtype(
            explicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 0)).subtype(value=0)),
        namedtype.NamedType('resources', ResourceBlock()),
        namedtype.NamedType('digestAlgorithm', DigestAlgorithmIdentifier()),
        namedtype.NamedType('checkList', univ.SequenceOf(
            componentType=FileNameAndHash()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_ct_signedChecklist: RpkiSignedChecklist(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
