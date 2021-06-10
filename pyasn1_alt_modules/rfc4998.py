#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some help from asn1ate v.0.6.0
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Evidence Record Syntax (ERS)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4998.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652

MAX = float('inf')

ersEncryptionInfoValueMap = { }


# Imports from RFC 5280 and RFC 5652

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

Attribute = rfc5652.Attribute

ContentType = rfc5652.ContentType

ContentInfo = rfc5652.ContentInfo


# Evidence Record Syntax

class PartialHashtree(univ.SequenceOf):
    componentType = univ.OctetString()


class Attributes(univ.SetOf):
    componentType = Attribute()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class ArchiveTimeStamp(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('digestAlgorithm',
            AlgorithmIdentifier().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('attributes',
            Attributes().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('reducedHashtree',
            univ.SequenceOf(componentType=PartialHashtree()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 2))),
        namedtype.NamedType('timeStamp', ContentInfo())
    )


class ArchiveTimeStampChain(univ.SequenceOf):
    componentType = ArchiveTimeStamp()


class ArchiveTimeStampSequence(univ.SequenceOf):
    componentType = ArchiveTimeStampChain()


class CryptoInfos(univ.SequenceOf):
    componentType = Attribute()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class EncryptionInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptionInfoType', univ.ObjectIdentifier()),
        namedtype.NamedType('encryptionInfoValue', univ.Any(),
            openType=opentype.OpenType('encryptionInfoType',
                ersEncryptionInfoValueMap))
    )


class EvidenceRecord(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version',
            univ.Integer(namedValues=namedval.NamedValues(('v1', 1)))),
        namedtype.NamedType('digestAlgorithms',
            univ.SequenceOf(componentType=AlgorithmIdentifier())),
        namedtype.OptionalNamedType('cryptoInfos',
            CryptoInfos().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('encryptionInfo',
            EncryptionInfo().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.NamedType('archiveTimeStampSequence',
            ArchiveTimeStampSequence())
    )


ltans = univ.ObjectIdentifier('1.3.6.1.5.5.11')

id_aa_er_internal = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.49')

id_aa_er_internal = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.50')


# Update the CMS Attribute Map in rfc5652.py.

_cmsAttributesMapUpdate = {
    id_aa_er_internal: EvidenceRecord(),
    id_aa_er_internal: EvidenceRecord(),
}

rfc5652.cmsAttributesMap.update(_cmsAttributesMapUpdate)
