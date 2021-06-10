#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# TimeStampedData
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5544.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc3161
from pyasn1_alt_modules import rfc4998
from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652

MAX = float('inf')

otherEvidenceMap = { }


# Imports from RFC 5652

Attribute = rfc5652.Attribute


# Imports from RFC 5280

CertificateList = rfc5280.CertificateList


# Imports from RFC 3161

TimeStampToken = rfc3161.TimeStampToken


# Imports from RFC 4998

EvidenceRecord = rfc4998.EvidenceRecord


# TimeStampedData

class Attributes(univ.SetOf):
    componentType = Attribute()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class TimeStampAndCRL(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('timeStamp', TimeStampToken()),
        namedtype.OptionalNamedType('crl', CertificateList())
    )


class TimeStampTokenEvidence(univ.SequenceOf):
    componentType = TimeStampAndCRL()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class OtherEvidence(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('oeType', univ.ObjectIdentifier()),
        namedtype.NamedType('oeValue', univ.Any(),
            openType=opentype.OpenType('oeType', otherEvidenceMap))
    )


class Evidence(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('tstEvidence',
            TimeStampTokenEvidence().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('ersEvidence',
            EvidenceRecord().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('otherEvidence',
            OtherEvidence().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 2)))
    )


class MetaData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('hashProtected', univ.Boolean()),
        namedtype.OptionalNamedType('fileName', char.UTF8String()),
        namedtype.OptionalNamedType('mediaType', char.IA5String()),
        namedtype.OptionalNamedType('otherMetaData', Attributes())
    )


class TimeStampedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version',
            univ.Integer(namedValues=namedval.NamedValues(('v1', 1)))),
        namedtype.OptionalNamedType('dataUri', char.IA5String()),
        namedtype.OptionalNamedType('metaData', MetaData()),
        namedtype.OptionalNamedType('content', univ.OctetString()),
        namedtype.NamedType('temporalEvidence', Evidence())
    )


id_ct_timestampedData = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.31')


# Update the CMS Content Type Map in rfc5652.py

_cmsContentTypesMapUpdate = {
    id_ct_timestampedData: TimeStampedData(),
}

rfc5652.cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
