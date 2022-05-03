# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Data Structure for the Security Suitability of Cryptographic Algorithms
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5698.txt
# https://www.rfc-editor.org/errata/eid6948

from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import univ
from pyasn1.type import useful

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

dsscExtensionsMap = opentypemap.get('dsscExtensionsMap')


# Import from RFC 5652

ContentInfo = rfc5652.ContentInfo


# DSSC

class AlgID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', char.UTF8String()),
        namedtype.NamedType('oid', univ.SequenceOf(
            componentType=univ.ObjectIdentifier()).subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('uri', univ.SequenceOf(
            componentType=char.IA5String()).subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


class Extension(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('extensionType', univ.ObjectIdentifier()),
        namedtype.NamedType('extension', univ.Any(),
            openType=opentype.OpenType('extensionType', dsscExtensionsMap)
        )
    )


class Parameter(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', char.UTF8String()),
        namedtype.OptionalNamedType('min', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('max', univ.Integer().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('other', Extension().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 2)))
    )


class Validity(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('start', useful.GeneralizedTime().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('end', useful.GeneralizedTime().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


class Evaluation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('parameters', univ.SequenceOf(
            componentType=Parameter()).subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('validity',
            Validity().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('other',
            Extension().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 2)))
    )


class Algorithm(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithmIdentifier', AlgID()),
        namedtype.NamedType('evaluations',
            univ.SequenceOf(componentType=Evaluation())),
        namedtype.OptionalNamedType('information', univ.SequenceOf(
            componentType=char.UTF8String()).subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('other', Extension().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 1)))
    )


class PolicyName(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', char.UTF8String()),
        namedtype.OptionalNamedType('oid', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('uri', char.IA5String())
    )


class Publisher(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', char.UTF8String()),
        namedtype.OptionalNamedType('address',
            char.UTF8String().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('uri',
            char.IA5String().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


class SecuritySuitabilityPolicy(ContentInfo):
    pass


class TBSPolicy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version', univ.Integer(
            namedValues=namedval.NamedValues(('v1', 1))).subtype(value='v1')),
        namedtype.DefaultedNamedType('language',
            char.UTF8String().subtype(value='en')),
        namedtype.NamedType('policyName', PolicyName()),
        namedtype.NamedType('publisher', Publisher()),
        namedtype.NamedType('policyIssueDate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('nextUpdate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('usage', char.UTF8String()),
        namedtype.NamedType('algorithms',
            univ.SequenceOf(componentType=Algorithm()))
    )


id_ct_dssc = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 11, 1, 6))


# Update the CMS Content Type Map

_cmsContentTypesMapUpdate = {
    id_ct_dssc: TBSPolicy(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
