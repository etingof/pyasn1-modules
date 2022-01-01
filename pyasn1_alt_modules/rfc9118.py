# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Enhanced JWT Claim Constraints certificate extensions
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9118.txt

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

MAX = float('inf')


# EnhancedJWTClaimConstraints Certificate Extension

id_pe_eJWTClaimConstraints = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.33')


class JWTClaimName(char.IA5String):
    pass


class JWTClaimNames(univ.SequenceOf):
    componentType = JWTClaimName()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class JWTClaimValues(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('claim', JWTClaimName()),
        namedtype.NamedType('values', univ.SequenceOf(
            componentType=char.UTF8String()).subtype(
                sizeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


class JWTClaimValuesList(univ.SequenceOf):
    componentType = JWTClaimValues()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class EnhancedJWTClaimConstraints(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('mustInclude',
            JWTClaimNames().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('permittedValues',
            JWTClaimValuesList().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('mustExclude',
            JWTClaimNames().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 2)))
    )
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.WithComponentsConstraint(
            ('mustInclude', constraint.ComponentPresentConstraint())),
        constraint.WithComponentsConstraint(
            ('permittedValues', constraint.ComponentPresentConstraint())),
        constraint.WithComponentsConstraint(
            ('mustExclude', constraint.ComponentPresentConstraint()))
    )


# Update the Certificate Extension Map

_certificateExtensionsMapUpdate = {
    id_pe_eJWTClaimConstraints: EnhancedJWTClaimConstraints(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
