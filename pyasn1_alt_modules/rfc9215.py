#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# GOST R 34.10-2012 and GOST R 34.11-2012 Algorithms
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9215.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

certificateAttributesMap = opentypemap.get('certificateAttributesMap')

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# MODULE: GostR3410-2012-PKISyntax { 1 2 643 7 1 0 2 }

id_tc26 = univ.ObjectIdentifier((1, 2, 643, 7, 1))

id_tc26_sign = id_tc26 + (1, 1)

id_tc26_digest = id_tc26 + (1, 2)

id_tc26_sign_constants = id_tc26 + (2, 1)

id_tc26_gost_3410_2012_256_constants = id_tc26_sign_constants + (1,)

id_tc26_gost_3410_2012_512_constants = id_tc26_sign_constants + (2,)

id_tc26_gost3410_2012_256 = id_tc26_sign + (1,)

id_tc26_gost3410_2012_512 = id_tc26_sign + (2,)

id_tc26_gost3411_12_256 = id_tc26_digest + (2,)

id_tc26_gost3411_12_512 = id_tc26_digest + (3,)

id_tc26_signwithdigest = id_tc26 + (1, 3)

id_tc26_signwithdigest_gost3410_2012_256 = id_tc26_signwithdigest + (2,)

id_tc26_signwithdigest_gost3410_2012_512 = id_tc26_signwithdigest + (3,)

id_tc26_gost_3410_2012_256_paramSetA = id_tc26_gost_3410_2012_256_constants + (1,)

id_tc26_gost_3410_2012_256_paramSetB = id_tc26_gost_3410_2012_256_constants + (2,)

id_tc26_gost_3410_2012_256_paramSetC = id_tc26_gost_3410_2012_256_constants + (3,)

id_tc26_gost_3410_2012_256_paramSetD = id_tc26_gost_3410_2012_256_constants + (4,)

id_tc26_gost_3410_2012_512_paramSetTest = id_tc26_gost_3410_2012_512_constants + (0,)

id_tc26_gost_3410_2012_512_paramSetA = id_tc26_gost_3410_2012_512_constants + (1,)

id_tc26_gost_3410_2012_512_paramSetB = id_tc26_gost_3410_2012_512_constants + (2,)

id_tc26_gost_3410_2012_512_paramSetC = id_tc26_gost_3410_2012_512_constants + (3,)


class GostR3410_2012_256_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(64, 64)


class GostR3410_2012_512_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(128, 128)


class GostR3410_2012_PublicKey(univ.OctetString):
    subtypeSpec = constraint.ConstraintsUnion(
        constraint.ValueSizeConstraint(64, 64),
        constraint.ValueSizeConstraint(128, 128)
    )


class GostR3410_2012_PublicKeyParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('publicKeyParamSet', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('digestParamSet', univ.ObjectIdentifier())
    )


# MODULE: RuStrongCertsSyntax { 1 2 643 7 1 0 6 }

id_ca = univ.ObjectIdentifier((1, 2, 643, 3))

id_fss = univ.ObjectIdentifier((1, 2, 643, 100))

id_fns = id_ca + (131,)


class OGRN(char.NumericString):
    subtypeSpec = constraint.ValueSizeConstraint(13, 13)

id_OGRN = id_fss + (1,)


class SNILS(char.NumericString):
    subtypeSpec = constraint.ValueSizeConstraint(11, 11)

id_SNILS = id_fss + (3,)


class OGRNIP(char.NumericString):
    subtypeSpec = constraint.ValueSizeConstraint(15, 15)

id_OGRNIP = id_fss + (5,)


id_class = id_fss + (113,)

id_class_kc1 = id_class + (1,)

id_class_kc2 = id_class + (2,)

id_class_kc3 = id_class + (3,)

id_class_kb1 = id_class + (4,)

id_class_kb2 = id_class + (5,)

id_class_ka = id_class + (6,)


class INN(char.NumericString):
    subtypeSpec = constraint.ValueSizeConstraint(12, 12)

id_INN = id_fns + (1, 1)


class INNLE(char.NumericString):
    subtypeSpec = constraint.ValueSizeConstraint(10, 10)

id_INNLE = id_fss + (4,)


class SubjectSignTool(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(1, 200)

id_SubjectSignTool = id_fss + (111,)


class IssuerSignTool(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('signTool',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 200))),
        namedtype.NamedType('cATool',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 200))),
        namedtype.NamedType('signToolCert',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 100))),
        namedtype.NamedType('cAToolCert',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 100)))
    )

id_IssuerSignTool = id_fss + (112,)


class IdentificationKind(univ.Integer):
    namedValues = namedval.NamedValues(
        ('personal', 0),
        ('remote_cert', 1),
        ('remote_passport', 2),
        ('remote_system', 3)
    )

id_IdentificationKind = id_fss + (114,)


# Update the Algorithm Identifier Map

_algorithmIdentifierMapUpdate = {
    id_tc26_gost3410_2012_256: GostR3410_2012_PublicKeyParameters(),
    id_tc26_gost3410_2012_512: GostR3410_2012_PublicKeyParameters(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)


# Update the Certificate Attribute Map

_certificateAttributesMapUpdate = {
    id_INN: INN(),
    id_INNLE: INNLE(),
    id_OGRN: OGRN(),
    id_OGRNIP: OGRNIP(),
    id_SNILS: SNILS(),
    id_IdentificationKind: IdentificationKind()
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)


# Update the Certificate Extension Map

_certificateExtensionsMap = {
    id_SubjectSignTool: SubjectSignTool(),
    id_IssuerSignTool: IssuerSignTool(),
}

certificateExtensionsMap.update(_certificateExtensionsMap)
