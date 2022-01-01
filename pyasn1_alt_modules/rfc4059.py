#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Warranty Certificate Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4059.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import useful
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

MAX = float('inf')


class TermsAndConditionsURL(char.IA5String):
    pass


class CurrencyAmount(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('currency', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(1, 999))),
        namedtype.NamedType('amount', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, MAX))),
        namedtype.NamedType('amtExp10', univ.Integer().subtype(
            subtypeSpec=constraint.ValueRangeConstraint(0, MAX)))
    )


class ValidityPeriod(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('notBefore', useful.GeneralizedTime()),
        namedtype.NamedType('notAfter', useful.GeneralizedTime())
    )


class WarrantyType(univ.Integer):
    namedValues = namedval.NamedValues(
        ('aggregated', 0),
        ('perTransaction', 1)
    )


class WarrantyValidityPeriod(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sameAsCertificate', univ.Null()),
        namedtype.NamedType('explicitPeriod', ValidityPeriod())
    )


class WarrantyInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('validity', WarrantyValidityPeriod()),
        namedtype.NamedType('amount', CurrencyAmount()),
        namedtype.NamedType('wType', WarrantyType())
    )


class WarrantyData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('base', WarrantyInfo()),
        namedtype.OptionalNamedType('extended', WarrantyInfo()),
        namedtype.OptionalNamedType('tcURL', TermsAndConditionsURL())
    )


class Warranty(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('none', univ.Null()),
        namedtype.NamedType('wData', WarrantyData())
    )


id_pe = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 1))


id_pe_warranty_extn = id_pe + (16,)


# Update the Certificate Extensions Map

_certificateExtensionsMap = {
    id_pe_warranty_extn: Warranty(),
}

certificateExtensionsMap.update(_certificateExtensionsMap)
