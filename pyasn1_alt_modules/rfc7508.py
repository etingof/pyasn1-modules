#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Securing Header Fields with S/MIME
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc7508.txt
# https://www.rfc-editor.org/errata/eid5875
#

import string

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

cmsAttributesMap = opentypemap.get('cmsAttributesMap')

MAX = float('inf')


class Algorithm(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('canonAlgorithmSimple', 0),
        ('canonAlgorithmRelaxed', 1)
    )


class HeaderFieldStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('duplicated', 0),
        ('deleted', 1),
        ('modified', 2)
    )


class HeaderFieldName(char.VisibleString):
    subtypeSpec = (
        constraint.PermittedAlphabetConstraint(*string.printable) -
        constraint.PermittedAlphabetConstraint(':')
    )


class HeaderFieldValue(char.UTF8String):
    pass


class HeaderField(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('field-Name', HeaderFieldName()),
        namedtype.NamedType('field-Value', HeaderFieldValue()),
        namedtype.DefaultedNamedType('field-Status',
            HeaderFieldStatus().subtype(value='duplicated'))
    )


class HeaderFields(univ.SequenceOf):
    componentType = HeaderField()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class SecureHeaderFields(univ.Set):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('canonAlgorithm', Algorithm()),
        namedtype.NamedType('secHeaderFields', HeaderFields())
    )


id_aa = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 2, ))

id_aa_secureHeaderFieldsIdentifier = id_aa + (55, )



# Update the CMS Attribute Attributes Map

_cmsAttributesMapUpdate = {
    id_aa_secureHeaderFieldsIdentifier: SecureHeaderFields(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)

