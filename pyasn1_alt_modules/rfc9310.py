#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Certificate Extension for 5G Network Function Types
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9310.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

MAX = float('inf')


# NFTypes Certificate Extension

class NFType(char.IA5String):
    subtypeSpec = constraint.ValueSizeConstraint(1, 32)


class NFTypes(univ.SequenceOf):
    componentType = NFType()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


id_pe_nftype = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 1, 34))


# Add to the map of Certificate Extensions

_certificateExtensionsMap = {
    id_pe_nftype: NFTypes(),
}

certificateExtensionsMap.update(_certificateExtensionsMap)
