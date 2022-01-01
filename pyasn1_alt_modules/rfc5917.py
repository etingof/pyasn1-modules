#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Clearance Sponsor Attribute
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5917.txt
# https://www.rfc-editor.org/errata/eid4558
# https://www.rfc-editor.org/errata/eid5883
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')


# DirectoryString is the same as RFC 5280, except for two things:
#   1. the length is limited to 64;
#   2. only the 'utf8String' choice remains because the ASN.1
#      specification says: ( WITH COMPONENTS { utf8String PRESENT } )

class DirectoryString(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('utf8String', char.UTF8String().subtype(
            subtypeSpec=constraint.ValueSizeConstraint(1, 64))),
    )


# Clearance Sponsor Attribute

id_clearanceSponsor = univ.ObjectIdentifier((2, 16, 840, 1, 101, 2, 1, 5, 68))

ub_clearance_sponsor = univ.Integer(64)


at_clearanceSponsor = rfc5280.Attribute()
at_clearanceSponsor['type'] = id_clearanceSponsor
at_clearanceSponsor['values'][0] = DirectoryString()


# Update the Certificate Attributes Map

_certificateAttributesMapUpdate = {
    id_clearanceSponsor: DirectoryString(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)
