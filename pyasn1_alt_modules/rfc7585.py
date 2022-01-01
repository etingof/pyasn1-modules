#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Network Access Identifier (NAI) Realm Name for Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc7585.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')


# NAI Realm Name for Certificates

id_pkix = univ.ObjectIdentifier('1.3.6.1.5.5.7')

id_on = id_pkix + (8, )

id_on_naiRealm = id_on + (8, )


ub_naiRealm_length = univ.Integer(255)


class NAIRealm(char.UTF8String):
    subtypeSpec = constraint.ValueSizeConstraint(1, ub_naiRealm_length)


naiRealm = rfc5280.AnotherName()
naiRealm['type-id'] = id_on_naiRealm
naiRealm['value'] = NAIRealm()


# Update the Other Names Map

_otherNamesMapUpdate = {
    id_on_naiRealm: NAIRealm(),
}

otherNamesMap.update(_otherNamesMapUpdate)
