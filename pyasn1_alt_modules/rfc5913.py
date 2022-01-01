#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Authority Clearance Constraints Certificate Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5913.txt
# https://www.rfc-editor.org/errata/eid5890
#

from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5755
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

MAX = float('inf')


# Authority Clearance Constraints Certificate Extension

id_pe_clearanceConstraints = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.21')

id_pe_authorityClearanceConstraints = id_pe_clearanceConstraints


class AuthorityClearanceConstraints(univ.SequenceOf):
    componentType = rfc5755.Clearance()
    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_pe_clearanceConstraints: AuthorityClearanceConstraints(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
