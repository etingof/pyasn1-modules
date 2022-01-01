#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Internet X.509 Public Key Infrastructure Permanent Identifier
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4043.txt
#

from pyasn1.type import char
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')


id_pkix = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, ))

id_on = id_pkix + (8, )

id_on_permanentIdentifier = id_on + (3, )


class PermanentIdentifier(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('identifierValue', char.UTF8String()),
        namedtype.OptionalNamedType('assigner', univ.ObjectIdentifier())
    )


# Update the Other Names to Map

_otherNameMapUpdate = {
    id_on_permanentIdentifier: PermanentIdentifier(),
}

otherNamesMap.update(_otherNameMapUpdate)
