#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Device Owner Attribute
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5916.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')


# Device Owner Attribute

id_deviceOwner = univ.ObjectIdentifier((2, 16, 840, 1, 101, 2, 1, 5, 69))

at_deviceOwner = rfc5280.Attribute()
at_deviceOwner['type'] = id_deviceOwner
at_deviceOwner['values'][0] = univ.ObjectIdentifier()


# Update the Certificate Attributes Map

_certificateAttributesMapUpdate = {
    id_deviceOwner: univ.ObjectIdentifier(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)
