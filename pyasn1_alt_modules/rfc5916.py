#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Device Owner Attribute
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5916.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Device Owner Attribute

id_deviceOwner = univ.ObjectIdentifier((2, 16, 840, 1, 101, 2, 1, 5, 69))

at_deviceOwner = rfc5280.Attribute()
at_deviceOwner['type'] = id_deviceOwner
at_deviceOwner['values'][0] = univ.ObjectIdentifier()


# Add to the map of Attribute Type OIDs to Attributes in rfc5280.py.

_certificateAttributesMapUpdate = {
    id_deviceOwner: univ.ObjectIdentifier(),
}

rfc5280.certificateAttributesMap.update(_certificateAttributesMapUpdate)
