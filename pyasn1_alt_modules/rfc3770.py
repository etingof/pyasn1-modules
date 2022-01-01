#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Certificate Extensions and Attributes Supporting Authentication
#   in PPP and Wireless LAN Networks
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3770.txt
# https://www.rfc-editor.org/errata/eid234
#

from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

certificateAttributesMap = opentypemap.get('certificateAttributesMap')

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

MAX = float('inf')


# Extended Key Usage Values

id_kp_eapOverLAN = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.14')

id_kp_eapOverPPP = univ.ObjectIdentifier('1.3.6.1.5.5.7.3.13')


# Wireless LAN SSID Extension

id_pe_wlanSSID = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.13')


class SSID(univ.OctetString):
    pass

SSID.subtypeSpec = constraint.ValueSizeConstraint(1, 32)


class SSIDList(univ.SequenceOf):
    pass

SSIDList.componentType = SSID()
SSIDList.subtypeSpec=constraint.ValueSizeConstraint(1, MAX)


# Wireless LAN SSID Attribute Certificate Attribute
# Uses same syntax as the certificate extension: SSIDList
# Correction for https://www.rfc-editor.org/errata/eid234

id_aca_wlanSSID = univ.ObjectIdentifier('1.3.6.1.5.5.7.10.7')


# Update the Certificate Extension Map

_certificateExtensionsMapUpdate = {
    id_pe_wlanSSID: SSIDList(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)


# Update the Certificate Attribute Map

_certificateAttributesMapUpdate = {
    id_aca_wlanSSID: SSIDList(),
}

certificateAttributesMap.update(_certificateAttributesMapUpdate)
