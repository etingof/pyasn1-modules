#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Resource Public Key Infrastructure (RPKI) Validation Reconsidered
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8360.txt
# https://www.rfc-editor.org/errata/eid5870
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc3779
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# IP Address Delegation Extension V2

id_pe_ipAddrBlocks_v2 = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.28')

IPAddrBlocks = rfc3779.IPAddrBlocks


# Autonomous System Identifier Delegation Extension V2

id_pe_autonomousSysIds_v2 = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.29')

ASIdentifiers = rfc3779.ASIdentifiers


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_pe_ipAddrBlocks_v2: IPAddrBlocks(),
    id_pe_autonomousSysIds_v2: ASIdentifiers(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
