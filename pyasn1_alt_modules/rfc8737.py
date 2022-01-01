#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2020-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# ACME TLS ALPN Challenge Certificate Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8737.txt
#

from pyasn1.type import univ
from pyasn1.type import constraint

from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


id_pe_acmeIdentifier = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 1, 31))

class Authorization(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(32, 32)


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_pe_acmeIdentifier: Authorization(),	
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
