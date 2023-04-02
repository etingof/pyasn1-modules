# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Delegated Credentials for TLS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9345.txt

from pyasn1.type import univ
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# DelegatedCredentialExtn

class DelegationUsage(univ.Null):
    pass


id_cloudflare = univ.ObjectIdentifier((1, 3, 6, 1, 4, 1, 44363,))

id_ce_delegationUsage = id_cloudflare + (44,)


# Update the Certificate Extension Map

_certificateExtensionsMapUpdate = {
    id_ce_delegationUsage: DelegationUsage(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
