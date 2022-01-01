#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# BRSKI MASA Certificate Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8995.txt
#

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


id_pe = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 1))

id_pe_masa_url = id_pe + (32,)


class MASAURLSyntax(char.IA5String):
    pass


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_pe_masa_url: MASAURLSyntax(),	
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
