#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to add maps for use with opentypes.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# X.509 Extensions for MUD URL and MUD Signer;
# Object Identifier for CMS Content Type for a MUD file
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8520.txt
#

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')


# X.509 Extension for MUD URL

id_pe_mud_url = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.25')

class MUDURLSyntax(char.IA5String):
    pass


# X.509 Extension for MUD Signer

id_pe_mudsigner = univ.ObjectIdentifier('1.3.6.1.5.5.7.1.30')

class MUDsignerSyntax(rfc5280.Name):
    pass


# Object Identifier for CMS Content Type for a MUD file

id_ct_mudtype = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.41')


# Update the Certificate Extensions Map

_certificateExtensionsMapUpdate = {
    id_pe_mud_url: MUDURLSyntax(),
    id_pe_mudsigner: MUDsignerSyntax(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_mudtype: univ.OctetString(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
