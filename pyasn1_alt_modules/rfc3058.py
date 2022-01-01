#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# IDEA Encryption Algorithm in CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3058.txt
# https://www.rfc-editor.org/errata/eid5913
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


# Object Identifiers and Parameters for IDEA

id_IDEA_CBC = univ.ObjectIdentifier('1.3.6.1.4.1.188.7.1.1.2')

           
id_alg_CMSIDEAwrap = univ.ObjectIdentifier('1.3.6.1.4.1.188.7.1.1.6')


class IDEA_CBCPar(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('iv', univ.OctetString())
        # exactly 8 octets, when present
    )


# Update the Algorithm Identifiers Map and the SMIMECapability Map

_algorithmIdentifierMapUpdate = {
    id_IDEA_CBC: IDEA_CBCPar(),
    id_alg_CMSIDEAwrap: univ.Null("")
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
