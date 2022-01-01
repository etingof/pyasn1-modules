#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# KEA and SKIPJACK Algorithms in CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc2876.txt
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

smimeCapabilityMap = opentypemap.get('smimeCapabilityMap')


id_fortezzaConfidentialityAlgorithm = univ.ObjectIdentifier('2.16.840.1.101.2.1.1.4')


id_fortezzaWrap80 = univ.ObjectIdentifier('2.16.840.1.101.2.1.1.23')


id_kEAKeyEncryptionAlgorithm = univ.ObjectIdentifier('2.16.840.1.101.2.1.1.24')


id_keyExchangeAlgorithm = univ.ObjectIdentifier('2.16.840.1.101.2.1.1.22')


class Skipjack_Parm(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('initialization-vector', univ.OctetString())
    )


# Update the Algorithm Identifier map

_algorithmIdentifierMapUpdate = {
    id_fortezzaConfidentialityAlgorithm: Skipjack_Parm(),
    id_kEAKeyEncryptionAlgorithm: rfc5280.AlgorithmIdentifier(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)


# Update the S/MIME Capability map

_smimeCapabilityMapUpdate = {
    id_kEAKeyEncryptionAlgorithm: rfc5280.AlgorithmIdentifier(),
}

smimeCapabilityMap.update(_smimeCapabilityMapUpdate)
