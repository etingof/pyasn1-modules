#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager and
#   update the S/MIME Capability Map.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Wrapping a Hashed Message Authentication Code (HMAC) key
#   with a Triple-Data Encryption Standard (DES) Key or
#   an Advanced Encryption Standard (AES) Key
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3537.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')

smimeCapabilityMap = opentypemap.get('smimeCapabilityMap')


# Object Identifiers

id_alg_HMACwith3DESwrap = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.11')
   
id_alg_HMACwithAESwrap = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.12')


# Update the Algorithm Identifiers Map and S/MIME Capability Map

_algorithmIdentifierMapUpdate = {
    id_alg_HMACwith3DESwrap: univ.Null(""),
    id_alg_HMACwithAESwrap: univ.Null(""),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)

smimeCapabilityMap.update(_algorithmIdentifierMapUpdate)
