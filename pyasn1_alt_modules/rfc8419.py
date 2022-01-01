# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Edwards-Curve Digital Signature Algorithm (EdDSA) Signatures in the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8419.txt
# https://www.rfc-editor.org/errata/eid5869

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


class ShakeOutputLen(univ.Integer):
    pass


id_Ed25519 = univ.ObjectIdentifier('1.3.101.112')

sigAlg_Ed25519 = rfc5280.AlgorithmIdentifier()
sigAlg_Ed25519['algorithm'] = id_Ed25519
# sigAlg_Ed25519['parameters'] is absent


id_Ed448 = univ.ObjectIdentifier('1.3.101.113')

sigAlg_Ed448 = rfc5280.AlgorithmIdentifier()
sigAlg_Ed448['algorithm'] = id_Ed448
# sigAlg_Ed448['parameters'] is absent


hashAlgs = univ.ObjectIdentifier('2.16.840.1.101.3.4.2')

id_sha512 = hashAlgs + (3, )

hashAlg_SHA_512 = rfc5280.AlgorithmIdentifier()
hashAlg_SHA_512['algorithm'] = id_sha512
# hashAlg_SHA_512['parameters'] is absent


id_shake256 = hashAlgs + (12, )

hashAlg_SHAKE256 = rfc5280.AlgorithmIdentifier()
hashAlg_SHAKE256['algorithm'] = id_shake256
# hashAlg_SHAKE256['parameters']is absent


id_shake256_len = hashAlgs + (18, )

hashAlg_SHAKE256_LEN  = rfc5280.AlgorithmIdentifier()
hashAlg_SHAKE256_LEN['algorithm'] = id_shake256_len
hashAlg_SHAKE256_LEN['parameters'] = ShakeOutputLen()


# Update the Algorithm Identifiers Map

_algorithmIdentifierMapUpdate = {
    id_shake256_len: ShakeOutputLen(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
