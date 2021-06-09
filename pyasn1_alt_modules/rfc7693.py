#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# The BLAKE2 Cryptographic Hash and MAC
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc7693.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


hashAlgs = univ.ObjectIdentifier('1.3.6.1.4.1.1722.12.2')

blake2b = hashAlgs + (1, )

id_blake2b160 = blake2b + (5, )

id_blake2b256 = blake2b + (8, )

id_blake2b384 = blake2b + (12, )

id_blake2b512 = blake2b + (16, )

blake2s = hashAlgs + (2, )

id_blake2s128 = blake2s + (4, )

id_blake2s160 = blake2s + (5, )

id_blake2s224 = blake2s + (7, )

id_blake2s256 = blake2s + (8, )


# Update the Algorithm Identifier map

_algorithmIdentifierMapUpdate = {
    id_blake2b160: univ.Null(),
    id_blake2b256: univ.Null(),
    id_blake2b384: univ.Null(),
    id_blake2b512: univ.Null(),
    id_blake2s128: univ.Null(),
    id_blake2s160: univ.Null(),
    id_blake2s224: univ.Null(),
    id_blake2s256: univ.Null(),
}

rfc5280.algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
