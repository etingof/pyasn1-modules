#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# GOST Algorithms with PKCS#5
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9337.txt
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


# Object Identifiers

id_tc26 = univ.ObjectIdentifier((1, 2, 643, 7, 1))

id_tc26_algorithms = id_tc26 + (1,)

id_tc26_mac = id_tc26_algorithms + (4,)

id_tc26_hmac_gost3411_12_512 = id_tc26_mac + (2,)

id_tc26_cipher = id_tc26_algorithms + (5,)

id_tc26_cipher_gostr3412_2015_magma = id_tc26_cipher + (1,)

id_tc26_cipher_gostr3412_2015_magma_ctracpkm = \
    id_tc26_cipher_gostr3412_2015_magma + (1,)

id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac = \
    id_tc26_cipher_gostr3412_2015_magma + (2,)

id_tc26_cipher_gostr3412_2015_kuznyechik = id_tc26_cipher + (2,)

id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm = \
    id_tc26_cipher_gostr3412_2015_kuznyechik + (1,)

id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac = \
    id_tc26_cipher_gostr3412_2015_kuznyechik + (2,)


# Parameters

class Gost3412_15_Encryption_Parameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('ukm', univ.OctetString())
    )


# Update the algorithm identifiers map

_algorithmIdentifierMapUpdate = {
    id_tc26_hmac_gost3411_12_512: univ.Null(),
    id_tc26_cipher_gostr3412_2015_magma_ctracpkm: \
        Gost3412_15_Encryption_Parameters(),
    id_tc26_cipher_gostr3412_2015_magma_ctracpkm_omac: \
        Gost3412_15_Encryption_Parameters(),
    id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm: \
        Gost3412_15_Encryption_Parameters(),
    id_tc26_cipher_gostr3412_2015_kuznyechik_ctracpkm_omac: \
        Gost3412_15_Encryption_Parameters(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
