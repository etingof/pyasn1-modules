#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2020-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# The ARIA Encryption Algorithm
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5794.txt
# https://www.rfc-editor.org/errata/eid2064
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import addon
from pyasn1_alt_modules import rfc5280


# Import from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier


# Object Identifiers

OID = univ.ObjectIdentifier


id_algorithm = univ.ObjectIdentifier((1, 2, 410, 200046, 1,))

id_sea = id_algorithm + (1,)

id_pad = id_algorithm + (2,)


id_aria128_ecb = id_sea + (1,)

id_aria128_cbc = id_sea + (2,)

id_aria128_cfb = id_sea + (3,)

id_aria128_ofb = id_sea + (4,)

id_aria128_ctr = id_sea + (5,)

id_aria192_ecb = id_sea + (6,)

id_aria192_cbc = id_sea + (7,)

id_aria192_cfb = id_sea + (8,)

id_aria192_ofb = id_sea + (9,)

id_aria192_ctr = id_sea + (10,)

id_aria256_ecb = id_sea + (11,)

id_aria256_cbc = id_sea + (12,)

id_aria256_cfb = id_sea + (13,)

id_aria256_ofb = id_sea + (14,)

id_aria256_ctr = id_sea + (15,)

id_aria128_cmac = id_sea + (21,)

id_aria192_cmac = id_sea + (22,)

id_aria256_cmac = id_sea + (23,)

id_aria128_ocb2 = id_sea + (31,)

id_aria192_ocb2 = id_sea + (32,)

id_aria256_ocb2 = id_sea + (33,)

id_aria128_gcm = id_sea + (34,)

id_aria192_gcm = id_sea + (35,)

id_aria256_gcm = id_sea + (36,)

id_aria128_ccm = id_sea + (37,)

id_aria192_ccm = id_sea + (38,)

id_aria256_ccm = id_sea + (39,)

id_aria128_kw = id_sea + (40,)

id_aria192_kw = id_sea + (41,)

id_aria256_kw = id_sea + (42,)

id_aria128_kwp = id_sea + (43,)

id_aria192_kwp = id_sea + (44,)

id_aria256_kwp = id_sea + (45,)


# Relative OIDs

id_pad_null = addon.RelativeOID('0') # no padding algorithms identified

id_pad_1 = addon.RelativeOID('1')    # padding method 2 of ISO/IEC 9797-1:1999


# Parameters

class AriaPadAlgo(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('specifiedPadAlgo', addon.RelativeOID()),
        namedtype.NamedType('generalPadAlgo', univ.ObjectIdentifier())
    )


default_aria_pad_algo_null = AriaPadAlgo()
default_aria_pad_algo_null['specifiedPadAlgo'] = id_pad_null


default_aria_pad_algo_1 = AriaPadAlgo()
default_aria_pad_algo_1['specifiedPadAlgo'] = id_pad_1


class AriaEcbParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('padAlgo', default_aria_pad_algo_null)
    )


class AriaCbcParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('m', univ.Integer().subtype(value=1)),
        namedtype.DefaultedNamedType('padAlgo', default_aria_pad_algo_1)
    )


class AriaCfbParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),  #  128<=r<=128*1024
        namedtype.NamedType('k', univ.Integer()),  #  1<=k<=128
        namedtype.NamedType('j', univ.Integer()),  #  1<=j<=k
        namedtype.DefaultedNamedType('padAlgo', default_aria_pad_algo_null)
    )


class AriaOfbParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('j', univ.Integer()),  #  1<=j<=128
        namedtype.DefaultedNamedType('padAlgo', default_aria_pad_algo_null)
    )


class AriaCtrParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('j', univ.Integer()),  #  1<=j<=128
        namedtype.DefaultedNamedType('padAlgo', default_aria_pad_algo_null)
    )


class AriaCmacParameters(univ.Integer):
    pass


class AriaOcb2Parameters(univ.Integer):
    pass


class AriaGcmParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('s', univ.Integer()),
        namedtype.NamedType('t', univ.Integer())
    )


class AriaCcmParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('w', univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(
                2, 3, 4, 5, 6, 7, 8))),
        namedtype.NamedType('t', univ.Integer().subtype(
            subtypeSpec=constraint.SingleValueConstraint(
                32, 48, 64, 80, 96, 112, 128)))
    )


# Algorithm Identifiers

class AriaModeOfOperation(AlgorithmIdentifier):
    pass


aria128ecb = AlgorithmIdentifier()
aria128ecb['algorithm'] = id_aria128_ecb
aria128ecb['parameters'] = AriaEcbParameters() 


aria128cbc = AlgorithmIdentifier()
aria128cbc['algorithm'] = id_aria128_cbc
aria128cbc['parameters'] = AriaCbcParameters() 


aria128cfb = AlgorithmIdentifier()
aria128cfb['algorithm'] = id_aria128_cfb
aria128cfb['parameters'] = AriaCfbParameters() 


aria128ofb = AlgorithmIdentifier()
aria128ofb['algorithm'] = id_aria128_ofb
aria128ofb['parameters'] = AriaOfbParameters() 


aria128ctr = AlgorithmIdentifier()
aria128ctr['algorithm'] = id_aria128_ctr
aria128ctr['parameters'] = AriaCtrParameters() 


aria192ecb = AlgorithmIdentifier()
aria192ecb['algorithm'] = id_aria192_ecb
aria192ecb['parameters'] = AriaEcbParameters() 


aria192cbc = AlgorithmIdentifier()
aria192cbc['algorithm'] = id_aria192_cbc
aria192cbc['parameters'] = AriaCbcParameters() 


aria192cfb = AlgorithmIdentifier()
aria192cfb['algorithm'] = id_aria192_cfb
aria192cfb['parameters'] = AriaCfbParameters() 


aria192ofb = AlgorithmIdentifier()
aria192ofb['algorithm'] = id_aria192_ofb
aria192ofb['parameters'] = AriaOfbParameters() 


aria192ctr = AlgorithmIdentifier()
aria192ctr['algorithm'] = id_aria192_ctr
aria192ctr['parameters'] = AriaCtrParameters() 


aria256ecb = AlgorithmIdentifier()
aria256ecb['algorithm'] = id_aria256_ecb
aria256ecb['parameters'] = AriaEcbParameters() 


aria256cbc = AlgorithmIdentifier()
aria256cbc['algorithm'] = id_aria256_cbc
aria256cbc['parameters'] = AriaCbcParameters() 


aria256cfb = AlgorithmIdentifier()
aria256cfb['algorithm'] = id_aria256_cfb
aria256cfb['parameters'] = AriaCfbParameters() 


aria256ofb = AlgorithmIdentifier()
aria256ofb['algorithm'] = id_aria256_ofb
aria256ofb['parameters'] = AriaOfbParameters() 


aria256ctr = AlgorithmIdentifier()
aria256ctr['algorithm'] = id_aria256_ctr
aria256ctr['parameters'] = AriaCtrParameters() 


aria128cmac = AlgorithmIdentifier()
aria128cmac['algorithm'] = id_aria128_cmac
aria128cmac['parameters'] = AriaCmacParameters() 


aria192cmac = AlgorithmIdentifier()
aria192cmac['algorithm'] = id_aria192_cmac
aria192cmac['parameters'] = AriaCmacParameters() 


aria256cmac = AlgorithmIdentifier()
aria256cmac['algorithm'] = id_aria256_cmac
aria256cmac['parameters'] = AriaCmacParameters() 


aria128ocb2 = AlgorithmIdentifier()
aria128ocb2['algorithm'] = id_aria128_ocb2
aria128ocb2['parameters'] = AriaOcb2Parameters() 


aria192ocb2 = AlgorithmIdentifier()
aria192ocb2['algorithm'] = id_aria192_ocb2
aria192ocb2['parameters'] = AriaOcb2Parameters() 


aria256ocb2 = AlgorithmIdentifier()
aria256ocb2['algorithm'] = id_aria256_ocb2
aria256ocb2['parameters'] = AriaOcb2Parameters() 


aria128gcm = AlgorithmIdentifier()
aria128gcm['algorithm'] = id_aria128_gcm
aria128gcm['parameters'] = AriaGcmParameters() 


aria192gcm = AlgorithmIdentifier()
aria192gcm['algorithm'] = id_aria192_gcm
aria192gcm['parameters'] = AriaGcmParameters() 


aria256gcm = AlgorithmIdentifier()
aria256gcm['algorithm'] = id_aria256_gcm
aria256gcm['parameters'] = AriaGcmParameters() 


aria128ccm = AlgorithmIdentifier()
aria128ccm['algorithm'] = id_aria128_ccm
aria128ccm['parameters'] = AriaCcmParameters() 


aria192ccm = AlgorithmIdentifier()
aria192ccm['algorithm'] = id_aria192_ccm
aria192ccm['parameters'] = AriaCcmParameters() 


aria256ccm = AlgorithmIdentifier()
aria256ccm['algorithm'] = id_aria256_ccm
aria256ccm['parameters'] = AriaCcmParameters() 


aria128kw = AlgorithmIdentifier()
aria128kw['algorithm'] = id_aria128_kw


aria192kw = AlgorithmIdentifier()
aria192kw['algorithm'] = id_aria192_kw


aria256kw = AlgorithmIdentifier()
aria256kw['algorithm'] = id_aria256_kw


aria128kwp = AlgorithmIdentifier()
aria128kwp['algorithm'] = id_aria128_kwp


aria192kwp = AlgorithmIdentifier()
aria192kwp['algorithm'] = id_aria192_kwp


aria256kwp = AlgorithmIdentifier()
aria256kwp['algorithm'] = id_aria256_kwp


# Update the Algorithm Identifier map in rfc5280.py

_algorithmIdentifierMapUpdate = {
    id_aria128_ecb: AriaEcbParameters(),
    id_aria128_cbc: AriaCbcParameters(),
    id_aria128_cfb: AriaCfbParameters(),
    id_aria128_ofb: AriaOfbParameters(),
    id_aria128_ctr: AriaCtrParameters(),
    id_aria192_ecb: AriaEcbParameters(),
    id_aria192_cbc: AriaCbcParameters(),
    id_aria192_cfb: AriaCfbParameters(),
    id_aria192_ofb: AriaOfbParameters(),
    id_aria192_ctr: AriaCtrParameters(),
    id_aria256_ecb: AriaEcbParameters(),
    id_aria256_cbc: AriaCbcParameters(),
    id_aria256_cfb: AriaCfbParameters(),
    id_aria256_ofb: AriaOfbParameters(),
    id_aria256_ctr: AriaCtrParameters(),
    id_aria128_cmac: AriaCmacParameters(),
    id_aria192_cmac: AriaCmacParameters(),
    id_aria256_cmac: AriaCmacParameters(),
    id_aria128_ocb2: AriaOcb2Parameters(),
    id_aria192_ocb2: AriaOcb2Parameters(),
    id_aria256_ocb2: AriaOcb2Parameters(),
    id_aria128_gcm: AriaGcmParameters(),
    id_aria192_gcm: AriaGcmParameters(),
    id_aria256_gcm: AriaGcmParameters(),
    id_aria128_ccm: AriaCcmParameters(),
    id_aria192_ccm: AriaCcmParameters(),
    id_aria256_ccm: AriaCcmParameters(),
}

rfc5280.algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
