#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Cryptographic Algorithms for GOST R 34.10-2012 and GOST R 34.11-2012
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc7836.txt
#

from pyasn1.type import namedtype
from pyasn1.type import univ


class GOST3410_2012_CanonicalFormParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('p', univ.Integer()),
        namedtype.NamedType('a', univ.Integer()),
        namedtype.NamedType('b', univ.Integer()),
        namedtype.NamedType('m', univ.Integer()),
        namedtype.NamedType('q', univ.Integer()),
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer())
    )


class GOST3410_2012_TwistedEdwardsFormParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('p', univ.Integer()),
        namedtype.NamedType('a', univ.Integer()),
        namedtype.NamedType('b', univ.Integer()),
        namedtype.NamedType('e', univ.Integer()),
        namedtype.NamedType('d', univ.Integer()),
        namedtype.NamedType('m', univ.Integer()),
        namedtype.NamedType('q', univ.Integer()),
        namedtype.NamedType('x', univ.Integer()),
        namedtype.NamedType('y', univ.Integer()),
        namedtype.NamedType('u', univ.Integer()),
        namedtype.NamedType('v', univ.Integer())
    )


id_tc26_gost_28147_param_Z = univ.ObjectIdentifier('1.2.643.7.1.2.5.1.1')


id_tc26_gost_3410_12_512_paramSetA = univ.ObjectIdentifier('1.2.643.7.1.2.1.2.1')


id_tc26_gost_3410_12_512_paramSetB = univ.ObjectIdentifier('1.2.643.7.1.2.1.2.2')


id_tc26_gost_3410_2012_256_paramSetA = univ.ObjectIdentifier('1.2.643.7.1.2.1.1.1')


id_tc26_gost_3410_2012_512_paramSetC = univ.ObjectIdentifier('1.2.643.7.1.2.1.2.3')


id_tc26_hmac_gost_3411_12_256 = univ.ObjectIdentifier('1.2.643.7.1.1.4.1')


id_tc26_hmac_gost_3411_12_512 = univ.ObjectIdentifier('1.2.643.7.1.1.4.2')
