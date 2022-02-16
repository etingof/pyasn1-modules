#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# GOST Cipher Suites for TLS 1.2
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9189.txt
#

from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4357


#-- IMPORTS from RFC 9189

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


#-- IMPORTS from RFC 4357

Gost28147_89_Key = rfc4357.Gost28147_89_Key

Gost28147_89_MAC = rfc4357.Gost28147_89_MAC

Gost28147_89_EncryptedKey = rfc4357.Gost28147_89_EncryptedKey


#-- RFC 9189 -- Section 4.2.4.1 --

class GostKeyTransport(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyExp', univ.OctetString()),
        namedtype.NamedType('ephemeralPublicKey', SubjectPublicKeyInfo()),
        namedtype.OptionalNamedType('ukm', univ.OctetString())
    )


#-- RFC 9189 -- Section 4.2.4.2 --

class GostR3410_TransportParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptionParamSet', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('ephemeralPublicKey',
            SubjectPublicKeyInfo().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.NamedType('ukm', univ.OctetString())
    )


class GostR3410_KeyTransport(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('sessionEncryptedKey', Gost28147_89_EncryptedKey()),
        namedtype.OptionalNamedType('transportParameters',
            GostR3410_TransportParameters().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0)))
    )


class TLSGostKeyTransportBlob(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('keyBlob', GostR3410_KeyTransport())
    )
