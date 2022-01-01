#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Route Origin Authorizations (ROAs)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6482.txt
# https://www.rfc-editor.org/errata/eid5881
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


id_ct_routeOriginAuthz = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.24')


class ASID(univ.Integer):
    pass


class IPAddress(univ.BitString):
    pass


class ROAIPAddress(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('address', IPAddress()),
        namedtype.OptionalNamedType('maxLength', univ.Integer())
    )


class ROAIPAddressFamily(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('addressFamily',
            univ.OctetString().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(2, 3))),
        namedtype.NamedType('addresses',
            univ.SequenceOf(componentType=ROAIPAddress()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


class RouteOriginAttestation(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version',
            univ.Integer().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0)).subtype(value=0)),
        namedtype.NamedType('asID', ASID()),
        namedtype.NamedType('ipAddrBlocks',
            univ.SequenceOf(componentType=ROAIPAddressFamily()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_routeOriginAuthz: RouteOriginAttestation(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
