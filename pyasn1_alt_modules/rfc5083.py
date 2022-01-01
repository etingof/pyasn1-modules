# This file is being contributed to of pyasn1-modules software.
#
# Created by Russ Housley without assistance from the asn1ate tool.
# Modified by Russ Housley to add a map for use with opentypes and
#   simplify the code for the object identifier assignment.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2018-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
#  Authenticated-Enveloped-Data for the Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5083.txt

from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


# CMS Authenticated-Enveloped-Data Content Type

id_ct_authEnvelopedData = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.23')

class AuthEnvelopedData(univ.Sequence):
    pass

AuthEnvelopedData.componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', rfc5652.CMSVersion()),
    namedtype.OptionalNamedType('originatorInfo', rfc5652.OriginatorInfo().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))),
    namedtype.NamedType('recipientInfos', rfc5652.RecipientInfos()),
    namedtype.NamedType('authEncryptedContentInfo', rfc5652.EncryptedContentInfo()),
    namedtype.OptionalNamedType('authAttrs', rfc5652.AuthAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.NamedType('mac', rfc5652.MessageAuthenticationCode()),
    namedtype.OptionalNamedType('unauthAttrs', rfc5652.UnauthAttributes().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
)


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_authEnvelopedData: AuthEnvelopedData(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
