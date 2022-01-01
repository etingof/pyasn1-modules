#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to add a map for use with opentypes.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Protecting Multiple Contents with the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4073.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


# Content Collection Content Type and Object Identifier

id_ct_contentCollection = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.19')

class ContentCollection(univ.SequenceOf):
    pass

ContentCollection.componentType = rfc5652.ContentInfo()
ContentCollection.sizeSpec = constraint.ValueSizeConstraint(1, MAX)


# Content With Attributes Content Type and Object Identifier

id_ct_contentWithAttrs = univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.20')

class ContentWithAttributes(univ.Sequence):
    pass

ContentWithAttributes.componentType = namedtype.NamedTypes(
    namedtype.NamedType('content', rfc5652.ContentInfo()),
    namedtype.NamedType('attrs', univ.SequenceOf(
        componentType=rfc5652.Attribute()).subtype(
            sizeSpec=constraint.ValueSizeConstraint(1, MAX)))
)


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_contentCollection: ContentCollection(),
    id_ct_contentWithAttrs: ContentWithAttributes(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
