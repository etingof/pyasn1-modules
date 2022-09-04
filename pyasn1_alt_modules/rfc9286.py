#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley from rfc6486.py, adding the permitted alphabet
#   constraint to the file name.  Note that RFC 9286 obsoletes RFC 6486.
# Modified by Russ Housley to apply eid7118.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Manifests
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9286.txt
# https://www.rfc-editor.org/errata/eid7118
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import tag
from pyasn1.type import useful
from pyasn1.type import univ

from pyasn1_alt_modules import opentypemap

cmsContentTypesMap = opentypemap.get('cmsContentTypesMap')

MAX = float('inf')


id_smime = univ.ObjectIdentifier('1.2.840.113549.1.9.16')

id_ct = id_smime + (1, )

id_ct_rpkiManifest = id_ct + (26, )


class FileAndHash(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('file', char.IA5String().subtype(subtypeSpec=
            constraint.PermittedAlphabetConstraint('a', 'b', 'c', 'd', 'e',
                'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C',
                'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
                'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '0',
                '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_', '.'))),
        namedtype.NamedType('hash', univ.BitString())
    )


class Manifest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('version',
            univ.Integer().subtype(explicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0)).subtype(value=0)),
        namedtype.NamedType('manifestNumber',
            univ.Integer().subtype(
                subtypeSpec=constraint.ValueRangeConstraint(0, MAX))),
        namedtype.NamedType('thisUpdate',
            useful.GeneralizedTime()),
        namedtype.NamedType('nextUpdate',
            useful.GeneralizedTime()),
        namedtype.NamedType('fileHashAlg',
            univ.ObjectIdentifier()),
        namedtype.NamedType('fileList',
            univ.SequenceOf(componentType=FileAndHash()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


# Update the CMS Content Types Map

_cmsContentTypesMapUpdate = {
    id_ct_rpkiManifest: Manifest(),
}

cmsContentTypesMap.update(_cmsContentTypesMapUpdate)
