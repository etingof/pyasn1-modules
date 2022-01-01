#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Multiple Signatures in Cryptographic Message Syntax (CMS)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5752.txt
# https://www.rfc-editor.org/errata/eid4444
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5035
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsAttributesMap = opentypemap.get('cmsAttributesMap')


class SignAttrsHash(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algID', rfc5652.DigestAlgorithmIdentifier()),
        namedtype.NamedType('hash', univ.OctetString())
    )


class MultipleSignatures(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bodyHashAlg', rfc5652.DigestAlgorithmIdentifier()),
        namedtype.NamedType('signAlg', rfc5652.SignatureAlgorithmIdentifier()),
        namedtype.NamedType('signAttrsHash', SignAttrsHash()),
        namedtype.OptionalNamedType('cert', rfc5035.ESSCertIDv2())
    )


id_aa_multipleSignatures = univ.ObjectIdentifier('1.2.840.113549.1.9.16.2.51')


# Update the CMS Attribute Types Map

_cmsAttributesMapUpdate = {
    id_aa_multipleSignatures: MultipleSignatures(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)
