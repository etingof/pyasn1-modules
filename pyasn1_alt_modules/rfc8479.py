#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Storing Validation Parameters in PKCS#8
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8479.txt
#

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import opentypemap

cmsAttributesMap = opentypemap.get('cmsAttributesMap')


id_attr_validation_parameters = univ.ObjectIdentifier('1.3.6.1.4.1.2312.18.8.1')


class ValidationParams(univ.Sequence):
    pass

ValidationParams.componentType = namedtype.NamedTypes(
    namedtype.NamedType('hashAlg', univ.ObjectIdentifier()),
    namedtype.NamedType('seed', univ.OctetString())
)


at_validation_parameters = rfc5652.Attribute()
at_validation_parameters['attrType'] = id_attr_validation_parameters
at_validation_parameters['attrValues'][0] = ValidationParams()


# Update the CMS Attributes Map

_cmsAttributesMapUpdate = {
    id_attr_validation_parameters: ValidationParams(),
}

cmsAttributesMap.update(_cmsAttributesMapUpdate)
