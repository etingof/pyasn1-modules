#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Experiment for Hash Functions with Parameters in the CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6210.txt
#

from pyasn1.type import constraint
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

algorithmIdentifierMap = opentypemap.get('algorithmIdentifierMap')


# MD5-XOR Experimental Message Digest Algorithm

id_alg_MD5_XOR_EXPERIMENT = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.13')


class MD5_XOR_EXPERIMENT(univ.OctetString):
    subtypeSpec = constraint.ValueSizeConstraint(64, 64)


mda_xor_md5_EXPERIMENT = rfc5280.AlgorithmIdentifier()
mda_xor_md5_EXPERIMENT['algorithm'] = id_alg_MD5_XOR_EXPERIMENT
mda_xor_md5_EXPERIMENT['parameters'] = MD5_XOR_EXPERIMENT()


# Update the Algorithm Identifier Map and the S/MIME Capability Map

_algorithmIdentifierMapUpdate = {
    id_alg_MD5_XOR_EXPERIMENT: MD5_XOR_EXPERIMENT(),
}

algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
