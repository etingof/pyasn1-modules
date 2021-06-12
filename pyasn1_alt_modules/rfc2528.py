#
# This file is part of pyasn1-modules.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Identifiers for the Key Exchange Algorithm (KEA)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc2528.txt
# https://www.rfc-editor.org/rfc/rfc3279.txt
#

from pyasn1_alt_modules import rfc3279


# The KEA object identifier is defined in RFC 3279

id_keyExchangeAlgorithm = rfc3279.id_keyExchangeAlgorithm


# The KEA parameters structure is defined in RFC 3279

KEA_Parms_Id = rfc3279.KEA_Parms_Id


# The Algorithm Identifier map is updated by importing rfc3279.
# To save looking it up, the map is updated with this entry:
#
# _algorithmIdentifierMapUpdate = {
#     id_keyExchangeAlgorithm: KEA_Parms_Id(),
# }
