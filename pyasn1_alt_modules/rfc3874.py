#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Identifiers for SHA-224
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3874.txt
# https://www.rfc-editor.org/rfc/rfc5990.txt
#

from pyasn1_alt_modules import rfc5990


# Import from RFC 4055

id_sha224 = rfc5990.id_sha224


# The Algorithm Identifier map is updated by importing rfc5990.
# To save looking it up, the map is updated with this entry:
#
# _algorithmIdentifierMapUpdate = {
#     id_sha224: univ.Null(),
# }
