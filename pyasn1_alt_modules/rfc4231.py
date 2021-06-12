#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2020-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Identifiers for HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384,
#   and HMAC-SHA-512
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4231.txt
# https://www.rfc-editor.org/rfc/rfc8018.txt
#

from pyasn1_alt_modules import rfc8018


# The HMAC object identifiers are already defined in RFC 8018

id_hmacWithSHA224 = rfc8018.id_hmacWithSHA224

id_hmacWithSHA256 = rfc8018.id_hmacWithSHA256

id_hmacWithSHA384 = rfc8018.id_hmacWithSHA384

id_hmacWithSHA512 = rfc8018.id_hmacWithSHA512


# The Algorithm Identifier map is updated by importing rfc8018.
# To save looking it up, the map is updated with these entries:
#  _algorithmIdentifierMapUpdate = {
#     id_hmacWithSHA224: univ.Null(),
#     id_hmacWithSHA256: univ.Null(),
#     id_hmacWithSHA384: univ.Null(),
#     id_hmacWithSHA512: univ.Null(),
#  }
