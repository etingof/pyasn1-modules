#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Triple-DES and RC2 Key Wrapping 
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3217.txt
# https://www.rfc-editor.org/rfc/rfc3370.txt
# https://www.rfc-editor.org/rfc/rfc5990.txt
#

from pyasn1_alt_modules import rfc3370
from pyasn1_alt_modules import rfc5990


# Imports from RFC 3370

id_alg_CMSRC2wrap = rfc3370.id_alg_CMSRC2wrap

RC2ParameterVersion = rfc3370.RC2ParameterVersion

RC2wrapParameter = rfc3370.RC2wrapParameter


# Imports from RFC 5990

id_alg_CMS3DESwrap = rfc5990.id_alg_CMS3DESwrap


# The update to the Algorithm Identifier map is already handled
# by importing rfc3370 and rfc5990. To save looking it up, the
# map is updated with these entries:
#
# _algorithmIdentifierMapUpdate = {
#     id_alg_CMS3DESwrap: univ.Null(),
#     id_alg_CMSRC2wrap: RC2wrapParameter(),
# }
