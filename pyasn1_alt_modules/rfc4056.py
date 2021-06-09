#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RSASSA-PSS Signature Algorithm in CMS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4056.txt
#

from pyasn1_alt_modules import rfc4055


# Imports from RFC 4055

rsaEncryption = rfc4055.rsaEncryption

id_RSASSA_PSS = rfc4055.id_RSASSA_PSS

RSAPublicKey = rfc4055.RSAPublicKey

RSASSA_PSS_params = rfc4055.RSASSA_PSS_params

rSASSA_PSS_Default_Params = rfc4055.rSASSA_PSS_Default_Params

rSASSA_PSS_Default_Identifier = rfc4055.rSASSA_PSS_Default_Identifier

rSASSA_PSS_SHA224_Params = rfc4055.rSASSA_PSS_SHA224_Params

rSASSA_PSS_SHA224_Identifier = rfc4055.rSASSA_PSS_SHA224_Identifier

rSASSA_PSS_SHA256_Params = rfc4055.rSASSA_PSS_SHA256_Params

rSASSA_PSS_SHA256_Identifier = rfc4055.rSASSA_PSS_SHA256_Identifier

rSASSA_PSS_SHA384_Params = rfc4055.rSASSA_PSS_SHA384_Params

rSASSA_PSS_SHA384_Identifier = rfc4055.rSASSA_PSS_SHA384_Identifier

rSASSA_PSS_SHA512_Params = rfc4055.rSASSA_PSS_SHA512_Params

rSASSA_PSS_SHA512_Identifier = rfc4055.rSASSA_PSS_SHA512_Identifier


# The the Algorithm Identifier map in rfc5280 is updated by
# importing rfc4055.  As a reminder it includes:
#
# _algorithmIdentifierMapUpdate = {
#     id_RSASSA_PSS: RSASSA_PSS_params(),
# }
# 
# rfc5280.algorithmIdentifierMap.update(_algorithmIdentifierMapUpdate)
