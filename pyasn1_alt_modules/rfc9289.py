#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Extended Key Usage values for RPC over TLS
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9289.txt
#

from pyasn1.type import univ


id_kp = univ.ObjectIdentifier('1.3.6.1.5.5.7.3')

id_kp_rpcTLSClient = id_kp + (33,)

id_kp_rpcTLSServer = id_kp + (34,)
