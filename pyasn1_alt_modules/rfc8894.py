#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2020-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Simple Certificate Enrolment Protocol
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8894.txt
#

from pyasn1.type import univ
from pyasn1.type import namedtype

from pyasn1_alt_modules import rfc5280


# Object Identifiers
   
id_VeriSign = univ.ObjectIdentifier((2, 16, 840, 1, 113733))

id_pki = id_VeriSign + (1, )

id_attributes = id_pki + (9, )

id_transactionID = id_attributes + (7, )

id_messageType = id_attributes + (2, )

id_pkiStatus = id_attributes + (3, )

id_failInfo = id_attributes + (4, )

id_senderNonce = id_attributes + (5, )

id_recipientNonce  = id_attributes + (6, )

id_scep = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 24))

id_scep_failInfoText = id_scep + (1, )   


# Structures

class IssuerAndSubject(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', rfc5280.Name()),
        namedtype.NamedType('subject', rfc5280.Name())
    )
