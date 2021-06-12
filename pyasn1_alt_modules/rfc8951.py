#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2020-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Enrollment over Secure Transport (EST) Clarifications
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8951.txt
#

from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc7030


# Imports from RFC 5652

Attribute = rfc5652.Attribute


# Imports from RFC 7030

id_aa_asymmDecryptKeyID = rfc7030.id_aa_asymmDecryptKeyID

AsymmetricDecryptKeyIdentifier = rfc7030.AsymmetricDecryptKeyIdentifier

AttrOrOID = rfc7030.AttrOrOID

CsrAttrs = rfc7030.CsrAttrs


# Asymmetric Decrypt Key Identifier Attribute

aa_asymmDecryptKeyID = Attribute()
aa_asymmDecryptKeyID['attrType'] = id_aa_asymmDecryptKeyID
aa_asymmDecryptKeyID['attrValues'][0] = AsymmetricDecryptKeyIdentifier()


# Note that the update CMS Attribute Map is handled by importing rfc7030
