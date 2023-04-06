#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# PkiPath as used in TLS Extensions
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc3546.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# PkiPath ::= SEQUENCE OF Certificate

class PkiPath(univ.SequenceOf):
    componentType = rfc5280.Certificate()
