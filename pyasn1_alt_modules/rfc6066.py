#
# This file is part of pyasn1-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://snmplabs.com/pyasn1/license.html
#
# PkiPath for the pkix-pkipath media type
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6066.txt
#

from pyasn1_modules import rfc5280

from pyasn1.type import constraint
from pyasn1.type import univ

MAX = float('inf')


class PkiPath(univ.SequenceOf):
    componentType = rfc5280.Certificate()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)
