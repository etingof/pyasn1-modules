#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# RPKI Ghostbusters Record
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6493.txt
#

from pyasn1.type import univ


# Content Type for Ghostbusters Records

id_ct_rpkiGhostbusters =univ.ObjectIdentifier('1.2.840.113549.1.9.16.1.35')


# There is no need for an entry in the CMS Content Type Map because
# the vCard is carried directly in the CMS eContent OCTET STRING.
