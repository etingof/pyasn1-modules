#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Profile for X.509 PKIX Resource Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6487.txt
#

from pyasn1.type import univ

id_pkix = univ.ObjectIdentifier('1.3.6.1.5.5.7')

id_ad = id_pkix + (48, )

id_ad_rpkiManifest = id_ad + (10, )
id_ad_signedObject = id_ad + (11, )
