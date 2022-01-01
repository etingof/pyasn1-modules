#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Delay-Tolerant Networking TCP Convergence Layer Version 4
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9174.txt
#

from pyasn1.type import char
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import opentypemap

otherNamesMap = opentypemap.get('otherNamesMap')
 
id_pkix = rfc5280.id_pkix

id_kp = id_pkix + (3, )

id_on = id_pkix + (8, )


# DTN Bundle EID

id_on_bundleEID = id_on + (11, )
   

class BundleEID(char.IA5String):
    pass


on_BundleEID = rfc5280.AnotherName()
on_BundleEID['type-id'] = id_on_bundleEID
on_BundleEID['value'] = BundleEID()


# Extended Key Usage for bundle security

id_kp_bundleSecurity = id_kp + (35, )


# Update the Other Names Map

_otherNamesMapUpdate = {
    id_on_bundleEID: BundleEID(),
}

otherNamesMap.update(_otherNamesMapUpdate)
