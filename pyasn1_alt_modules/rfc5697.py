# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
# Modified by Russ Housley to import SCVP-related structures from RFC 5055,
#   which did not exist at the time this module was first written.  Also,
#   include the opentypemap manager.
#
# Copyright (c) 2019-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Other Certificates Extension
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5697.txt

from pyasn1.type import namedtype
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc4055
from pyasn1_alt_modules import rfc5055
from pyasn1_alt_modules import opentypemap

certificateExtensionsMap = opentypemap.get('certificateExtensionsMap')


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

CertificateSerialNumber = rfc5280.CertificateSerialNumber

GeneralNames = rfc5280.GeneralNames


# Imports from RFC 4055

id_sha1 = rfc4055.id_sha1


# Imports from RFC 5055

SCVPIssuerSerial = rfc5055.SCVPIssuerSerial

sha1_alg_id = rfc5055.algid_SHA1

SCVPCertID = rfc5055.SCVPCertID


# Other Certificates Extension

id_pe_otherCerts = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 1, 19,))

class OtherCertificates(univ.SequenceOf):
    componentType = SCVPCertID()


# Update the Certificate Extension Map

_certificateExtensionsMapUpdate = {
    id_pe_otherCerts: OtherCertificates(),
}

certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
