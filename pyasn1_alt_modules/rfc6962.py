#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Certificate Transparency
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc6962.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


class SignedCertificateTimestampList(univ.OctetString):
    pass


id_ce_embeddedSCT = univ.ObjectIdentifier('1.3.6.1.4.1.11129.2.4.2')


id_ce_criticalPoison = univ.ObjectIdentifier('1.3.6.1.4.1.11129.2.4.3')


id_kp_precertificateSigning = univ.ObjectIdentifier('1.3.6.1.4.1.11129.2.4.4')


id_pkix_ocsp_SCT = univ.ObjectIdentifier('1.3.6.1.4.1.11129.2.4.5')


# Update the Extension Map in rfc5280.py.
# Note that rfc6960.py also uses this same map for OCSP extensions.
# The id_ce_criticalPoison OID is not automatically added to the map
# because normal relying parties are supposed to reject certificates
# that contain it.

_certificateExtensionsMapUpdate = {
    id_ce_embeddedSCT: SignedCertificateTimestampList(),
    # id_ce_criticalPoison: univ.Null(""),
    id_pkix_ocsp_SCT: SignedCertificateTimestampList(),
}

rfc5280.certificateExtensionsMap.update(_certificateExtensionsMapUpdate)
