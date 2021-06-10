#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Using SCVP to convey Long-Term Evidence Records
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5276.txt
#

from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import univ

from pyasn1_alt_modules import rfc4998
from pyasn1_alt_modules import rfc5055

MAX = float('inf')


# Imports from RFC 4998 and RFC 5055

EvidenceRecord = rfc4998.EvidenceRecord

CertBundle = rfc5055.CertBundle


# Long-Term Evidence Records in SCVP

class EvidenceRecordWantBack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('targetWantBack', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('evidenceRecord', EvidenceRecord())
    )


class EvidenceRecordWantBacks(univ.SequenceOf):
    componentType = EvidenceRecordWantBack()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class EvidenceRecords(univ.SequenceOf):
    componentType = EvidenceRecord()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


id_swb = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 18))

id_swb_partial_cert_path = id_swb + (15,)

id_swb_ers_pkc_cert = id_swb + (16,)

id_swb_ers_best_cert_path = id_swb + (17,)

id_swb_ers_partial_cert_path = id_swb + (18,)

id_swb_ers_revocation_info = id_swb + (19,)

id_swb_ers_all = id_swb + (20,)


# Update the SCVP Want Back map in rfc5055.py.

_scvpWantBackMapUpdate = {
    id_swb_partial_cert_path: CertBundle(),
    id_swb_ers_pkc_cert: EvidenceRecord(),
    id_swb_ers_best_cert_path: EvidenceRecord(),
    id_swb_ers_partial_cert_path: EvidenceRecord(),
    id_swb_ers_revocation_info: EvidenceRecords(),
    id_swb_ers_all: EvidenceRecordWantBacks(),
}

rfc5055.scvpWantBackMap.update(_scvpWantBackMapUpdate)
