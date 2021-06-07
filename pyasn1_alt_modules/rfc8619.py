#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2019-2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Algorithm Identifiers for HKDF
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc8619.txt
#

from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280


# Object Identifiers

id_alg_hkdf_with_sha256 = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.28')


id_alg_hkdf_with_sha384 = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.29')


id_alg_hkdf_with_sha512 = univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.30')


# Key Derivation Algorithm Identifiers

kda_hkdf_with_sha256 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha256['algorithm'] = id_alg_hkdf_with_sha256
# kda_hkdf_with_sha256['parameters'] are absent


kda_hkdf_with_sha384 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha384['algorithm'] = id_alg_hkdf_with_sha384
# kda_hkdf_with_sha384['parameters'] are absent


kda_hkdf_with_sha512 = rfc5280.AlgorithmIdentifier()
kda_hkdf_with_sha512['algorithm'] = id_alg_hkdf_with_sha512
# kda_hkdf_with_sha512['parameters'] are absent
