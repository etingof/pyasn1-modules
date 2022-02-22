#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley.
#
# Copyright (c) 2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# PKCS #5: Password-Based Cryptography Specification, Version 2.0
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc2898.txt
# https://www.rfc-editor.org/rfc/rfc8018.txt
#

from pyasn1_alt_modules import rfc8018


# PKCS#5 Version 2.1 is backward compatible with PKCS#5 Version 2.0,
# so all of the definitions can be imported from the newer document.

rsadsi = rfc8018.rsadsi

pkcs = rfc8018.pkcs

digestAlgorithm = rfc8018.digestAlgorithm

encryptionAlgorithm = rfc8018.encryptionAlgorithm

pkcs_5 = rfc8018.pkcs_5

id_PBKDF2 = rfc8018.id_PBKDF2

PBKDF2_params = rfc8018.PBKDF2_params

id_hmacWithSHA1 = rfc8018.id_hmacWithSHA1

algid_hmacWithSHA1 = rfc8018.algid_hmacWithSHA1

pbeWithMD2AndDES_CBC = rfc8018.pbeWithMD2AndDES_CBC

pbeWithMD2AndRC2_CBC = rfc8018.pbeWithMD2AndRC2_CBC

pbeWithMD5AndDES_CBC = rfc8018.pbeWithMD5AndDES_CBC

pbeWithMD5AndRC2_CBC = rfc8018.pbeWithMD5AndRC2_CBC

pbeWithSHA1AndDES_CBC = rfc8018.pbeWithSHA1AndDES_CBC

pbeWithSHA1AndRC2_CBC = rfc8018.pbeWithSHA1AndRC2_CBC

PBEParameter = rfc8018.PBEParameter

id_PBES2 = rfc8018.id_PBES2

PBES2_params = rfc8018.PBES2_params

id_PBMAC1 = rfc8018.id_PBMAC1

PBMAC1_params = rfc8018.PBMAC1_params

desCBC = rfc8018.desCBC

des_EDE3_CBC = rfc8018.des_EDE3_CBC

rc2CBC = rfc8018.rc2CBC

RC2_CBC_Parameter = rfc8018.RC2_CBC_Parameter

rc5_CBC_PAD = rfc8018.rc5_CBC_PAD

RC5_CBC_Parameters = rfc8018.RC5_CBC_Parameters
