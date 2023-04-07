#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley from rfc3709.py and rfc6710.py.
#
# Copyright (c) 2023, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Logotypes in X.509 Certificates
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc9399.txt
#

from pyasn1_alt_modules import rfc3709
from pyasn1_alt_modules import rfc6170


# Types defined in RFC 3709

HashAlgAndValue = rfc3709.HashAlgAndValue

LogotypeDetails = rfc3709.LogotypeDetails

LogotypeAudioInfo = rfc3709.LogotypeAudioInfo

LogotypeAudio = rfc3709.LogotypeAudio

LogotypeImageType = rfc3709.LogotypeImageType

LogotypeImageResolution = rfc3709.LogotypeImageResolution

LogotypeImageInfo = rfc3709.LogotypeImageInfo

LogotypeImage = rfc3709.LogotypeImage

LogotypeData = rfc3709.LogotypeData

LogotypeReference = rfc3709.LogotypeReference

LogotypeInfo = rfc3709.LogotypeInfo

OtherLogotypeInfo = rfc3709.OtherLogotypeInfo

LogotypeExtn = rfc3709.LogotypeExtn


# Object identifiers from RFC 3709 and RFC 6170

id_pe_logotype = rfc3709.id_pe_logotype

id_logo_background = rfc3709.id_logo_background

id_logo_loyalty = rfc3709.id_logo_loyalty

id_logo_certImage = rfc6170.id_logo_certImage


# The Certificate Extensions Map is updated by importing rfc3709
