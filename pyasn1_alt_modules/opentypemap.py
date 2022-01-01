#
# This file is part of pyasn1-alt-modules software.
#
# This very simple manager for opentype maps allows various related
# ASN.1 modules to share the same maps.
#
# Created by Russ Housley
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#

from collections import defaultdict

map_of_opentype_maps = defaultdict(dict)


def get (map_name):
    """Get the named opentype map, creating an empty one if needed."""
    return map_of_opentype_maps[map_name]
