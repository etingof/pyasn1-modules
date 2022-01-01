#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest

from pyasn1_alt_modules import opentypemap


class OpenTypeMapManagerTestCase(unittest.TestCase):

    def testOpenTypeMap(self):
        firstMap = {
            'mapKey1': 'mapValue1init',
            'mapKey2': 'mapValue2',
        }

        secondMap = {
            'mapKey1': 'mapValue1new',
            'mapKey3': 'mapValue3',
        }

        opentypemap.get('testMap').update(firstMap)
        opentypemap.get('testMap').update(secondMap)

        self.assertEqual(3, len(opentypemap.get('testMap')))
        self.assertIn('mapKey1', opentypemap.get('testMap'))
        self.assertIn('mapKey2', opentypemap.get('testMap'))
        self.assertIn('mapKey3', opentypemap.get('testMap'))
        self.assertEqual('mapValue1new', opentypemap.get('testMap')['mapKey1'])


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
