#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import pickle
import sys
import unittest

from pyasn1.type import tag
from pyasn1.type import univ

from pyasn1_alt_modules import addon


class RelativeOID(unittest.TestCase):
    def testStr(self):
        assert str(addon.RelativeOID((1, 3, 6))) == '1.3.6', 'str() fails'

    def testRepr(self):
        assert '1.3.6' in repr(addon.RelativeOID('1.3.6'))

    def testEq(self):
        assert addon.RelativeOID((1, 3, 6)) == (1, 3, 6), '__cmp__() fails'

    def testAdd(self):
        assert addon.RelativeOID((1, 3)) + (6,) == (1, 3, 6), '__add__() fails'

    def testRadd(self):
        assert (1,) + addon.RelativeOID((3, 6)) == (1, 3, 6), '__radd__() fails'

    def testLen(self):
        assert len(addon.RelativeOID((1, 3))) == 2, '__len__() fails'

    def testPrefix(self):
        o = addon.RelativeOID('1.3.6')
        assert o.isPrefixOf((1, 3, 6)), 'isPrefixOf() fails'
        assert o.isPrefixOf((1, 3, 6, 1)), 'isPrefixOf() fails'
        assert not o.isPrefixOf((1, 3)), 'isPrefixOf() fails'

    def testInput1(self):
        assert addon.RelativeOID('1.3.6') == (1, 3, 6), 'prettyIn() fails'

    def testInput2(self):
        assert addon.RelativeOID((1, 3, 6)) == (1, 3, 6), 'prettyIn() fails'

    def testInput3(self):
        assert addon.RelativeOID(addon.RelativeOID('1.3') + (6,)) == (1, 3, 6), 'prettyIn() fails'

    def testUnicode(self):
        s = '1.3.6'
        if sys.version_info[0] < 3:
            s = s.decode()
        assert addon.RelativeOID(s) == (1, 3, 6), 'unicode init fails'

    def testTag(self):
        assert addon.RelativeOID().tagSet == tag.TagSet(
            (),
            tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x0d)
        )

    def testContains(self):
        s = addon.RelativeOID('1.3.6.1234.99999')
        assert 1234 in s
        assert 4321 not in s

    def testStaticDef(self):

        class RelOID(univ.ObjectIdentifier):
            pass

        assert str(RelOID((1, 3, 6))) == '1.3.6'


class RelativeOIDPicklingTestCase(unittest.TestCase):

    def testSchemaPickling(self):
        old_asn1 = addon.RelativeOID()
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert type(new_asn1) == addon.RelativeOID
        assert old_asn1.isSameTypeWith(new_asn1)

    def testValuePickling(self):
        old_asn1 = addon.RelativeOID('2.3.1.1.2')
        serialised = pickle.dumps(old_asn1)
        assert serialised
        new_asn1 = pickle.loads(serialised)
        assert new_asn1 == (2, 3, 1, 1, 2)


suite = unittest.TestLoader().loadTestsFromModule(sys.modules[__name__])

if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
