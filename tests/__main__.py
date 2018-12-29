#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2018, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.test_rfc2314.suite',
     'tests.test_rfc2315.suite',
     'tests.test_rfc2437.suite',
     'tests.test_rfc2459.suite',
     'tests.test_rfc2511.suite',
     'tests.test_rfc2560.suite',
     'tests.test_rfc2986.suite',
     'tests.test_rfc4210.suite',
     'tests.test_rfc5208.suite',
     'tests.test_rfc5280.suite',
     'tests.test_rfc5652.suite',]
)


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite)
