#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2019, Ilya Etingof <etingof@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
try:
    import unittest2 as unittest

except ImportError:
    import unittest

suite = unittest.TestLoader().loadTestsFromNames(
    ['tests.test_pem.suite',
     'tests.test_rfc2314.suite',
     'tests.test_rfc2315.suite',
     'tests.test_rfc2437.suite',
     'tests.test_rfc2459.suite',
     'tests.test_rfc2511.suite',
     'tests.test_rfc2560.suite',
     'tests.test_rfc2634.suite',
     'tests.test_rfc2985.suite',
     'tests.test_rfc2986.suite',
     'tests.test_rfc3161.suite',
     'tests.test_rfc3274.suite',
     'tests.test_rfc3447.suite',
     'tests.test_rfc3560.suite',
     'tests.test_rfc3565.suite',
     'tests.test_rfc3709.suite',
     'tests.test_rfc3770.suite',
     'tests.test_rfc3779.suite',
     'tests.test_rfc4055.suite',
     'tests.test_rfc4073.suite',
     'tests.test_rfc4108.suite',
     'tests.test_rfc4210.suite',
     'tests.test_rfc5035.suite',
     'tests.test_rfc5083.suite',
     'tests.test_rfc5084.suite',
     'tests.test_rfc5208.suite',
     'tests.test_rfc5280.suite',
     'tests.test_rfc5480.suite',
     'tests.test_rfc5649.suite',
     'tests.test_rfc5652.suite',
     'tests.test_rfc5751.suite',
     'tests.test_rfc5914.suite',
     'tests.test_rfc5915.suite',
     'tests.test_rfc5934.suite',
     'tests.test_rfc5940.suite',
     'tests.test_rfc5958.suite',
     'tests.test_rfc5990.suite',
     'tests.test_rfc6010.suite',
     'tests.test_rfc6019.suite',
     'tests.test_rfc6031.suite',
     'tests.test_rfc6032.suite',
     'tests.test_rfc6210.suite',
     'tests.test_rfc6211.suite',
     'tests.test_rfc7030.suite',
     'tests.test_rfc7191.suite',
     'tests.test_rfc7292.suite',
     'tests.test_rfc7296.suite',
     'tests.test_rfc7773.suite',
     'tests.test_rfc7894.suite',
     'tests.test_rfc7906.suite',
     'tests.test_rfc7914.suite',
     'tests.test_rfc8017.suite',
     'tests.test_rfc8018.suite',
     'tests.test_rfc8103.suite',
     'tests.test_rfc8209.suite',
     'tests.test_rfc8226.suite',
     'tests.test_rfc8358.suite',
     'tests.test_rfc8360.suite',
     'tests.test_rfc8398.suite',
     'tests.test_rfc8410.suite',
     'tests.test_rfc8418.suite',
     'tests.test_rfc8419.suite',
     'tests.test_rfc8479.suite',
     'tests.test_rfc8494.suite',
     'tests.test_rfc8520.suite',
     'tests.test_rfc8619.suite',
     'tests.test_rfc8649.suite']
)


if __name__ == '__main__':
    import sys

    result = unittest.TextTestRunner(verbosity=2).run(suite)
    sys.exit(not result.wasSuccessful())
