#!/usr/bin/env python
#
# This file is part of pyasn1-alt-modules software.
#
# Copyright (c) 2005-2020, Ilya Etingof <etingof@gmail.com>
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
import sys
import unittest


doclines = """A alternate collection of ASN.1-based protocols modules.

   A collection of ASN.1 modules expressed in form of pyasn1 classes.
   Includes protocols PDUs definition (SNMP, LDAP, OCSP, and so on) as 
   various data structures (X.509, PKCS, and so on).
"""

doclines = [x.strip() for x in doclines.split('\n') if x]


classifiers = """\
Development Status :: 5 - Production/Stable
Environment :: Console
Intended Audience :: Developers
Intended Audience :: Education
Intended Audience :: Information Technology
Intended Audience :: System Administrators
Intended Audience :: Telecommunications Industry
License :: OSI Approved :: BSD License
Natural Language :: English
Operating System :: OS Independent
Programming Language :: Python :: 2
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Programming Language :: Python :: 3.7
Programming Language :: Python :: 3.8
Topic :: Communications
Topic :: System :: Monitoring
Topic :: System :: Networking :: Monitoring
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_setuptools():
    print("""
   Error: You need setuptools Python package!

   It's very easy to install it, just type (as root on Linux):

   wget https://bitbucket.org/pypa/setuptools/raw/bootstrap/ez_setup.py
   python ez_setup.py

   Then you could make eggs from this package.
""")


if sys.version_info[:2] < (2, 7):
    print("ERROR: this package requires Python 2.7 or later!")
    sys.exit(1)

try:
    from setuptools import setup, Command

    params = {
        'zip_safe': True,
        'install_requires': ['pyasn1>=0.4.7']
    }

except ImportError:
    for arg in sys.argv:
        if 'egg' in arg:
            howto_install_setuptools()
            sys.exit(1)

    from distutils.core import setup, Command

    params = {
        'requires': ['pyasn1>=0.4.7']
    }

params.update(
    {'name': 'pyasn1-alt-modules',
     'version': open('pyasn1_alt_modules/__init__.py').read().split('\'')[1],
     'description': doclines[0],
     'long_description': ' '.join(doclines[1:]),
     'long_description_content_type': 'text/plain',
     'maintainer': 'Russ Housley <housley@vigilsec.com>',
     'author': 'Russ Housley',
     'author_email': 'housley@vigilsec.com',
     'url': 'https://github.com/russhousley/pyasn1-alt-modules',
     'platforms': ['any'],
     'classifiers': [x for x in classifiers.split('\n') if x],
     'license': 'BSD-2-Clause',
     'packages': ['pyasn1_alt_modules'],
     'python_requires': '>=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, !=3.4.*'})

class PyTest(Command):
    user_options = []

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        suite = unittest.TestLoader().loadTestsFromNames(
            ['tests.__main__.suite']
        )

        unittest.TextTestRunner(verbosity=2).run(suite)

params['cmdclass'] = {
    'test': PyTest,
    'tests': PyTest
}

setup(**params)
