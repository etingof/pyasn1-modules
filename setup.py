#!/usr/bin/env python
#
# This file is part of pyasn1-modules software.
#
# Copyright (c) 2005-2017, Ilya Etingof <etingof@gmail.com>
# License: http://pyasn1.sf.net/license.html
#
"""A collection of ASN.1-based protocols modules.

   A collection of ASN.1 modules expressed in form of pyasn1 classes.
   Includes protocols PDUs definition (SNMP, LDAP etc.) and various
   data structures (X.509, PKCS etc.).
"""

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
Programming Language :: Python :: 2.4
Programming Language :: Python :: 2.5
Programming Language :: Python :: 2.6
Programming Language :: Python :: 2.7
Programming Language :: Python :: 3
Programming Language :: Python :: 3.2
Programming Language :: Python :: 3.3
Programming Language :: Python :: 3.4
Programming Language :: Python :: 3.5
Programming Language :: Python :: 3.6
Topic :: Communications
Topic :: System :: Monitoring
Topic :: System :: Networking :: Monitoring
Topic :: Software Development :: Libraries :: Python Modules
"""


def howto_install_distribute():
    print("""
   Error: You need the distribute Python package!

   It's very easy to install it, just type (as root on Linux):

   wget http://python-distribute.org/distribute_setup.py
   python distribute_setup.py

   Then you could make eggs from this package.
""")


def howto_install_setuptools():
    print("""
   Error: You need setuptools Python package!

   It's very easy to install it, just type (as root on Linux):

   wget http://peak.telecommunity.com/dist/ez_setup.py
   python ez_setup.py

   Then you could make eggs from this package.
""")


try:
    from setuptools import setup

    params = {
        'install_requires': ['pyasn1>=0.1.8'],
        'zip_safe': True
    }
except ImportError:
    import sys

    for arg in sys.argv:
        if arg.find('egg') != -1:
            if sys.version_info[0] > 2:
                howto_install_distribute()
            else:
                howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup

    params = {}
    if sys.version_info[:2] > (2, 4):
        params['requires'] = ['pyasn1(>=0.1.8)']

doclines = [x.strip() for x in (__doc__ or '').split('\n') if x]

params.update(
    {'name': 'pyasn1-modules',
     'version': open('pyasn1_modules/__init__.py').read().split('\'')[1],
     'description': doclines[0],
     'long_description': ' '.join(doclines[1:]),
     'maintainer': 'Ilya Etingof <etingof@gmail.com>',
     'author': 'Ilya Etingof',
     'author_email': 'etingof@gmail.com',
     'url': 'https://github.com/etingof/pyasn1-modules',
     'platforms': ['any'],
     'classifiers': [x for x in classifiers.split('\n') if x],
     'license': 'BSD',
     'packages': ['pyasn1_modules']}
)

setup(**params)
