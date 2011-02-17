#!/usr/bin/env python
import sys
import string

def howto_install_setuptools():
    print """Error: You need setuptools Python package!

It's very easy to install it, just type (as root on Linux):
   wget http://peak.telecommunity.com/dist/ez_setup.py
   python ez_setup.py
"""

try:
    from setuptools import setup
    params = {
        'install_requires': [ 'pyasn1' ],
        'zip_safe': True
        }    
except ImportError:
    for arg in sys.argv:
        if string.find(arg, 'egg') != -1:
            howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup
    if sys.version_info > (2, 2):
        params = {
            'requires': [ 'pyasn1' ]
            }
    else:
        params = {}

params.update( {
    'name': 'pyasn1-modules',
    'version': '0.0.1a',
    'description': 'ASN.1 modules',
    'author': 'Ilya Etingof',
    'author_email': 'ilya@glas.net',
    'url': 'http://sourceforge.net/projects/pyasn1/',
    'license': 'BSD',
    'packages': [ 'pyasn1_modules' ]
      } )

apply(setup, (), params)
