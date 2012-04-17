#!/usr/bin/env python
import sys

def howto_install_setuptools():
    print("""
   Error: You need setuptools Python package!

   It's very easy to install it, just type (as root on Linux):
   wget http://peak.telecommunity.com/dist/ez_setup.py
   python ez_setup.py
""")

try:
    from setuptools import setup
    params = {
        'install_requires': [ 'pyasn1>=0.1.1' ],
        'zip_safe': True
        }    
except ImportError:
    for arg in sys.argv:
        if arg.find('egg') != -1:
            howto_install_setuptools()
            sys.exit(1)
    from distutils.core import setup
    params = {}
    if sys.version_info[:2] > (2, 4):
        params['requires'] = [ 'pyasn1(>=0.1.1)' ]

params.update( {
    'name': 'pyasn1-modules',
    'version': '0.0.3',
    'description': 'ASN.1 modules',
    'author': 'Ilya Etingof',
    'author_email': 'ilya@glas.net',
    'url': 'http://sourceforge.net/projects/pyasn1/',
    'classifiers': [
      'Development Status :: 5 - Production/Stable',
      'Intended Audience :: Developers',
      'Intended Audience :: Information Technology',
      'Intended Audience :: Telecommunications Industry',
      'Operating System :: OS Independent',
      'Programming Language :: Python :: 2',
      'Programming Language :: Python :: 3',
      'Topic :: Communications',
      'Topic :: Security :: Cryptography',
      'Topic :: Software Development :: Libraries :: Python Modules',
      'License :: OSI Approved :: BSD License'
    ],
    'license': 'BSD',
    'packages': [ 'pyasn1_modules' ]
    } )

setup(**params)
