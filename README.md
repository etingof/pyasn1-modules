
Alternative ASN.1 modules for pyasn1
------------------------------------
[![PyPI](https://img.shields.io/pypi/v/pyasn1-alt-modules.svg?maxAge=2592000)](https://pypi.org/project/pyasn1-alt-modules)
[![Python Versions](https://img.shields.io/pypi/pyversions/pyasn1-alt-modules.svg)](https://pypi.org/project/pyasn1-alt-modules/)
[![GitHub license](https://img.shields.io/badge/license-BSD-blue.svg)](https://raw.githubusercontent.com/russhousley/pyasn1-alt-modules/master/LICENSE.txt)

The `pyasn1-alt-modules` package contains a collection of
[ASN.1](https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.208-198811-W!!PDF-E&type=items)
data structures expressed as Python classes based on [pyasn1](https://github.com/etingof/pyasn1)
data model.

It seems that [pyasn1-modules](https://github.com/etingof/pyasn1-modules) is no
longer being maintained.  As a result, the `pyasn1-alt-modules` package was
created to share new module developments.  Previous modules are included in
the `pyasn1-alt-modules` package so that both do not need to be installed.

However, the tools directory of the `pyasn1-modules` package in not included.

If ASN.1 module you need is not present in this collection, try using
[Asn1ate](https://github.com/kimgr/asn1ate) tool that compiles (some)
ASN.1 modules into pyasn1 code.

Feedback
--------

If something does not work as expected, 
[open an issue](https://github.com/russhousley/pyasn1-alt-modules/issues) at GitHub.
 
Additional module contributions are welcome via GitHub pull requests.

Copyright (c) 2005-2020, [Ilya Etingof](mailto:etingof@gmail.com).<br/>
Copyright (c) 2021-2022, Vigil Security, LLC, (contact [Russ Housley](mailto:housley@vigilsec.com))<br/>
All rights reserved.
