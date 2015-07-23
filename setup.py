#!/usr/bin/env python

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from distutils.core import setup

setup(name="tlslite-ng",
      version="0.5.0-beta2",
      author="Hubert Kario",
      author_email="hkario@redhat.com",
      url="https://github.com/tomato42/tlslite-ng",
      description="tlslite implements SSL and TLS.",
      license="LGPLv2",
      scripts=["scripts/tls.py", "scripts/tlsdb.py"],
      packages=["tlslite", "tlslite.utils", "tlslite.integration"],
      package_data={
                    'package1': ['LICENSE', 'README.md']},
      )
