#!/usr/bin/env python

# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

from distutils.core import setup
from tlslite import __version__

setup(name="tlslite",
      version=__version__,
      author="Trevor Perrin",
      author_email="tlslite@trevp.net",
      url="http://trevp.net/tlslite/",
      description="tlslite implements SSL and TLS.",
      license="public domain and BSD",
      scripts=["scripts/tls.py", "scripts/tlsdb.py"],
      packages=["tlslite", "tlslite.utils", "tlslite.integration"],)
