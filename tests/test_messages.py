# vim: fileencoding=utf8 foldmethod=marker
# SPDX-License-Identifier: BSD-2-Clause
# {{{ License header: BSD-2-Clause
# Copyright (c) 2014, Till Maas <opensource@till.name>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
# list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# }}}
import sys

# FIXME: Maybe there is a better way to do this
sys.path.insert(0, "..")
sys.path.insert(0, ".")

from tlslite.messages import EllipticCurvesExtension


def test_EllipticCurvesExtension():
    """
    Test values from http://tools.ietf.org/html/rfc4492#section-5.1.1
    """
    def hex_to_bytearray(hexdata):
        return bytearray(hexdata.replace(" ", "").decode("hex"))

    extension = EllipticCurvesExtension().create(
        elliptic_curves=[0x0013, 0x0015])

    extension_bytes = extension.write()
    expected = hex_to_bytearray("00 0A 00 06 00 04 00 13 00 15")
    assert extension_bytes == expected

    extension = EllipticCurvesExtension().create(
        elliptic_curves=[0xFF02])

    extension_bytes = extension.write()
    expected = hex_to_bytearray("00 0A 00 04 00 02 FF 02")
    assert extension_bytes == expected
