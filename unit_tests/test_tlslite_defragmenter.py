# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

# compatibility with Python 2.6, for that we need unittest2 package,
# which is not available on 3.3 or 3.4
try:
    import unittest2 as unittest
except ImportError:
    import unittest

from tlslite.defragmenter import Defragmenter

class TestDefragmenter(unittest.TestCase):
    def test___init__(self):
        a = Defragmenter()

        self.assertIsNotNone(a)

    def test_getMessage(self):
        a = Defragmenter()

        self.assertIsNone(a.getMessage())
        self.assertIsNone(a.getMessage())

    def test_addStaticSize(self):
        d = Defragmenter()

        d.addStaticSize(10, 2)

        d.addData(10, bytearray(b'\x03'*2))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\x03'*2), data)

    def test_addStaticSize_with_already_defined_type(self):
        d = Defragmenter()

        d.addStaticSize(10, 255)

        with self.assertRaises(ValueError):
            d.addStaticSize(10, 2)

    def test_addStaticSize_with_uncomplete_message(self):
        d = Defragmenter()

        d.addStaticSize(10, 2)

        d.addData(10, bytearray(b'\x10'))

        ret = d.getMessage()
        self.assertIsNone(ret)

        d.addData(10, bytearray(b'\x11'))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\x10\x11'), data)

        ret = d.getMessage()
        self.assertIsNone(ret)

    def test_addStaticSize_with_multiple_types(self):
        d = Defragmenter()

        # types are added in order of priority...
        d.addStaticSize(10, 2)
        # so type 8 should be returned later than type 10 if both are in buffer
        d.addStaticSize(8, 4)

        d.addData(8, bytearray(b'\x08'*4))
        d.addData(10, bytearray(b'\x10'*2))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\x10'*2), data)

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(8, msgType)
        self.assertEqual(bytearray(b'\x08'*4), data)

        ret = d.getMessage()
        self.assertIsNone(ret)

    def test_addStaticSize_with_multiple_uncompleted_messages(self):
        d = Defragmenter()

        d.addStaticSize(10, 2)
        d.addStaticSize(8, 4)

        d.addData(8, bytearray(b'\x08'*3))
        d.addData(10, bytearray(b'\x10'))

        ret = d.getMessage()
        self.assertIsNone(ret)

        d.addData(8, bytearray(b'\x09'))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(8, msgType)
        self.assertEqual(bytearray(b'\x08'*3 + b'\x09'), data)

        ret = d.getMessage()
        self.assertIsNone(ret)

    def test_addDynamicSize(self):
        d = Defragmenter()

        d.addDynamicSize(10, 2, 2)

        ret = d.getMessage()
        self.assertIsNone(ret)

        d.addData(10, bytearray(
            b'\xee\xee' +   # header bytes
            b'\x00\x00' +   # remaining length
            # next message
            b'\xff\xff' +   # header bytes
            b'\x00\x01' +   # remaining length
            b'\xf0'))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\xee\xee\x00\x00'), data)

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\xff\xff\x00\x01\xf0'), data)

        ret = d.getMessage()
        self.assertIsNone(ret)

    def test_addDynamicSize_with_incomplete_header(self):
        d = Defragmenter()

        d.addDynamicSize(10, 2, 2)

        d.addData(10, bytearray(b'\xee'))

        self.assertIsNone(d.getMessage())

        d.addData(10, bytearray(b'\xee'))

        self.assertIsNone(d.getMessage())

        d.addData(10, bytearray(b'\x00'))

        self.assertIsNone(d.getMessage())

        d.addData(10, bytearray(b'\x00'))

        ret = d.getMessage()
        self.assertIsNotNone(ret)
        msgType, data = ret
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\xee\xee\x00\x00'), data)

    def test_addDynamicSize_with_incomplete_payload(self):
        d = Defragmenter()

        d.addDynamicSize(10, 2, 2)

        d.addData(10, bytearray(b'\xee\xee\x00\x01'))

        self.assertIsNone(d.getMessage())

        d.addData(10, bytearray(b'\x99'))

        msgType, data = d.getMessage()
        self.assertEqual(10, msgType)
        self.assertEqual(bytearray(b'\xee\xee\x00\x01\x99'), data)

    def test_addDynamicSize_with_two_streams(self):
        d = Defragmenter()

        d.addDynamicSize(9, 0, 3)
        d.addDynamicSize(10, 2, 2)

        d.addData(10, bytearray(b'\x44\x44\x00\x04'))
        d.addData(9, bytearray(b'\x00\x00\x02'))

        self.assertIsNone(d.getMessage())

        d.addData(9, bytearray(b'\x09'*2))
        d.addData(10, bytearray(b'\x10'*4))

        msgType, data = d.getMessage()
        self.assertEqual(msgType, 9)
        self.assertEqual(data, bytearray(b'\x00\x00\x02\x09\x09'))

        msgType, data = d.getMessage()
        self.assertEqual(msgType, 10)
        self.assertEqual(data, bytearray(b'\x44'*2 + b'\x00\x04' + b'\x10'*4))

    def test_addStaticSize_with_zero_size(self):
        d = Defragmenter()

        with self.assertRaises(ValueError):
            d.addStaticSize(10, 0)

    def test_addStaticSize_with_invalid_size(self):
        d = Defragmenter()

        with self.assertRaises(ValueError):
            d.addStaticSize(10, -10)

    def test_addDynamicSize_with_double_type(self):
        d = Defragmenter()

        d.addDynamicSize(1, 0, 1)
        with self.assertRaises(ValueError):
            d.addDynamicSize(1, 2, 2)

    def test_addDynamicSize_with_invalid_size(self):
        d = Defragmenter()

        with self.assertRaises(ValueError):
            d.addDynamicSize(1, 2, 0)

    def test_addDynamicSize_with_invalid_offset(self):
        d = Defragmenter()

        with self.assertRaises(ValueError):
            d.addDynamicSize(1, -1, 2)

    def test_addData_with_undefined_type(self):
        d = Defragmenter()

        with self.assertRaises(ValueError):
            d.addData(1, bytearray(10))

    def test_clearBuffers(self):
        d = Defragmenter()

        d.addStaticSize(10, 2)

        d.addData(10, bytearray(10))

        d.clearBuffers()

        self.assertIsNone(d.getMessage())
