# Author: Trevor Perrin
# See the LICENSE file for legal information regarding use of this file.

"""Classes for reading/writing binary data (such as TLS records)."""

from __future__ import division


class Writer(object):
    def __init__(self):
        self.bytes = bytearray(0)

    def add(self, x, length):
        self.bytes += bytearray(length)
        newIndex = len(self.bytes) - 1
        for count in range(length):
            self.bytes[newIndex] = x & 0xFF
            x >>= 8
            newIndex -= 1
        if x != 0:
            raise ValueError("Can't represent value in specified length")

    def addFixSeq(self, seq, length):
        for e in seq:
            self.add(e, length)

    def addVarSeq(self, seq, length, lengthLength):
        self.add(len(seq)*length, lengthLength)
        for e in seq:
            self.add(e, length)

    def addVarTupleSeq(self, seq, length, lengthLength):
        """
        Add a variable length list of same-sized element tuples.

        Note that all tuples must have the same size.

        Inverse of Parser.getVarTupleList()

        @type seq: enumerable
        @param seq: list of tuples

        @type length: int
        @param length: length of single element in tuple

        @type lengthLength: int
        @param lengthLength: length in bytes of overall length field
        """
        if len(seq) == 0:
            self.add(0, lengthLength)
        else:
            tupleSize = len(seq[0])
            tupleLength = tupleSize*length
            self.add(len(seq)*tupleLength, lengthLength)
            for elemTuple in seq:
                if len(elemTuple) != tupleSize:
                    raise ValueError("Tuples of different sizes")
                for elem in elemTuple:
                    self.add(elem, length)

class Parser(object):
    """
    Parser for TLV and LV byte-based encodings.

    Parser that can handle arbitrary byte-based encodings usually employed in
    Type-Length-Value or Length-Value binary encoding protocols like ASN.1
    or TLS

    Note: if the raw bytes don't match expected values (like trying to
    read a 4-byte integer from a 2-byte buffer), most methods will raise a
    SyntaxError exception.

    TODO: don't use an exception used by language parser to indicate errors
    in application code.

    @type bytes: bytearray
    @ivar bytes: data to be interpreted (buffer)

    @type index: int
    @ivar index: current position in the buffer

    @type lengthCheck: int
    @ivar lengthCheck: size of struct being parsed

    @type indexCheck: int
    @ivar indexCheck: position at which the structure begins in buffer
    """

    def __init__(self, bytes):
        """
        Bind raw bytes with parser.

        @type bytes: bytearray
        @param bytes: bytes to be parsed/interpreted
        """
        self.bytes = bytes
        self.index = 0
        self.indexCheck = 0
        self.lengthCheck = 0

    def get(self, length):
        """
        Read a single big-endian integer value encoded in 'length' bytes.

        @type length: int
        @param length: number of bytes in which the value is encoded in

        @rtype: int
        """
        if self.index + length > len(self.bytes):
            raise SyntaxError()
        x = 0
        for _ in range(length):
            x <<= 8
            x |= self.bytes[self.index]
            self.index += 1
        return x

    def getFixBytes(self, lengthBytes):
        """
        Read a string of bytes encoded in 'lengthBytes' bytes.

        @type lengthBytes: int
        @param lengthBytes: number of bytes to return

        @rtype: bytearray
        """
        if self.index + lengthBytes > len(self.bytes):
            raise SyntaxError()
        bytes = self.bytes[self.index : self.index+lengthBytes]
        self.index += lengthBytes
        return bytes

    def getVarBytes(self, lengthLength):
        """
        Read a variable length string with a fixed length.

        @type lengthLength: int
        @param lengthLength: number of bytes in which the length of the string
        is encoded in

        @rtype: bytearray
        """
        lengthBytes = self.get(lengthLength)
        return self.getFixBytes(lengthBytes)

    def getFixList(self, length, lengthList):
        """
        Read a list of static length with same-sized ints.

        @type length: int
        @param length: size in bytes of a single element in list

        @type lengthList: int
        @param lengthList: number of elements in list

        @rtype: list of int
        """
        l = [0] * lengthList
        for x in range(lengthList):
            l[x] = self.get(length)
        return l

    def getVarList(self, length, lengthLength):
        """
        Read a variable length list of same-sized integers.

        @type length: int
        @param length: size in bytes of a single element

        @type lengthLength: int
        @param lengthLength: size of the encoded length of the list

        @rtype: list of int
        """
        lengthList = self.get(lengthLength)
        if lengthList % length != 0:
            raise SyntaxError()
        lengthList = lengthList // length
        l = [0] * lengthList
        for x in range(lengthList):
            l[x] = self.get(length)
        return l

    def getVarTupleList(self, elemLength, elemNum, lengthLength):
        """
        Read a variable length list of same sized tuples.

        @type elemLength: int
        @param elemLength: length in bytes of single tuple element

        @type elemNum: int
        @param elemNum: number of elements in tuple

        @type lengthLength: int
        @param lengthLength: length in bytes of the list length variable

        @rtype: list of tuple of int
        """
        lengthList = self.get(lengthLength)
        if lengthList % (elemLength * elemNum) != 0:
            raise SyntaxError()
        tupleCount = lengthList // (elemLength * elemNum)
        tupleList = []
        for _ in range(tupleCount):
            currentTuple = []
            for _ in range(elemNum):
                currentTuple.append(self.get(elemLength))
            tupleList.append(tuple(currentTuple))
        return tupleList

    def startLengthCheck(self, lengthLength):
        """
        Read length of struct and start a length check for parsing.

        @type lengthLength: int
        @param lengthLength: number of bytes in which the length is encoded
        """
        self.lengthCheck = self.get(lengthLength)
        self.indexCheck = self.index

    def setLengthCheck(self, length):
        """
        Set length of struct and start a length check for parsing.

        @type length: int
        @param length: expected size of parsed struct in bytes
        """
        self.lengthCheck = length
        self.indexCheck = self.index

    def stopLengthCheck(self):
        """
        Stop struct parsing, verify that no under- or overflow occurred.

        In case the expected length was mismatched with actual length of
        processed data, raises an exception.
        """
        if (self.index - self.indexCheck) != self.lengthCheck:
            raise SyntaxError()

    def atLengthCheck(self):
        """
        Check if there is data in structure left for parsing.

        Returns True if the whole structure was parsed, False if there is
        some data left.

        Will raise an exception if overflow occured (amount of data read was
        greater than expected size)
        """
        if (self.index - self.indexCheck) < self.lengthCheck:
            return False
        elif (self.index - self.indexCheck) == self.lengthCheck:
            return True
        else:
            raise SyntaxError()

    def getRemainingLength(self):
        """Return amount of data remaining in struct being parsed."""
        return len(self.bytes) - self.index
