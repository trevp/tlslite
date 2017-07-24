# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.

""" Helper package for handling fragmentation of messages """

from __future__ import generators

from .utils.codec import Parser

class Defragmenter(object):

    """
    Class for demultiplexing TLS messages.

    Since the messages can be interleaved and fragmented between each other
    we need to cache not complete ones and return in order of urgency.

    Supports messages with given size (like Alerts) or with a length header
    in specific place (like Handshake messages).

    :ivar priorities: order in which messages from given types should be
        returned.
    :ivar buffers: data buffers for message types
    :ivar decoders: functions which check buffers if a message of given type
        is complete
    """

    def __init__(self):
        """Set up empty defregmenter"""
        self.priorities = []
        self.buffers = {}
        self.decoders = {}

    def addStaticSize(self, msgType, size):
        """Add a message type which all messages are of same length"""
        if msgType in self.priorities:
            raise ValueError("Message type already defined")
        if size < 1:
            raise ValueError("Message size must be positive integer")

        self.priorities += [msgType]

        self.buffers[msgType] = bytearray(0)
        def sizeHandler(data):
            """
            Size of message in parameter

            If complete message is present in parameter returns its size,
            None otherwise.
            """
            if len(data) < size:
                return None
            else:
                return size
        self.decoders[msgType] = sizeHandler

    def addDynamicSize(self, msgType, sizeOffset, sizeOfSize):
        """Add a message type which has a dynamic size set in a header"""
        if msgType in self.priorities:
            raise ValueError("Message type already defined")
        if sizeOfSize < 1:
            raise ValueError("Size of size must be positive integer")
        if sizeOffset < 0:
            raise ValueError("Offset can't be negative")

        self.priorities += [msgType]
        self.buffers[msgType] = bytearray(0)

        def sizeHandler(data):
            """
            Size of message in parameter

            If complete message is present in parameter returns its size,
            None otherwise.
            """
            if len(data) < sizeOffset+sizeOfSize:
                return None
            else:
                parser = Parser(data)
                # skip the header
                parser.getFixBytes(sizeOffset)

                payloadLength = parser.get(sizeOfSize)
                if parser.getRemainingLength() < payloadLength:
                    # not enough bytes in buffer
                    return None
                return sizeOffset + sizeOfSize + payloadLength

        self.decoders[msgType] = sizeHandler

    def addData(self, msgType, data):
        """Adds data to buffers"""
        if msgType not in self.priorities:
            raise ValueError("Message type not defined")

        self.buffers[msgType] += data

    def getMessage(self):
        """Extract the highest priority complete message from buffer"""
        for msgType in self.priorities:
            length = self.decoders[msgType](self.buffers[msgType])
            if length is None:
                continue

            # extract message
            data = self.buffers[msgType][:length]
            # remove it from buffer
            self.buffers[msgType] = self.buffers[msgType][length:]
            return (msgType, data)
        return None

    def clearBuffers(self):
        """Remove all data from buffers"""
        for key in self.buffers.keys():
            self.buffers[key] = bytearray(0)
