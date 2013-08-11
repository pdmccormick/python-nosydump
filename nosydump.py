#!/usr/bin/env python
# -*- coding: utf-8 -*-

# nosy-dump.py -- Python port of Kristian Høgsberg's nosy-dump
#
# (c) 2009-2013 Peter McCormick
#

import os
import sys
import select
import tty
import termios

from fcntl import ioctl
from datetime import time
from ctypes import Structure, Union, sizeof, c_uint, c_ulong, c_ubyte

TCODE_CYCLE_START = 0x8

NOSY_IOC_GET_STATS = 0x80082600
NOSY_IOC_START = 0x2601
NOSY_IOC_STOP = 0x2602
NOSY_IOC_FILTER = 0x40042602

QUADLET_LENGTH = 4

TCODES = [
        "WRITE_QUADLET",
        "WRITE_BLOCK",
        "WRITE_RESPONSE",
        "READ_QUADLET",
        "READ_BLOCK",
        "READ_QUADLET_RESPONSE",
        "READ_BLOCK_RESPONSE",
        "CYCLE_START",
        "LOCK_REQUEST",
        "ISO_DATA",
        "LOCK_RESPONSE",
        "PHY_PACKET"
        ]

def log(msg="\n"):
    sys.stdout.write(str(msg) + "\r\n")

class OverlayStructure(Structure):
    raw_memory_overlay_klass = None

    @classmethod
    def from_bytestring(cls, raw):
        size = sizeof(cls)

        if cls.raw_memory_overlay_klass is None:
            class RawMemoryOverlay(Union):
                _fields_ = [
                        ( "struct", cls ),
                        ( "raw", c_ubyte * size ),
                        ]
                #

            cls.raw_memory_overlay_klass = RawMemoryOverlay

        over = cls.raw_memory_overlay_klass()

        if isinstance(raw, str):
            if size > len(raw):
                raw = raw.ljust(size, chr(0))

            if len(raw) > size:
                raw = raw[0:size]

            raw = [ ord(k) for k in raw ]

        over.raw = (c_ubyte * size)(*raw)

        return over.cls

class PhyPacket(OverlayStructure):
    class _union(Union):
        class _common(Structure):
            _fields_ = [
                    ( "zero", c_uint, 24 ),
                    ( "phy_id", c_uint, 6 ),
                    ( "identifier", c_uint, 2 ),
                    ]
            #

        class _phy_config(Structure):
            _fields_ = [
                    ( "zero", c_uint, 16 ),
                    ( "gap_count", c_uint, 6 ),
                    ( "set_gap_count", c_uint, 1),
                    ( "set_root", c_uint, 1),
                    ( "root_id", c_uint, 6 ),
                    ( "identifier", c_uint, 2 ),
                    ]
            #

        class _self_id(Structure):
            _fields_ = [
                    ( "more_packets", c_uint, 1 ),
                    ( "initiated_reset", c_uint, 1 ),
                    ( "port2", c_uint, 2 ),
                    ( "port1", c_uint, 2 ),
                    ( "port0", c_uint, 2 ),
                    ( "power_class", c_uint, 3 ),
                    ( "contender", c_uint, 1 ),
                    ( "phy_delay", c_uint, 2 ),
                    ( "phy_speed", c_uint, 2 ),
                    ( "gap_count", c_uint, 6 ),
                    ( "link_active", c_uint, 1 ),
                    ( "extended", c_uint, 1 ),
                    ( "phy_id", c_uint, 6 ),
                    ( "identifier", c_uint, 2 ),
                    ]
            #

        class _ext_self_id(Structure):
            _fields_ = [
                    ( "more_packets", c_uint, 1 ),
                    ( "reserved1", c_uint, 1 ),
                    ( "porth", c_uint, 2 ),
                    ( "portg", c_uint, 2 ),
                    ( "portf", c_uint, 2 ),
                    ( "porte", c_uint, 2 ),
                    ( "portd", c_uint, 2 ),
                    ( "portc", c_uint, 2 ),
                    ( "portb", c_uint, 2 ),
                    ( "porta", c_uint, 2 ),
                    ( "reserved0", c_uint, 2 ),
                    ( "sequence", c_uint, 3 ),
                    ( "extended", c_uint, 1 ),
                    ( "phy_id", c_uint, 6 ),
                    ( "identifier", c_uint, 2 ),
                    ]
            #

        # _union fields
        _fields_ = [
                ( "common", _common ),
                ( "link_on", _common ),
                ( "phy_config", _phy_config ),
                ( "self_id", _self_id ),
                ( "ext_self_id", _ext_self_id ),
                ( "nonverted", c_ulong ),
                ]
        #

    # PhyPacket fields
    _fields_ = [
            ( "timestamp", c_ulong ),
            ( "_", _union ),
            ( "inverted", c_ulong ),
            ( "ack", c_ulong ),
            ]
    #

sizeof_phy_packet = sizeof(PhyPacket)

class LinkPacket(OverlayStructure):
    class _union(Union):
        class _common(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_ulong ),
                    ]
            #

        class _read_quadlet(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_ulong ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _read_quadlet_response(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "reserved0", c_uint, 12 ),
                    ( "rcode", c_uint, 4 ),
                    ( "source", c_uint, 16 ),
                    ( "reserved1", c_ulong ),
                    ( "data", c_ulong ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _read_block(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_ulong ),
                    ( "extended_tcode", c_uint, 16 ),
                    ( "data_length", c_uint, 16 ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _read_block_response(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "reserved0", c_uint, 12 ),
                    ( "rcode", c_uint, 4 ),
                    ( "source", c_uint, 16 ),
                    ( "reserved1", c_ulong ),
                    ( "extended_tcode", c_uint, 16 ),
                    ( "data_length", c_uint, 16 ),
                    ( "crc", c_ulong ),
                    ( "data", c_ulong ),
                    ]
            #

        class _write_quadlet(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_ulong ),
                    ( "data", c_ulong ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _write_block(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_uint, 32 ),
                    ( "extended_tcode", c_uint, 16 ),
                    ( "data_length", c_uint, 16 ),
                    ( "crc", c_ulong ),
                    ( "data", c_ulong ),
                    ]
            #

        class _write_response(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "reserved0", c_uint, 12 ),
                    ( "rcode", c_uint, 4 ),
                    ( "source", c_uint, 16 ),
                    ( "reserved1", c_ulong ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _cycle_start(Structure):
            _fields_ = [
                    ( "priority", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "rt", c_uint, 2 ),
                    ( "tlabel", c_uint, 6 ),
                    ( "destination", c_uint, 16 ),

                    ( "offset_high", c_uint, 16 ),
                    ( "source", c_uint, 16 ),
                    ( "offset_low", c_ulong ),
                    ( "data", c_ulong ),
                    ( "crc", c_ulong ),
                    ]
            #

        class _cycle_start(Structure):
            _fields_ = [
                    ( "sy", c_uint, 4 ),
                    ( "tcode", c_uint, 4 ),
                    ( "channel", c_uint, 6 ),
                    ( "tag", c_uint, 2 ),
                    ( "data_length", c_uint, 16 ),
                    ( "crc", c_ulong ),
                    ]
            #

        # _union fields
        _fields_ = [
                ( "common", _common ),
                ( "read_quadlet", _read_quadlet ),
                ( "read_quadlet_response", _read_quadlet_response ),
                ( "read_block", _read_block ),
                ( "read_block_response", _read_block_response ),
                ( "write_quadlet", _write_quadlet ),
                ( "write_block", _write_block ),
                ( "write_response", _write_response ),
                ( "cycle_start", _cycle_start ),
                ]
        #

    # LinkPacket fields
    _fields_ = [
            ( "timestamp", c_ulong ),
            ( "_", _union ),
            ]
    #


class NosyDumpApp(object):
    def __init__(self):
        self.bus_reset_count = 0
        self.short_packet_count = 0
        self.phy_packet_count = 0

    def run_main(self, argv):
        dev = open("/dev/nosy", 'rw')

        filter = ~0
        filter = ~(1 << TCODE_CYCLE_START)

        ioctl(dev, NOSY_IOC_FILTER, filter)
        ioctl(dev, NOSY_IOC_START)

        dev_fd = dev.fileno()
        stdin_fd = sys.stdin.fileno()

        p = select.poll()
        p.register(dev_fd, select.POLLIN)
        p.register(stdin_fd, select.POLLIN)

        MAX_BUFFER = 128*1024

        old_tc = termios.tcgetattr(stdin_fd)
        tty.setraw(stdin_fd)

        running = True
        try:
            while running:
                for (fd, ev) in p.poll():
                    if fd == dev_fd:
                        data = os.read(dev_fd, MAX_BUFFER)
                        self.print_packet(data)

                    elif fd == stdin_fd:
                        data = sys.stdin.read(1)
                        if data == 'q':
                            running = False
                            break
        except Exception, e:
            log(e)
        finally:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tc)
            print "Goodbye!"


    def print_packet(self, data):
        length = len(data)

        if length == 0:
            self.bus_reset_count += 1
        elif length < 4:
            self.short_packet_count += 1
        elif length == 4:
            log("bus reset")
        elif length < sizeof_phy_packet:
            log("short packet")
        elif length == sizeof_phy_packet:
            s = PhyPacket.from_bytestring(data)

            if s.inverted == ~s._.nonverted:
                self.phy_packet_count += 1

            log("phy packet")
        else:
            s = LinkPacket.from_bytestring(data)
            tcode = TCODES[s._.common.tcode].lower()

            details = getattr(s._, tcode)

            pairs = dict([ ( f[0], "0x%x" % getattr(details, f[0]) ) for f in details._fields_ ])
            log("%6lu %21s: %s" % (s.timestamp, tcode, " ".join([ "%s=%s" % k for k in pairs.items() ])))

            del s

if __name__ == '__main__':
    app = NosyDumpApp()
    app.run_main(sys.argv[1:])

