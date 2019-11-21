#!/usr/bin/env python
# -*- coding: UTF-8 -*-
# Author : tintinweb@oststrom.com <github.com/tintinweb>

from __future__ import print_function

import binascii
import sys

try:
    import scapy.all as scapy
except ImportError:
    import scapy

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *

import socket


def dtls_ch_valid(ip):
    # create udp socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Cipher Suites
    suites = [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, TLSCipherSuite.RSA_WITH_AES_128_GCM_SHA256]
    suites_length = 2 * len(suites)

    # Client Hello message
    d1_ch = DTLSClientHello(cipher_suites=suites,
                            cipher_suites_length=suites_length,
                            compression_methods_length=1,
                            compression_methods=['NULL'])
    d1_ch_len = len(str(d1_ch))

    # Populate the Handshake message
    d1_hs = DTLSHandshake(length=d1_ch_len, fragment_offset=0)
    d1_hs_len = len(str(d1_hs))

    # Construct the DTL ClientHello Request
    record_len = d1_hs_len + d1_ch_len
    p = DTLSRecord(length=record_len, sequence=0) / d1_hs / d1_ch
    p.show()

    print("Sending DTLS payload")
    s.sendto(str(p), ip)
    resp = s.recv(1024 * 8)
    print("Received, %s" % repr(resp))
    DTLSRecord(resp).show()
    s.close()


if __name__ == "__main__":
    if len(sys.argv) <= 2:
        print("USAGE: <host> <port>")
        exit(1)
    target = (sys.argv[1], int(sys.argv[2]))
    dtls_ch_valid(target)

