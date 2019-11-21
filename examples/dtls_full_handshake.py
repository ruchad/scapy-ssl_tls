#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import with_statement
from __future__ import print_function
import sys

try:
    # This import works from the project directory
    from scapy_ssl_tls.ssl_tls import *
except ImportError:
    # If you installed this package via pip, you just need to execute this
    from scapy.layers.ssl_tls import *


dtls_version = TLSVersion.DTLS_1_0
ciphers = [TLSCipherSuite.RSA_WITH_AES_128_CBC_SHA, TLSCipherSuite.RSA_WITH_AES_256_CBC_SHA]


def dtls_client(ip):

    with TLSSocket(socket.socket(socket.AF_INET, socket.SOCK_DGRAM), client=True) as tls_socket:
        try:
            tls_socket.connect(ip)
            print("Connected to server: %s" % (ip,))
        except socket.timeout:
            print("Failed to open connection to server: %s" % (ip,), file=sys.stderr)
        else:
            try:
                server_hello, server_kex = tls_socket.do_handshake(dtls_version, ciphers)
                server_hello.show()
                server_kex.show()
            except TLSProtocolError as tpe:
                print("Got TLS error: %s" % tpe, file=sys.stderr)
                tpe.response.show()
            else:
                data = "GET / HTTP/1.1\r\nHOST: " + ip[0] + "\r\n\r\n"
                p = DTLSRecord(version=dtls_version, sequence=1, epoch=1) / \
                    TLSPlaintext(data=data)
                tls_socket.sendall(p)
                resp = tls_socket.recvall()
                print("Got response from server")
                resp.show()
            finally:
                print(tls_socket.tls_ctx)


if __name__ == "__main__":
    if len(sys.argv) > 2:
        server = (sys.argv[1], int(sys.argv[2]))
    else:
        server = ("127.0.0.1", 8443)
    dtls_client(server)
