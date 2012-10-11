#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         HTTPSConnection.py
# Purpose:      Similar to httplib.HTTPSConnection but uses ctSSL instead of 
#               the standard ssl module. Should eventually be part of ctSSL.
#
# Author:       alban
#
# Copyright:    2012 SSLyze developers
#
#   SSLyze is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 2 of the License, or
#   (at your option) any later version.
#
#   SSLyze is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with SSLyze.  If not, see <http://www.gnu.org/licenses/>.
#-------------------------------------------------------------------------------

import socket
from httplib import HTTPConnection, HTTPS_PORT

from ctSSL import SSL, SSL_CTX, constants, errors
from SSLSocket import SSLSocket



class HTTPSConnection(HTTPConnection):
    """
    This class mirrors httplib.HTTPSConnection but uses ctSSL instead of the 
    standard ssl module.
    For now the way to access low level SSL functions associated with a given 
    HTTPSConnection is to directly access the ssl and ssl_ctx attributes of the 
    object. TODO: change that.
    
    @type ssl_ctx: ctSSL.SSL_CTX
    @ivar ssl_ctx: SSL_CTX object for the HTTPS connection.

    @type ssl: ctSSL.SSL
    @ivar ssl: SSL object for the HTTPS connection.
    certificates.
    """
    
    def __init__(self, host, port, ssl, ssl_ctx, 
                 strict=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        """
        Create a new HTTPSConnection.

        @type host: str
        @param host: Host name of the server to connect to.
        
        @type port: int
        @param port: Port number to connect to. 443 by default.

        @type ssl: ctSSL.SSL
        @param ssl: SSL object for the HTTPS connection. If not specified,
        a default SSL object will be created for the connection and SSL 
        certificates will NOT be verified when connecting to the server.
        
        @type ssl_ctx: ctSSL.SSL_CTX
        @param ssl_ctx: SSL_CTX object for the HTTPS connection. If not 
        specified, a default SSL_CTX object will be created for the connection 
        and SSL certificates will NOT be verified when connecting to the server.

        @type timeout: int
        @param timeout: Socket timeout value.
        """        
        HTTPConnection.__init__(self, host, port, strict, timeout)

        self.ssl_ctx = ssl_ctx
        self.ssl = ssl
            
    
    def connect(self):
        """
        Connect to a host on a given (SSL) port.
        """
            
        sock = socket.create_connection((self.host, self.port),
                                        self.timeout)
        
        if self._tunnel_host:
            self.sock = sock
            self._tunnel()
              
        # Doing something similar to ssl.wrap_socket() but with ctSSL
        self.ssl.set_socket(sock)
        ssl_sock = SSLSocket(self.ssl)
        
        ssl_sock.do_handshake()
        self.sock = ssl_sock
        
