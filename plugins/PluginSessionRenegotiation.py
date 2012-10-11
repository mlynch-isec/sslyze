#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginSessionRenegotiation.py
# Purpose:      Tests the target server for insecure renegotiation.
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
from xml.etree.ElementTree import Element

from plugins import PluginBase
from utils.ctSSL import ctSSL_initialize, ctSSL_cleanup, SSL_CTX, \
    constants, errors
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection

class PluginSessionRenegotiation(PluginBase.PluginBase):

    available_commands = PluginBase.AvailableCommands(
        title="PluginSessionRenegotiation",
        description="Tests the target server for insecure renegotiation.")
    available_commands.add_command(
        command="reneg",
        help=(
            "Tests the target server's support for client-initiated "
            'renegotiations and secure renegotiations.'),
        dest=None)


    def process_task(self, target, command, args):

        ctSSL_initialize()
        try:
            (can_reneg, is_secure) = self._test_renegotiation(target)
        finally:
            ctSSL_cleanup()
        
        # Text output
        reneg_txt = 'Honored' if can_reneg else 'Rejected'
        secure_txt = 'Supported' if is_secure else 'Not supported'
        cmd_title = 'Session Renegotiation'
        txt_result = [self.PLUGIN_TITLE_FORMAT.format(cmd_title)]
        
        RENEG_FORMAT = '      {0:<35} {1}'
        txt_result.append(RENEG_FORMAT.format('Client-initiated Renegotiations:', reneg_txt))
        txt_result.append(RENEG_FORMAT.format('Secure Renegotiation: ', secure_txt))
        
        # XML output
        xml_reneg_attr = {'canBeClientInitiated' : str(can_reneg),
                          'isSecure' : str(is_secure)}
        xml_reneg = Element('sessionRenegotiation', attrib = xml_reneg_attr)
        
        xml_result = Element(command, title = cmd_title)
        xml_result.append(xml_reneg)
        
        return PluginBase.PluginResult(txt_result, xml_result)


    def _test_renegotiation(self, target):
        """
        Checks whether the server honors session renegotiation requests and 
        whether it supports secure renegotiation.
        """
        ssl_ctx = SSL_CTX.SSL_CTX('tlsv1') # sslv23 hello will fail for specific servers such as post.craigslist.org
        ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target,ssl_ctx,
                                          hello_workaround=True)
    
        try:
            ssl_connect.connect()
            is_secure = ssl_connect._ssl.get_secure_renegotiation_support()
    
            try: # Let's try to renegotiate
                ssl_connect._ssl.renegotiate()
                can_reneg = True
    
            # Errors caused by a server rejecting the renegotiation
            except errors.ctSSLUnexpectedEOF as e:
                can_reneg = False
            except socket.error as e:
                if 'connection was forcibly closed' in str(e.args):
                    can_reneg = False
                elif 'reset by peer' in str(e.args):
                    can_reneg = False
                else:
                    raise
            #except socket.timeout as e:
            #    result_reneg = 'Rejected (timeout)'
            except errors.SSLError as e:
                if 'handshake failure' in str(e.args):
                    can_reneg = False
                elif 'no renegotiation' in str(e.args):
                    can_reneg = False
                else:
                    raise
    
        finally:
            ssl_connect.close()
    
        return (can_reneg, is_secure)