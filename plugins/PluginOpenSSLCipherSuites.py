#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         PluginOpenSSLCipherSuites.py
# Purpose:      Scans the target server for supported OpenSSL cipher suites.
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

from xml.etree.ElementTree import Element
import socket

from plugins import PluginBase
from utils.ThreadPool import ThreadPool
from utils.ctSSL import SSL, SSL_CTX, constants, ctSSL_initialize, \
    ctSSL_cleanup
from utils.SSLyzeSSLConnection import SSLyzeSSLConnection, SSLHandshakeRejected


class PluginOpenSSLCipherSuites(PluginBase.PluginBase):


    available_commands = PluginBase.AvailableCommands(
        "PluginOpenSSLCipherSuites",
        "Scans the target server for supported OpenSSL cipher suites.")
    available_commands.add_command(
        command="sslv2",
        help="Lists the SSL 2.0 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_command(
        command="sslv3",
        help="Lists the SSL 3.0 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_command(
        command="tlsv1",
        help="Lists the TLS 1.0 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_command(
        command="tlsv1_1",
        help="Lists the TLS 1.1 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_command(
        command="tlsv1_2",
        help="Lists the TLS 1.2 OpenSSL cipher suites supported by the server.",
        dest=None)
    available_commands.add_option(
        option='http_get',
        help="Option - For each cipher suite, sends an HTTP GET request after "
        "completing the SSL handshake and returns the HTTP status code.",
        dest=None)
    available_commands.add_option(
        option='hide_rejected_ciphers',
        help="Option - Hides the (usually long) list of cipher suites that were"
        " rejected by the server.",
        dest=None)   
        
        
    def process_task(self, target, command, args):

        MAX_THREADS = 30
        
        if command in ['sslv2', 'sslv3', 'tlsv1', 'tlsv1_1', 'tlsv1_2']:
            ssl_version = command
        else:
            raise Exception("PluginOpenSSLCipherSuites: Unknown command.")

        # Get the list of available cipher suites for the given ssl version
        ctSSL_initialize(multithreading=True)
        ctx = SSL_CTX.SSL_CTX(ssl_version)
        ctx.set_cipher_list('ALL:NULL:@STRENGTH')
        ssl = SSL.SSL(ctx)
        cipher_list = ssl.get_cipher_list()

        # Create a thread pool
        NB_THREADS = min(len(cipher_list), MAX_THREADS) # One thread per cipher
        thread_pool = ThreadPool()

        # Scan for every available cipher suite
        for cipher in cipher_list:
            thread_pool.add_job((self._test_ciphersuite,
                                 (target, ssl_version, cipher)))

        # Scan for the preferred cipher suite
        thread_pool.add_job((self._pref_ciphersuite,
                             (target, ssl_version)))

        # Start processing the jobs
        thread_pool.start(NB_THREADS)

        result_dicts = {'preferredCipherSuite':{}, 'acceptedCipherSuites':{},
                        'rejectedCipherSuites':{}, 'errors':{}}
        
        # Store the results as they come
        for completed_job in thread_pool.get_result():
            (job, result) = completed_job
            if result is not None:
                (result_type, ssl_cipher, keysize, msg) = result
                (result_dicts[result_type])[ssl_cipher] = (msg, keysize)
                    
        # Store thread pool errors
        for failed_job in thread_pool.get_error():
            (job, exception) = failed_job
            ssl_cipher = str(job[1][2])
            error_msg = str(exception.__class__.__module__) + '.' \
                        + str(exception.__class__.__name__) + ' - ' + str(exception)
            result_dicts['errors'][ssl_cipher] = (error_msg, None)        
            
        thread_pool.join()
        ctSSL_cleanup()
        
        # Generate results
        return PluginBase.PluginResult(self._generate_txt_result(result_dicts, command),
                                       self._generate_xml_result(result_dicts, command))
        
         
# == INTERNAL FUNCTIONS ==

# FORMATTING FUNCTIONS
    def _generate_txt_result(self, result_dicts, ssl_version):
        
        cipher_format = '        {0:<32}{1:<35}'
        title_format =  '      {0:<32} '        
        keysize_format = '{0:<25}{1:<14}'
        title_txt = self.PLUGIN_TITLE_FORMAT.format(ssl_version.upper() + ' Cipher Suites')
        txt_result = [title_txt]
        
        txt_titles = [('preferredCipherSuite', 'Preferred Cipher Suite:'),
                      ('acceptedCipherSuites', 'Accepted Cipher Suite(s):'),
                      ('rejectedCipherSuites', 'Rejected Cipher Suite(s):'),
                      ('errors', 'Unknown Errors:')]
              
        if self._shared_settings['hide_rejected_ciphers']:
            txt_titles.pop(2)
            txt_result.append('')
            txt_result.append(title_format.format('Rejected Cipher Suite(s): Hidden'))
            
        for (result_type, result_title) in txt_titles:
            
            # Sort the cipher suites by results
            result_list = sorted(result_dicts[result_type].iteritems(), 
                                 key=lambda (k,v): (v,k), reverse=True)
                                 
            # Add a new line and title
            txt_result.append('')
            if len(result_list) == 0: # No ciphers
                txt_result.append(title_format.format(result_title + ' None'))
            else:
                txt_result.append(title_format.format(result_title))

                # Add one line for each ciphers
                for (cipher_txt, (msg, keysize)) in result_list:
                    if keysize:
                        cipher_txt = keysize_format.format(cipher_txt, keysize)
                                    
                    txt_result.append(cipher_format.format(cipher_txt, msg))
                                  
        return txt_result
            
            
    def _generate_xml_result(self, result_dicts, command):
                
        xml_result = Element(command,  title = command.upper() + ' Cipher Suites')
        
        for (result_type, result_dict) in result_dicts.items():
            xml_dict = Element(result_type)
            
            # Add one element for each ciphers
            for (ssl_cipher, (msg, keysize)) in result_dict.items():
                cipher_xml_attr = {'name' : ssl_cipher, 'connectionStatus' : msg}
                if keysize: 
                    cipher_xml_attr['keySize'] = keysize
                cipher_xml = Element('cipherSuite', attrib = cipher_xml_attr)
                    
                xml_dict.append(cipher_xml)
                
            xml_result.append(xml_dict)

        return xml_result
            
            
# SSL FUNCTIONS    
    def _test_ciphersuite(self, target, ssl_version, ssl_cipher):
        """
        Initiates a SSL handshake with the server, using the SSL version and 
        cipher suite specified.
        """
        ssl_ctx = SSL_CTX.SSL_CTX(ssl_version)
        ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
        ssl_ctx.set_cipher_list(ssl_cipher)
    
        # ssl_connect can be an HTTPS connection or an SMTP STARTTLS connection
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target, ssl_ctx=ssl_ctx)
        
        try: # Perform the SSL handshake
            ssl_connect.connect()
            
        except SSLHandshakeRejected as e:
            return ('rejectedCipherSuites', ssl_cipher, None, str(e))

        else:
            ssl_cipher = ssl_connect.ssl.get_current_cipher()
            if 'ADH' in ssl_cipher or 'AECDH' in ssl_cipher:
                keysize = 'Anon' # Anonymous, let s not care about the key size
            else:
                keysize = str(ssl_connect.ssl.get_current_cipher_bits())+' bits'
                
            status_msg = ssl_connect.post_handshake_check()
            return ('acceptedCipherSuites', ssl_cipher, keysize, status_msg)
    
        finally:
            ssl_connect.close()
            
        return
    
    
    def _pref_ciphersuite(self, target, ssl_version):
        """
        Initiates a SSL handshake with the server, using the SSL version and cipher
        suite specified.
        """
        ssl_ctx = SSL_CTX.SSL_CTX(ssl_version)
        ssl_ctx.set_verify(constants.SSL_VERIFY_NONE)
        # ssl_connect can be an HTTPS connection or an SMTP STARTTLS connection
        ssl_connect = SSLyzeSSLConnection(self._shared_settings, target, 
                                          ssl_ctx=ssl_ctx, hello_workaround=True)
        
        try: # Perform the SSL handshake
            ssl_connect.connect()
        except:
            return None

        else:
            ssl_cipher = ssl_connect.ssl.get_current_cipher()
            if 'ADH' in ssl_cipher or 'AECDH' in ssl_cipher:
                keysize = 'Anon' # Anonymous, let s not care about the key size
            else:
                keysize = str(ssl_connect.ssl.get_current_cipher_bits())+' bits'
                
            status_msg = ssl_connect.post_handshake_check()
            return ('preferredCipherSuite', ssl_cipher, keysize, status_msg)
    
        finally:
            ssl_connect.close()
            
        return

