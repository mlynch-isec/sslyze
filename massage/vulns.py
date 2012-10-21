#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         vulns.py
# Purpose:      Dictionnary of reported SSL misconfigurations
#
# Author:       loic
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

from massage.cipher_suite_whitelist import cipher_suite_whitelist
from massage.Vuln import Vuln, VulnCategory

# Types of SSL vulnerabilities/misconfigurations
vuln_categories = [
('sslv2', 'SSLv2 configuration'),
('sslv3', 'SSLv3 configuration'),
('tlsv1', 'TLSv1 configuration'),
('tlsv1_1', 'TLSv1.1 configuration'),
('tlsv1_2', 'TLSv1.2 configuration'),
('certinfo', 'Certificate information'),
('reneg', 'Session renegotiation'),
('resum', 'Session resumption'),
('compr', 'SSL compression'),
]

# Initialyze the dictionnary
vuln_dictionary = {}
for category in vuln_categories:
    vuln_dictionary[category[0]] = VulnCategory([], category[1])

# New vuln declaration
#vuln_dictionary['VULN_CATEGORY'].append(Vuln(
    # XML Tag
    # Attribute to check
    # Callback name
    # Callback input
    # Additional attributes to be printed in the report
    # Vuln short description
#   ))

# Allowed cipher suites for SSLv2, SSLv3, TLSv1, TLSv1.1, TLSv1.2
vuln_dictionary['sslv2'].vuln_list.append(Vuln(
    'target.sslv2.acceptedCipherSuites.cipherSuite',
    'name',
    Vuln.checkWhitelist,
    [],
    ['name', 'keySize'],
    'SSL v2 is enabled'))
vuln_dictionary['sslv3'].vuln_list.append(Vuln(
    'target.sslv3.acceptedCipherSuites.cipherSuite',
    'name',
    Vuln.checkWhitelist,
    cipher_suite_whitelist,
    ['name', 'keySize'],
    'Weak cipher suites for SSL v3 are supported'))
vuln_dictionary['tlsv1'].vuln_list.append(Vuln(
    'target.tlsv1.acceptedCipherSuites.cipherSuite',
    'name',
    Vuln.checkWhitelist,
    cipher_suite_whitelist,
    ['name', 'keySize'],
    'Weak cipher suites for TLS v1 are supported'))
vuln_dictionary['tlsv1_1'].vuln_list.append(Vuln(
    'target.tlsv1_1.acceptedCipherSuites.cipherSuite',
    'name',
    Vuln.checkWhitelist,
    cipher_suite_whitelist,
    ['name', 'keySize'],
    'Weak cipher suites for TLS v1.1 are supported'))
vuln_dictionary['tlsv1_2'].vuln_list.append(Vuln(
    'target.tlsv1_2.acceptedCipherSuites.cipherSuite',
    'name',
    Vuln.checkWhitelist,
    cipher_suite_whitelist,
    ['name', 'keySize'],
    'Weak cipher suites for TLS v1.2 are supported:'))

# Certificate info
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate.subjectPublicKeyInfo',
    'publicKeySize',
    Vuln.isLessThan,
    1024,
    [],
    'Public key size is too small'))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate.subjectPublicKeyInfo',
    'publicKeyAlgorithm',
    Vuln.checkBlacklist,
    ['md2WithRSAEncryption', 'md5WithRSAEncryption'], # TODO, make it a whitelist
    [],
    'Certificate\'s public key algorithm is weak'))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate',
    'isTrustedByMozillaCAStore',
    Vuln.isTrue,
    None,
    [],
    "Certificate is not trusted"))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate.validity',
    'notAfter',
    Vuln.checkDate,
    'notAfter',
    [],
    "Certificate is expired"))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate.validity',
    'notBefore',
    Vuln.checkDate,
    'notBefore',
    [],
    "Certificate is not valid yet"))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate.extensions',
    'X509v3BasicConstraints',
    Vuln.checkWhitelist,
    'CA:FALSE',
    [],
    "Certificate is a CA"))
vuln_dictionary['certinfo'].vuln_list.append(Vuln(
    'target.certinfo.certificate',
    'hasMatchingHostname',
    Vuln.isTrue,
    None,
    [],
    'Certificate\'s hostname mismatch'))

# Session renegotiation
vuln_dictionary['reneg'].vuln_list.append(Vuln(
    'target.reneg.sessionRenegotiation',
    'canBeClientInitiated',
    Vuln.isFalse,
    None,
    [],
    'Client can initiate renegotiation'))
vuln_dictionary['reneg'].vuln_list.append(Vuln(
    'target.reneg.sessionRenegotiation',
    'isSecure',
    Vuln.isTrue,
    None,
    [],
    'Renegotation is not secure'))

# Session resumption
vuln_dictionary['resum'].vuln_list.append(Vuln(
    'target.resum.sessionResumptionWithSessionIDs',
    'isSupported',
    Vuln.isTrue,
    None,
    [],
    'Session ID is not supported'))
vuln_dictionary['resum'].vuln_list.append(Vuln(
    'target.resum.sessionResumptionWithTLSTickets',
    'isSupported',
    Vuln.isTrue,
    None,
    [],
    'TLS ticket is not supported'))

# Compression
vuln_dictionary['compr'].vuln_list.append(Vuln(
    'target.compression.compression',
    'isSupported',
    Vuln.isFalse,
    None,
    [],
    'SSL compression is supported'))
