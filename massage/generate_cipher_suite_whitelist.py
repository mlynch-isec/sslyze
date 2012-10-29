#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         generate_cipher_suite_whitelist.py
# Purpose:      Generate the list of accepted cipher suites (OpenSSL call)
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

import cipher_suite_whitelist
import subprocess
import sys

# String representing the accepted cipher suites in OpenSSL (thanks Alban)
magic_string = "RC4-SHA:RC4-MD5:HIGH:!ADH:!CAMELLIA"

local_openssl_version = subprocess.check_output(["openssl", "version"]).rstrip("\n").split(" ")[1]
# Don't overwrite the whitelist of cipher suites if the local version of OpenSSL
# is older than the one previously used
if local_openssl_version <= cipher_suite_whitelist.openssl_version:
    print "You are using OpenSSL %s. The current list of cipher suites was\
generated using OpenSSL %s." % (local_openssl_version, cipher_suite_whitelist.openssl_version)
    print "Running this script with your OpenSSL version may generate a list\
that is missing the latest cipher suites, or accepts cipher suites that have\
been deprecated since."
    if len(sys.argv) >= 2:
        if sys.argv[1] == '-f':
            print "You've been warned... overwriting..."
    else:
        print "If you still wish to overwrite this file, use the -f option."
        sys.exit()

# Query the list of cipher suite to OpenSSL
cipher_suite_whitelist = sorted(subprocess.check_output(["openssl", "ciphers", magic_string]).rstrip().split(":"))

# Generate a python list
with open('cipher_suite_whitelist.py', 'wt') as f:
    f.write('# Autogenerated file, do not edit\n')
    f.write("openssl_version = \"%s\"\n" % local_openssl_version)
    f.write("cipher_suite_whitelist = [\n")
    for cipher_suite in cipher_suite_whitelist:
        f.write("\"%s\",\n" % cipher_suite)
    f.write("]\n")
    f.close()
