#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         Vuln.py
# Purpose:      SSL misconfiguration classes
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

from xml.etree import ElementTree
import datetime
import copy

class VulnCategory():

    def __init__(self, vuln_list, name):
        self.name = name
        self.vuln_list = vuln_list

class Vuln():

    def __init__(self, element, attribute, callback, check_values, details, description):
        self.element = element
        self.path = str.split(self.element, '.')
        self.attribute = attribute
        self.callback = callback
        self.check_values = check_values,
        self.details = details
        self.description = description
        self.vulnerable_hosts = {}

    def check_elements(self, results, path):
        # If we reached the last element, check its value
        if not path:
            for val in results:
                if self.attribute:
                    testValue = getattr(val, self.attribute)
                else:
                    testValue = val
                if self.callback(self, testValue, self.check_values):
                    # If host is vulnerable, print details
                    print_value = ''
                    for detail in self.details:
                        print_value = print_value + ' ' + getattr(val, detail)
                    self.appendHost(print_value)

            return
        # Recursion through the whole tree
        subpath = copy.deepcopy(path)
        tag = subpath.pop(0)
        attrs = getattr(results, tag)
        if attrs:
            for attr in attrs:
                # If new target, save the hostname
                if tag == 'target':
                    self.current_host = attr.host
                self.check_elements(attr, subpath)

    def isTrue(self, val, foo):
        if val != 'True':
            return True
        return False

    def isFalse(self, val, foo):
        if val != 'False':
            return True
        return False

    def checkWhitelist(self, val, whitelist):
        if val != None:
            if val not in whitelist[0]:
                return True
        return False

    def checkBlacklist(self, val, blacklist):
        if val in blacklist[0]:
            return True
        return False

    def isLessThan(self, val, minimum):
        if int(val) < int(minimum[0]):
            return True
        return False

    def checkDate(self, val, checkType):
        ct = checkType[0]
        today = datetime.datetime.today()
        cert_date = datetime.datetime.strptime(val, '%b %d %H:%M:%S %Y %Z')
        delta = (today - cert_date)
        delta_seconds = (delta.days * 24 * 3600) + delta.seconds
        if ((ct == 'notBefore') & (delta_seconds < 0)):
            return True
        elif ((ct == 'notAfter') & (delta_seconds > 0)):
            return True
        return False

    def appendHost(self, val):
        try:
            self.vulnerable_hosts[self.current_host].append(val)
        except KeyError, e:
            self.vulnerable_hosts[self.current_host] = [val]

    def check(self, results):
        self.check_elements(results, self.path)
        return True
