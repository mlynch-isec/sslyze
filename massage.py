#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         massage.py
# Purpose:      Generate a SSL misconfiguration report
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

import optparse
import copy
import datetime
from massage.xml2obj import xml2obj
from massage.HTMLReport import HTMLReport
from massage.Vuln import Vuln, VulnCategory
from massage.vulns import vuln_categories, vuln_dictionary
from xml.etree import ElementTree 
from xml.etree.ElementTree import iterparse, Element

MASSAGE_VERSION = 'SSLyzeMassage v0.1 beta'

# Command line parser
parser = optparse.OptionParser()
# XML input
parser.add_option(
    '--xml_in',
    help= (
        'Input xml file containing SSLyze results. '
        'XML_IN should be the name of the xml file to read from.'),
    dest='xml_in',
    default=None)

# HTML output
parser.add_option(
    '--html_out',
    help= (
        'Output the results to an HTML file. '
        'HTML_OUT should be the name of the file to write to.'),
    dest='html_out',
    default=None)

def main():

    # Parse the command line
    (args, foo) = parser.parse_args()
    if args.xml_in == None:
        print 'Command line error: you need to specify the name of the xml input file'
        return
    if args.html_out == None:
        print 'Command line error: you need to specify the name of the html output file'
        return

    # Open the SSLyze XML output and build a native python object
    with open(args.xml_in, 'rt') as f:
        xml = f.read()
        tree = xml2obj(xml)
        results = tree.results

    # Parse the datastructure and build a list of vulnerable hosts
    for vuln_category in vuln_dictionary:
        for vuln in vuln_dictionary[vuln_category].vuln_list:
            vuln.check(results)

    # Output the results to an HTML file
    report = HTMLReport()
    for vuln_category in vuln_categories:
        report.vulnCategory2HTML(vuln_dictionary[vuln_category[0]].name)
        for vuln in vuln_dictionary[vuln_category[0]].vuln_list:
            report.vuln2HTML(vuln)
    report.write(args.html_out)

if __name__ == "__main__":
    main()
