#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         HTMLReport.py
# Purpose:      Create an HTML report file
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

class HTMLReport():

    filename = ''

    def __init__(self, filename):

        self.filename = filename

        # HTML Headers
        self.root = ElementTree.Element('html')
        head = ElementTree.SubElement(self.root, 'head')
        title = ElementTree.SubElement(head, 'title')
        title.text = 'SSLyze Results'
        style = ElementTree.SubElement(head, 'style')
        try:
            with open('massage/style.css') as f:
                style.text = f.read()
        except IOError, e:
            print 'Ooops'

        # Body
        self.body = ElementTree.SubElement(self.root, 'body')

    def vulnCategoryOut(self, vuln_category):
        self.container = ElementTree.SubElement(self.body, 'div', attrib={'id':'container'})
        vuln_cat_div = ElementTree.SubElement(self.container, 'div', attrib={'id':'vuln_cat'})
        vuln_cat_div.text = vuln_category

    def vulnOut(self, vuln):
        if vuln.vulnerable_hosts:
            vuln_name_div = ElementTree.SubElement(self.container, 'div', attrib={'id':'vuln_name'})
            vuln_name_div.text = vuln.description
            host_list_div = ElementTree.SubElement(self.container, 'div', attrib={'id':'host_list'})
            for host in vuln.vulnerable_hosts:
                hostname_div = ElementTree.SubElement(host_list_div, 'div', attrib={'id':'hostname'})
                hostname_div.text = host
                details_div = ElementTree.SubElement(host_list_div, 'div', attrib={'id':'details'})
                detail_ul = ElementTree.SubElement(details_div, 'ul')
                for detail in vuln.vulnerable_hosts[host]:
                    li = ElementTree.SubElement(detail_ul, 'li')
                    li.text = detail
            clear_div = ElementTree.SubElement(self.container, 'div', attrib={'id':'clear'})
            clear_div.text = ' '

    def write(self):
        tree = ElementTree.ElementTree(self.root)
        tree.write(self.filename)
