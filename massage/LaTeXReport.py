#!/usr/bin/env python
#-------------------------------------------------------------------------------
# Name:         LaTeXReport.py
# Purpose:      Create a LaTeX tabular
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

class LaTeXReport():

    filename = ''

    def __init__(self, filename):
        self.filename = filename
        try:
            with open(filename, 'wt') as f:
                # Tabular Headers
                f.write('\\begin{tabular}{|m{.50\\textwidth}|m{.25\\textwidth}|m{.25\\textwidth}}\n')
        except IOError, e:
            print 'Failed to create file %s' % self.filename

    def vulnCategoryOut(self, vuln_category):
        try:
            with open(self.filename, 'awt') as f:
                f.write('\\multicolumn{3}{|c|}{\\cellcolor{nccblue}\\color{white}\\bf %s}\\\\\n' % vuln_category)
        except IOError, e:
            print 'Failed to write file %s' % self.filename

    def vulnOut(self, vuln):

        line = ''
        count = 0

        if vuln.vulnerable_hosts:
            line = vuln.description
            line += ' & '
            for host in vuln.vulnerable_hosts:
                if not count == 0:
                    line += ' & '
                count = count + 1
                line += host
                line += ' & '
                for detail in vuln.vulnerable_hosts[host]:
                    line += detail
                line += '\\\\\n'
        try:
            with open(self.filename, 'awt') as f:
                f.write(line)
        except IOError, e:
            print ' Failed to write in file %s' % self.filename

    def write(self):
        try:
            with open(self.filename, 'awt') as f:
                f.write('\\end{tabular}\n')
        except IOError, e:
            print 'Failed to write in file %s' % self.filename
