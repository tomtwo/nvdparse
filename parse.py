#!/usr/bin/env python

from lxml import etree
from io import StringIO, BytesIO
import sys, os

if len(sys.argv) < 2:
  sys.exit("Usage: %s [NVD xml file]" % (sys.argv[0]))

if not os.path.exists(sys.argv[1]):
  sys.exit("Error: %s does not exist" % (sys.argv[1]))

filename = sys.argv[1]

print "Reading in %s.." % filename

tree = etree.parse(filename)

# Getting all the name spaces.
nsmap = {}
for ns in tree.xpath('//namespace::*'):
  if ns[0]: # Removes the None namespace, neither needed nor supported.
    nsmap[ns[0]] = ns[1]
  else: # We actually do need it for the default namespace
    nsmap['def'] = ns[1]

print nsmap

vulnerabilities = tree.xpath('//def:entry', namespaces=nsmap)

print len(vulnerabilities)

class Vulnerability:
  def __init__(self, entry):

    self.id = entry.xpath('vuln:cve-id/text()', namespaces=nsmap)[0] # Pick first from list
    self.date_published = entry.xpath('vuln:published-datetime/text()', namespaces=nsmap)
    self.summary = entry.xpath('vuln:summary/text()', namespaces=nsmap)
    self.products = []
    self.contains_flash = False

    products = entry.xpath('vuln:vulnerable-software-list/vuln:product', namespaces=nsmap)
    for p in products:
      pr = Product.fromString(p.text)
      self.contains_flash |= pr.isFlash()
      self.products.append(pr)

  def __str__(self):
    return "Vuln %s>>> %s" % (self.id, "contains flash" if self.contains_flash else "no flash")

class Product:
  def __init__(self, type, vendor, product, version):
    self.type = type
    self.vendor = vendor
    self.product = product
    self.version = version

  def __str__(self):
    return "%s %s %s" % (self.vendor, self.product, self.version)

  def isFlash(self):
    return self.vendor == "adobe" and self.product == "flash_player"

  @classmethod
  def fromString(_class, product_string):
    # Follows CPE naming standard
    # ex: cpe:/a:apple:safari:6.0
    # ex: cpe:/o:apple:mac_os_x:10.8.2
    parts = product_string.split(':')

    if(parts[0] != 'cpe'):
      # Invalid
      raise Exception("Not a CPE product identifier")

    type = parts[1][1] # a(pplication), o(perating system), h(ardware)
    vendor = parts[2]
    product = parts[3]
    
    if len(parts) > 4:
      version = parts[4]
    else:
      print "EX:", product_string
      version = ''

    return _class(type, vendor, product, version)



def parseVulnerability(entry):
  global vs
  # PRE: entry = lxml etree instance of 'entry' node element
  # POST: Object containing relevant values from node
  #         element for database insertion

  


for v in vulnerabilities:
  print Vulnerability(v)
