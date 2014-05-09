#!/usr/bin/env python

import sys, os, logging, re
from hashids import Hashids
from string import maketrans

from database import Database
from nvd_parser import NVDFileParser, Vulnerability, Product

logging.basicConfig(level=logging.DEBUG, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("parser")

hasher = Hashids("salt")

if len(sys.argv) < 2:
  sys.exit("Usage: %s [NVD xml file(s)]" % (sys.argv[0]))

filenames = sys.argv[1:]

for file in filenames:
  # Check all inputted files exist
  if not os.path.exists(file):
    sys.exit("Error: %s does not exist" % file)

logger.info("Reading in %s.." % (', '.join(filenames)))

plugins = [
  ("adobe", "flash_player"),
  ("oracle", "jre"),
  ("microsoft", "silverlight"),
  ("apple", "quicktime")
]

vulnerabilities = []

for file in filenames:
  logger.info("Parsing %s.." % file)

  p = NVDFileParser(file, product_filter=plugins)
  vs = p.get_vulnerabilities()
  vulnerabilities.extend(vs)

# Open the database for insertion
db = Database("data.sqlite")

# Insert the products we're searching for into the db to map to vulnerabilities
for i in xrange(len(plugins)):
  vendor = plugins[i][0]
  product = plugins[i][1]

  db.product_insert(i, vendor, product)

for v in vulnerabilities:
  logger.info("Inserting vuln %s into database.." % v.id)
  db.vulnerability_insert(v.cve_year, v.cve_id, v.summary)

  for product in v.products:
    for i in xrange(len(plugins)):

      if product.equalTo(plugins[i]):
        logger.info("\t> %s" % product)

        # Generate hashid for version string
        version = ''
        if i == 0:        # flash_player
          # example: 10.0.1.154

          if ("mx" in product.version 
              or "r" in product.version 
              or "cs" in product.version):
            logger.info("Skipping over %s" % product)
            continue

          # Translate "d" to a . if it's there
          product.version = product.version.translate(maketrans("d", "."))

          vs = product.version.split('.')                         # get each version part

          for i in xrange(len(vs)):
            if vs[i] == '':
              vs[i] = '0'

          vs = map(int, vs)                                       # cast all strings to ints

          while len(vs) < 4:
            # Need to add missing suffix string for .0 releases which aren't specified
            vs.append(0)

          version = hasher.encrypt(vs[0], vs[1], vs[2], vs[3])

        elif i == 1:   # java jre
          # example: 1.5.0:update_55, 1.5.0:update5, 1.4.2_38
          half = product.version.split(':')                       # split main version from update part
          vs = half[0].split('.')                                 # split main version into major/minor/rev parts
          
          # the 1.4.2_38 case
          vs2 = vs[2].split('_')
          if len(vs2) > 1:
            vs[2] = vs2[0]
            vs.append(vs2[1]) # awful TODO

          if len(half) > 1:                                       # contains update_ prefix?
            vs.append(re.sub("[^0-9]", "", half[1]))              # remove non-numeric chars 

          while len(vs) < 4:
            vs.append(0)
          
          vs = map(int, vs)                                       # cast strings to ints
          version = hasher.encrypt(vs[0], vs[1], vs[2], vs[3])

        elif i == 2:   # silverlight
          # example: 5.0.60818.0
          vs = product.version.split('.')
          vs = map(int, vs)

          while len(vs) < 4:
            vs.append(0)

          version = hasher.encrypt(vs[0], vs[1], vs[2], vs[3])
          
        elif i == 3:   # quicktime
          # example: 7.7.2.0 (usually just 7.7.2)
          vs = product.version.split('.')
          vs = map(int, vs)

          while len(vs) < 4:
            vs.append(0)

          version = hasher.encrypt(vs[0], vs[1], vs[2], vs[3])

        # Add vulnerability_product entry to map product & version to a vulnerability
        ret = db.vulnerability_product_insert(i, version, v.cve_year, v.cve_id)

