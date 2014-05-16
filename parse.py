#!/usr/bin/env python

import sys, os, logging, re, argparse
from hashids import Hashids
from string import maketrans

from database import Database
from nvd_parser import NVDFileParser, Vulnerability, Product
from version_parser import *

logging.basicConfig(level=logging.DEBUG, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("parser")

hasher = Hashids("salt")


parser = argparse.ArgumentParser(description='| Parse nvd xml files into sqlite db')
parser.add_argument('filenames', metavar='nvd xml file', type=str, nargs='+',
                   help='nvd xml files to parse')
# parser.add_argument('--simulate', dest='accumulate', action='store_const',
#                    const=sum, default=max,
#                    help='sum the integers (default: find the max)')
parser.add_argument('--simulate', help='parse only, do not write to db', action='store_true', default=False)
parser.add_argument('--emptydb', help='clear database before insertion', action='store_true', default=False)
parser.add_argument('--database', help='database file to write to', type=str, default='data.sqlite')
parser.add_argument('--salt', help='salt to encrypt version numbers with', type=str, nargs=1, default='salt')

args = parser.parse_args()

filenames = args.filenames

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
db = Database(args.database, empty=args.emptydb, simulate=args.simulate)

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
        vs = parse_version(i, product.version)

        version = hasher.encrypt(vs[0], vs[1], vs[2], vs[3])

        # Add vulnerability_product entry to map product & version to a vulnerability
        ret = db.vulnerability_product_insert(i, version, v.cve_year, v.cve_id)

