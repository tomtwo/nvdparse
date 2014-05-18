#!/usr/bin/env python

import sys, os, logging, re, argparse
from hashids import Hashids
from string import maketrans

from database import Database
from nvd_parser import NVDFileParser, Vulnerability, Product
from version_parser import *

logging.basicConfig(level=logging.DEBUG, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("parser")

# --------------------------------- #
#         Argument Parsing          #
# --------------------------------- #

parser = argparse.ArgumentParser(description='| Parse nvd xml files into sqlite db')
parser.add_argument('filenames', metavar='nvd xml file', type=str, nargs='+',
                   help='nvd xml files to parse')
# parser.add_argument('--simulate', dest='accumulate', action='store_const',
#                    const=sum, default=max,
#                    help='sum the integers (default: find the max)')
parser.add_argument('--simulate', help='parse only, do not write to db', action='store_true', default=False)
parser.add_argument('--emptydb', help='clear database before insertion', action='store_true', default=False)
parser.add_argument('--database', help='database file to write to', type=str, default='data.sqlite')
parser.add_argument('--salt', help='salt to encrypt version numbers with', type=str, default='salt')
parser.add_argument('--interactive', help='enable interactive input of input parameters', action='store_true', default=False)

args = parser.parse_args()

filenames = args.filenames
salt = args.salt
emptydb = args.emptydb
simulate = args.simulate
database = args.database


if args.interactive:
  # Override arguments with any inputted into program
  simulate = raw_input("Simulate? [Y/n]: ")
  salt = raw_input("Salt? [salt]: ")
  emptydb = raw_input("Empty DB? [y/N]: ")
  database = raw_input("Output DB? [filename]: ")

  simulate = simulate == 'y' or simulate == ''
  salt = salt or args.salt
  emptydb = emptydb == 'y'
  database = database or args.database

hasher = Hashids(salt)


# --------------------------------- #
#      Check XML files exist        #
# --------------------------------- #

for file in filenames:
  if not os.path.exists(file):
    sys.exit("Error: %s does not exist" % file)

logger.info("Reading in %s.." % (', '.join(filenames)))

vulnerabilities = []


# -------------------------------------- #
#   Read vulnerabilities from XML files  #
# -------------------------------------- #

for file in filenames:
  logger.info("Parsing %s.." % file)

  p = NVDFileParser(file, product_filter=plugins)
  vs = p.get_vulnerabilities()
  vulnerabilities.extend(vs)


# --------------------------------- #
#       Open SQLite database        #
# --------------------------------- #

db = Database(database, empty=emptydb, simulate=simulate)


# --------------------------------- #
#   Plugins we are searching for    #
# --------------------------------- #

plugins = [
  ("adobe", "flash_player"),
  ("oracle", "jre"),
  ("microsoft", "silverlight"),
  ("apple", "quicktime")
]

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

