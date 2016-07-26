#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os, logging, re, argparse
from hashids import Hashids
from string import maketrans

from database import Database
from nvd_parser import NVDFileParser, Vulnerability, Product, Util

logging.basicConfig(level=logging.DEBUG, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("parser")


# --------------------------------- #
#         Argument Parsing          #
# --------------------------------- #

parser = argparse.ArgumentParser(description='| Parse nvd xml files into sqlite db')
parser.add_argument('filenames', metavar='nvd xml file', type=str, nargs='*',
                   help='nvd xml files to parse')
# parser.add_argument('--simulate', dest='accumulate', action='store_const',
#                    const=sum, default=max,
#                    help='sum the integers (default: find the max)')
parser.add_argument('--simulate', help='parse only, do not write to db', action='store_true', default=False)
parser.add_argument('--emptydb', help='clear database before insertion', action='store_true', default=False)
parser.add_argument('--database', help='database file to write to', type=str, default='data.sqlite')
parser.add_argument('--interactive', help='enable interactive input of input parameters', action='store_true', default=False)
parser.add_argument('--products', help='products to search for in nvd', type=str, default='')

args = parser.parse_args()

if args.interactive is False and len(args.filenames) == 0:
  parser.error("input xml paths required as arguments in non-interactive mode")

filenames = args.filenames
emptydb = args.emptydb
simulate = args.simulate
database = args.database
products = []

if args.products:
  # expected format: adobe flash_player&apple quicktime&oracle jre ...
  products = list(tuple(x.split(' ')) for x in args.products.split('&'))

def read_list(prompt=">", processor=None):
  res = []
  while True:
    val = raw_input("%s " % prompt)

    if len(val) == 0:
      break
    else:
      if processor is not None:
        val = processor(val)

      res.append(val)

  return res

if args.interactive:
  # Override arguments with any inputted into program
  simulate = raw_input("Simulate? [Y/n]: ")
  emptydb = raw_input("Empty DB? [y/N]: ")
  database = raw_input("Output DB? [%s]: " % database)

  simulate = simulate == 'y' or simulate == ''
  emptydb = emptydb == 'y'
  database = database or args.database

  # Read filenames
  print "Enter all NVD XML filenames to parse, separated by newlines."
  print "Empty line to end input"
  filenames = read_list() or filenames

  # Read plugins, comma separates
  print "Enter all products to filter by, separated by newlines"
  print "Empty line to end input"
  raw_products = read_list()

  for p in raw_products:
    split = p.split(' ')
    vendor = split[0]
    product = split[1]

    # Add vendor, product tuple to list
    products.append((vendor, product))

if not len(filenames):
  print "No files to parse; exiting"
  sys.exit(0)


# --------------------------------- #
#      Check XML files exist        #
# --------------------------------- #

for file in filenames:
  if not os.path.exists(file):
    sys.exit("Error: %s does not exist" % file)

logger.info("Reading in %s.." % (', '.join(filenames)))

vulnerabilities = []


# ---------------------------------- #
#  Check if any products were given  #
# ---------------------------------- #

if not products:
  logger.error("No products given to parser; nothing to retrieve")

  # Exit with failure status
  sys.exit(1)


# --------------------------------- #
#       Open SQLite database        #
# --------------------------------- #

db = Database(database, empty=emptydb, simulate=simulate)


# -------------------------------------- #
#   Read vulnerabilities from XML files  #
# -------------------------------------- #

for file in filenames:
  logger.info("Parsing %s.." % file)

  p = NVDFileParser(file, product_filter=products)
  vs = p.get_vulnerabilities()
  vulnerabilities.extend(vs)


# --------------------------------- #
#   Insert products into database   #
# --------------------------------- #

for i in xrange(len(products)):
  vendor = products[i][0]
  product = products[i][1]

  db.product_insert(i, vendor, product)

for v in vulnerabilities:
  logger.info("Inserting vuln %s into database.." % v.id)
  db.vulnerability_insert(v.cve_year, v.cve_id, v.summary, len(v.dependencies) > 0)

  for product in v.products:
    for i in xrange(len(products)):

      if product.equalTo(products[i]):
        logger.info("\t> %s" % product)

        # Parse version string into array of integers
        vs = Util.parse_version(product.version)

        # Add vulnerability_product entry to map product & version to a vulnerability
        ret = db.vulnerability_product_insert(i, vs, v.cve_year, v.cve_id)

  for dependency in v.dependencies:
    print "CVE-%d-%d depends on %s" % (v.cve_year, v.cve_id, dependency)
    db.dependency_insert(v.cve_year, v.cve_id, dependency.getIndexIn(products))
    print "grabbing rows"
    print db.dependencies_get(v.cve_year, v.cve_id)

print "---"
print db.dependencies_get(2013, 965)
print db.dependencies_get(2012, 666)
print db.dependencies_get(2013, 667)
