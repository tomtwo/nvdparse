#!/usr/bin/env python

import sys, os, logging
from database import Database
from nvd_parser import NVDFileParser, Vulnerability, Product

logging.basicConfig(level=logging.INFO, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("parser")

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
d = Database("datatmp2.sqlite")

for v in vulnerabilities:
  logger.info("Inserting vuln %s into database.." % v.id)
  d.vulnerability_insert(v.cve_year, v.cve_id, v.summary, v.get_product_ids())

  for product in v.products:
    d.product_insert(product.id, product.vendor, product.product, product.version)
