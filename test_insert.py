#!/usr/bin/env python

import sys, os, logging, string
from database import Database

logging.basicConfig(level=logging.INFO, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("testdb")

if len(sys.argv) < 2:
  sys.exit("Usage: %s [new sqlite db file]" % (sys.argv[0]))

#if os.path.exists(sys.argv[1]):
#  sys.exit("Error: path '%s' already exists" % (sys.argv[1]))

filename = sys.argv[1]

logger.info("%s db in %s.." % (("Reading" if os.path.exists(filename) else "Creating"), filename))

d = Database(filename, empty=True)

def version_to_string(product_version):
    return string.join(map(str, product_version), '.')

def test_insert(product_id, product_version, cve_year, cve_id):
    print "Inserting product", product_id
    d.product_insert(product_id, "vendor", "product")

    print("Inserting vulnerability CVE-%d-%d" % (cve_year, cve_id))
    d.vulnerability_insert(cve_year, cve_id, "test CVE, not real")

    print "Inserting mapping to version", version_to_string(product_version)
    d.vulnerability_product_insert(product_id, product_version, cve_year, cve_id)

def test_lookup(product_id, product_version):
    print "Searching for vulnerabilities for product ID", product_id, " v",version_to_string(product_version)

    print d.product_get_vulnerabilities(product_id, product_version)


test_insert(1, [1,2,3,4], 2015, 1)
test_insert(1, [1,2,3,4], 2015, 2)
test_insert(1, [1,2,3,4], 2015, 3)
test_insert(1, [1,2,3,4], 2015, 4)
test_insert(1, [1,2,3,None], 2015, 2)
test_insert(1, [1,2,3,None], 2015, 2)
print "--"
test_lookup(1, [1,2,3,4])