#!/usr/bin/env python

import string
from datetime import date
from database import Database

class DatabaseTest():
    # so as to not interfere with actual CVEs, should be for next year
    _default_year = date.today().year + 1

    def __init__(self):
        self.db = Database("/tmp/nvd_db.sqlite", empty=True)

    def insert_dummy_product(self, product_id):
        assert(type(product_id) is int)

        print "Inserting product", product_id
        self.db.product_insert(product_id, "vendor", "product")


    def insert_dummy_products(self, product_ids):
        assert(type(product_ids) is list)

        for pid in product_ids:
            self.insert_dummy_product(pid)

    def insert_dummy_vulnerability(self, cve_id):
        print("Inserting vulnerability CVE-%d-%d" % (self._default_year, cve_id))
        self.db.vulnerability_insert(self._default_year, cve_id, "test cve, not real")

    def insert_dummy_vulnerabilities(self, count):
        for i in xrange(0, count):
            self.insert_dummy_vulnerability(i + 1)

    def insert_mapping(self, product_id, product_version, cve_id):
        self.db.vulnerability_product_insert(product_id, product_version, self._default_year, cve_id)

    def insert_mappings(self, product_id, product_version, cve_ids):
        assert(type(cve_ids) == list)

        for i in cve_ids:
            self.insert_mapping(product_id, product_version, i)

    def lookup(self, product_id, product_version):
        return self.db.product_get_vulnerabilities(product_id, product_version)

    @classmethod
    def version_to_string(product_version):
        return string.join(map(str, product_version), '.')
    

t = DatabaseTest()

print "### INSERTION STAGE ###"

print ""
t.insert_dummy_products([1,2])
print ""
t.insert_dummy_vulnerabilities(10)
print ""

# For product 1, add some overlapping cases
t.insert_mappings(1, [1,0,0,0], [1,4,9])
t.insert_mappings(1, [1,0,1,0], [4,5,9])
t.insert_mappings(1, [1,0,0,None], [2])

# For product 2, overlap some elements with previous product
t.insert_mappings(2, [1,0,0,0], [1,3,9])
t.insert_mappings(2, [1,None,None,None], [3])
t.insert_mappings(2, [1,0,0,None], [1,2])

print ""
print "### LOOKUP STAGE ###"

print "# Should have vulnerabilities:"

# Product 1
print t.lookup(1, [1,0,0,0])
print t.lookup(1, [1,0,1,0])
print t.lookup(1, [1,0,0,None])

# Product 2
print t.lookup(2, [1,0,0,0])
print t.lookup(2, [1,None, None, None])
print t.lookup(2, [1,0,0,None])

print "# Should not have vulnerabilities:"

# Non-existing products & versions, all should return nothing
print t.lookup(1, [1,1,0,0])
print t.lookup(1, [1,None,None,None])
print t.lookup(2, [1,0,1,0])
print t.lookup(3, [1,0,0,0])
print t.lookup(3, [1,0,0,None])
