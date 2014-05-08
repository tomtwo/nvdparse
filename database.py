import sys, os, sqlite3, logging

logging.basicConfig(level=logging.DEBUG, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("database")

class Database:
  def __init__(self, filename, empty=False):
    if empty: # Empty the database before use
      os.remove(filename)

    # Either create a new or reopen an existing database
    self.conn = sqlite3.connect(filename)

    if not self.tables_exist(): 
      # Missing some tables
      self.tables_create()

  def __del__(self):
    self.conn.close()

  def tables_create(self):
    logger.info("Attempting to (re)create tables")
    cursor = self.conn.cursor()

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS vulnerability (
        cve_year INTEGER NOT NULL,
        cve_id INTEGER NOT NULL,
        description TEXT DEFAULT NULL,
        PRIMARY KEY (cve_year, cve_id)
      );
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS vendor (
        vendor_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL
      );
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS product (
        product_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL,
        version TEXT NOT NULL 
      );
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS vulnerability_product (
        product_id INTEGER NOT NULL REFERENCES product (product_id),
        cve_year INTEGER NOT NULL REFERENCES vulnerability (cve_year),
        cve_id INTEGER NOT NULL REFERENCES vulnerability (cve_id),
        PRIMARY KEY (product_id, cve_year, cve_id)
      );
    """)

    # Not yet in use, ignore
    cursor.execute("""
      CREATE TABLE IF NOT EXISTS vendor (
        vendor_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        PRIMARY KEY (vendor_id)
      );
    """)

    # commit changes
    self.conn.commit()

  def tables_exist(self):
    # Returns true iff vulnerability, product, vendor and vuln_pr tables all exist
    c = self.conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")

    required_tables = ["vulnerability", "product", "vulnerability_product", "vendor"]
    table_existence = [False for x in range(len(required_tables))]

    for table in c.fetchall():
      for i in range(len(required_tables)):
        if table[0] == required_tables[i]:
          table_existence[i] = True

    retval = True
    for bool in table_existence:
      retval = retval and bool

    return retval

  def product_insert(self, product_id, vendor, product, version):
    try:
      c = self.conn.cursor()
      c.execute("INSERT INTO product VALUES (?,?,?,?)", (product_id, vendor, product, version,))
    except Exception, e:
      self.conn.rollback()
      logger.error("Failed to insert product (%d, %s, %s, %s): %s" % (product_id, vendor, product, version, e))
      return False
    else:
      logger.debug("Inserted product %d: %s %s %s" % (product_id, vendor, product, version))
      self.conn.commit()
      return True

  def product_fetch(self, product_id):
    c = self.conn.cursor()
    c.execute("SELECT * FROM product WHERE product_id = ?", (product_id,))
    return c.fetchone()

  def product_lookup(self, vendor, product, version):
    # Lookup product ID for given product
    pass

  def vulnerability_insert(self, cve_year, cve_id, description, product_ids):
    last_product_id = -1
    try:
      c = self.conn.cursor()
      c.execute("INSERT INTO vulnerability VALUES (?,?,?)", (cve_year, cve_id, description,))
      
      for pid in product_ids:
        last_product_id = pid
        c.execute("INSERT INTO vulnerability_product VALUES (?,?,?)", (pid, cve_year, cve_id))
    except Exception, e:
      self.conn.rollback()
      logger.error("Failed to insert vulnerability (%d, %d, %s, %d): %s" % (cve_year, cve_id, description, last_product_id, e))
      return False
    else:
      logger.debug("Inserted vulnerability CVE-%d-%d: %s" % (cve_year, cve_id, description))
      self.conn.commit()
      return True

  def vulnerability_description(self, cve_year, cve_id):
    # Find the description of a vulnerability
    c = self.conn.cursor()
    c.execute("SELECT description FROM vulnerability WHERE cve_year = ? AND cve_id = ?", (cve_year, cve_id,))
    return c.fetchone()

  def product_get_vulnerabilities(self, product_id):
    pass