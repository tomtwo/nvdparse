import sys, os, sqlite3, logging, string

logging.basicConfig(level=logging.WARN, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("database")

VERSION_FIELDS = ["major", "minor", "patch", "build"]

class Database:
  def __init__(self, filename, empty=False, simulate = False):
    # Need version fields to continue
    assert(len(VERSION_FIELDS) > 0)

    # Empty the database before use
    if empty and os.path.isfile(filename): 
      os.remove(filename)

    # Either create a new or reopen an existing database
    self.conn = sqlite3.connect(filename)

    self.simulate = simulate

    if not self.tables_exist(): 
      # Missing some tables
      self.tables_create()

  def __del__(self):
    self.conn.close()

  def tables_create(self):
    if self.simulate:
      return

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
      CREATE TABLE IF NOT EXISTS product (
        product_id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        vendor TEXT NOT NULL,
        product TEXT NOT NULL
      );
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS vulnerability_product (
        cve_year INTEGER NOT NULL REFERENCES vulnerability (cve_year),
        cve_id INTEGER NOT NULL REFERENCES vulnerability (cve_id),
        product_id INTEGER NOT NULL REFERENCES product (product_id),
        product_version_major INTEGER NOT NULL,
        product_version_minor INTEGER NULL,
        product_version_patch INTEGER NULL,
        product_version_build INTEGER NULL,
        PRIMARY KEY (cve_year, cve_id, product_id, product_version_major,
                     product_version_minor, product_version_patch, product_version_build)
      );
    """)

    cursor.execute("""
      CREATE TABLE IF NOT EXISTS config (
        key TEXT NOT NULL PRIMARY KEY,
        value TEXT NOT NULL
      );
    """)

    # commit changes
    self.conn.commit()

  def tables_exist(self):
    # Returns true iff vulnerability, product, vendor and vuln_pr tables all exist
    c = self.conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table';")

    required_tables = ["vulnerability", "product", "vulnerability_product", "vendor", "config"]
    table_existence = [False for x in range(len(required_tables))]

    for table in c.fetchall():
      for i in range(len(required_tables)):
        if table[0] == required_tables[i]:
          table_existence[i] = True

    retval = True
    for bool in table_existence:
      retval = retval and bool

    return retval

  def product_insert(self, product_id, vendor, product):
    if self.simulate:
      logger.info("simulate: INSERT product(%d, %s, %s)" 
            % (product_id, vendor, product))
      return True

    try:
      c = self.conn.cursor()
      c.execute("INSERT INTO product VALUES (?,?,?)", (product_id, vendor, product,))
    except Exception, e:
      self.conn.rollback()
      logger.error("Failed to insert product (%d, %s, %s): %s" % (product_id, vendor, product, e))
      return False
    else:
      logger.debug("Inserted product %d: %s %s" % (product_id, vendor, product))
      self.conn.commit()
      return True

  def product_fetch(self, product_id):
    c = self.conn.cursor()
    c.execute("SELECT * FROM product WHERE product_id = ?", (product_id,))
    return c.fetchone()

  def product_lookup(self, vendor, product, version):
    # Lookup product ID for given product
    pass

  def vulnerability_insert(self, cve_year, cve_id, description):
    if self.simulate:
      logger.info("simulate: INSERT vulnerability(%d, %d, %s)" 
            % (cve_year, cve_id, description))
      return True

    try:
      c = self.conn.cursor()
      c.execute("INSERT INTO vulnerability VALUES (?,?,?)", (cve_year, cve_id, description,))
    except Exception, e:
      self.conn.rollback()

      if "not unique" in str(e):
        # Already exists, ignore
        return True

      logger.error("Failed to insert vulnerability (%d, %d, %s): %s" % (cve_year, cve_id, description, e))
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

  def vulnerability_product_insert(self, product_id, product_version, cve_year, cve_id):
    vs = map(str, product_version)
    vstring = string.join(vs, '.')
    if self.simulate:
      logger.info("simulate: INSERT vulnerability_product(%d, %s, %d, %d)" 
                  % (product_id, vstring, cve_year, cve_id))
      return True

    try:
      c = self.conn.cursor()
      c.execute("INSERT INTO vulnerability_product VALUES (?,?,?,?,?,?,?)", (cve_year, cve_id, product_id, product_version[0], product_version[1], product_version[2], product_version[3],))
    except Exception, e:
      self.conn.rollback()
      logger.error("Failed to insert vulnerability_product (%d, %s, %d-%d): %s" 
                  % (product_id, vstring, cve_year, cve_id, e))
      return False
    else:
      logger.debug("Inserted vulnerability_product CVE-%d-%d > %d / %s" % (cve_year, cve_id, product_id, product_version))
      self.conn.commit()
      return True

  def product_get_vulnerabilities(self, product_id, product_version):
    c = self.conn.cursor()

    # Build SQL query
    query_string = """SELECT cve_year, cve_id 
      FROM vulnerability_product
      WHERE product_id = ? """
    
    # Build tuple of arguments to pass to SQL
    tuple = (product_id,)

    # Differentiate between IS NULL checks and equals value checks
    for i in xrange(min(len(product_version), len(VERSION_FIELDS))):
      if product_version[i] == None:
        query_string += " AND product_version_" + VERSION_FIELDS[i] + " IS NULL"
      else:
        tuple += (product_version[i],)
        query_string += " AND product_version_" + VERSION_FIELDS[i] + " = ?"

    c.execute(query_string, tuple)

    # Fetch all vulnerabilities
    return c.fetchall()

  def config_get(self, key):
    c = self.conn.cursor()
    c.execute("SELECT value FROM config WHERE key = ?", (key,))
    val = c.fetchone() or [None]
    return val[0]

  def config_set(self, key, val):
    c = self.conn.cursor()
    try:
      # Attempt to insert key
      c.execute("INSERT INTO config VALUES (?, ?)", (key, val))
    except Exception, e:
      try:
        # Failing that, update key already set
        c.execute("UPDATE config SET value = ? WHERE key = ?", (val, key))
      except Exception, e2:
        # Failing that, accept failure
        return False
    finally:
      # Report success
      return True

  def salt_get(self):
    return self.config_get('salt')

  def salt_set(self, salt):
    return self.config_set('salt', salt)



