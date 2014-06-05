from lxml import etree
import re

class Vulnerability:
  def __init__(self, entry, nsmap, product_filter):
    self.id = entry.xpath('vuln:cve-id/text()', namespaces=nsmap)[0] # Pick first from list
    
    cve = self.id.split("-")
    self.cve_year = int(cve[1])
    self.cve_id = int(cve[2])

    self.date_published = entry.xpath('vuln:published-datetime/text()', namespaces=nsmap)
    self.summary = entry.xpath('vuln:summary/text()', namespaces=nsmap)[0]
    self.products = []
    self.contains_filtered_product = False

    products = entry.xpath('vuln:vulnerable-software-list/vuln:product', namespaces=nsmap)
    for p in products:
      pr = Product.fromString(p.text)

      if len(pr.version): # We don't want to deal with versionless products!
        # Is this a product we're interested in?
        is_needle = pr.existsIn(product_filter)

        self.contains_filtered_product |= is_needle

        if is_needle:
          self.products.append(pr)
        else:
          del pr

  def __str__(self):
    return "Vuln %s>>> %s" % (self.id, "contains queried product" if self.contains_filtered_product else "")

  def print_products(self):
    for p in self.products:
      print "\t", p

  def get_product_ids(self):
    ids = []
    for p in self.products:
      ids.append(p.id)
    return ids

class Product:
  global_product_map = {}
  global_product_list = []
  id_seed = 0

  def __init__(self, type, vendor, product, version):
    self.id = Product.genUID()
    self.type = type
    self.vendor = vendor
    self.product = product
    self.version = version

  def __str__(self):
    return "%i %s %s %s" % (self.id, self.vendor, self.product, self.version)

  def isFlash(self):
    return self.vendor == "adobe" and self.product == "flash_player"

  def existsIn(self, product_list):
    for product in product_list:
      if self.vendor == product[0] and self.product == product[1]:
        return True

    # Not in product list!
    return False

  def isPlugin(self, plugins):
    return self.existsIn(plugins)

  def equalTo(self, primitive_product):
    # primitive_product is a (vendor, product) pair
    return primitive_product[0] == self.vendor and primitive_product[1] == self.product

  @classmethod
  def genUID(_class):
    uid = _class.id_seed
    _class.id_seed += 1
    return uid

  @classmethod
  def fromUID(_class, product_id):
    return _class.global_product_list[product_id]

  @classmethod
  def fromString(_class, product_string):
    # Follows CPE naming standard
    # ex: cpe:/a:apple:safari:6.0
    # ex: cpe:/o:apple:mac_os_x:10.8.2

    if product_string in _class.global_product_map:
      # Already exists, we can just lookup and return that
      return _class.global_product_map[product_string]

    else:
      # Does not exist, we must create it

      parts = product_string.split(':')

      if(parts[0] != 'cpe'):
        # Invalid
        raise Exception("Not a CPE product identifier")

      type = parts[1][1] # a(pplication) | o(perating system) | h(ardware)
      vendor = parts[2]
      product = parts[3]
      
      if len(parts) > 4:
        version = parts[4]

        if len(parts) > 5 and len(parts[5]) > 0 and Util.contains_digit(parts[5]):
          # Any more version info to add?
          version += ':' + parts[5]
      else:
        # Has no version information attached
        version = ''

      instance = _class(type, vendor, product, version)

      # Add to global product list
      _class.global_product_map[product_string] = instance
      _class.global_product_list.append(instance)

      return instance

# Parses a single NVD XML file
class NVDFileParser:
  def __init__(self, filename, product_filter=[]):
    self.tree = etree.parse(filename)
    self.product_filter = product_filter
    self.nsmap = self.get_namespaces()

  def get_namespaces(self):
    nsmap = {}
    for ns in self.tree.xpath('//namespace::*'):
      if ns[0]: # Removes the None namespace, neither needed nor supported.
        nsmap[ns[0]] = ns[1]
      else: # We actually do need it for the default namespace
        nsmap['def'] = ns[1]
    return nsmap

  def get_vulnerabilities(self):
    vulnerabilities = []
    apply_filter = len(self.product_filter) > 0
    for entry_node in self.tree.xpath('//def:entry', namespaces=self.nsmap):
      vulnerability = Vulnerability(entry_node, self.nsmap, self.product_filter)
      
      if apply_filter and not vulnerability.contains_filtered_product:
        del vulnerability
        continue
      
      vulnerabilities.append(vulnerability)
    return vulnerabilities


class Util:
  _digit_search = re.compile('\d')

  @classmethod
  def contains_digit(_class, d):
    return bool(_class._digit_search.search(d))

  @classmethod
  def parse_version(_class, version_string):
    # Generate list of numbers (string values)
    vs = re.findall(r'\d+', version_string)

    # Convert the strings to integers
    vs = map(int, vs)

    # If the version is shorter than 4 wide, we append nothings
    while(len(vs) < 4):
      vs.append(None)

    # Limit to 4 version numbers
    return vs[:4]

