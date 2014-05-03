from lxml import etree

class Vulnerability:
  def __init__(self, entry, nsmap, plugins):
    self.id = entry.xpath('vuln:cve-id/text()', namespaces=nsmap)[0] # Pick first from list
    
    cve = self.id.split("-")
    self.cve_year = int(cve[1])
    self.cve_id = int(cve[2])

    self.date_published = entry.xpath('vuln:published-datetime/text()', namespaces=nsmap)
    self.summary = entry.xpath('vuln:summary/text()', namespaces=nsmap)
    self.products = []
    self.contains_plugin = False

    products = entry.xpath('vuln:vulnerable-software-list/vuln:product', namespaces=nsmap)
    for p in products:
      pr = Product.fromString(p.text)
      self.contains_plugin |= pr.isPlugin(plugins)
      self.products.append(pr)

  def __str__(self):
    return "Vuln %s>>> %s" % (self.id, "contains plugin" if self.contains_plugin else "no plugin")

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

  def isPlugin(self, plugins):
    for plugin in plugins:
      if self.vendor == plugin[0] and self.product == plugin[1]:
        return True

    # Not a plugin!
    return False

  @classmethod
  def genUID(_class):
    uid = _class.id_seed
    _class.id_seed += 1
    return uid

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
  def __init__(self, filename, plugins):
    self.tree = etree.parse(filename)
    self.plugins = plugins
    self.nsmap = {}
    # Getting all the namespaces
    self.nsmap = {}
    for ns in self.tree.xpath('//namespace::*'):
      if ns[0]: # Removes the None namespace, neither needed nor supported.
        self.nsmap[ns[0]] = ns[1]
      else: # We actually do need it for the default namespace
        self.nsmap['def'] = ns[1]

  def get_vulnerabilities(self):
    vulnerabilities = []
    for entry_node in self.tree.xpath('//def:entry', namespaces=self.nsmap):
      vulnerability = Vulnerability(entry_node, self.nsmap, self.plugins)
      vulnerabilities.append(vulnerability)
    return vulnerabilities