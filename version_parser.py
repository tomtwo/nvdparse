import re
from string import maketrans

def parse_version(product, version_string):
  i = product
  version = []

  if i == 0:        # flash_player
    version = parse_flash_version(version_string)
  elif i == 1:   # java jre
    version = parse_jre_version(version_string)
  elif i == 2:   # silverlight
    version = parse_silverlight_version(version_string)
  elif i == 3:   # quicktime
    version = parse_quicktime_version(version_string)

  while len(version) < 4:
    version.append(0)

  return version

def parse_flash_version(v):
  if ("mx" in v 
        or "r" in v 
        or "cs" in v):
    logger.info("Skipping over flash product: %s" % v)
    return null

  # Translate "d" to a . if it's there
  v = v.translate(maketrans("d", "."))

  vs = v.split('.')                         # get each version part

  for i in xrange(len(vs)):
    if vs[i] == '':
      vs[i] = '0'

  vs = map(int, vs)                                       # cast all strings to ints

  while len(vs) < 4:
    # Need to add missing suffix string for .0 releases which aren't specified
    vs.append(0)

  return vs

def parse_quicktime_version(v):
  # example: 7.7.2.0 (usually just 7.7.2)
  vs = v.split('.')
  vs = map(int, vs)

  while len(vs) < 4:
    vs.append(0)

  return vs

def parse_silverlight_version(v):
  # example: 5.0.60818.0
  vs = v.split('.')
  vs = map(int, vs)

  return vs

def parse_jre_version(v):
  # example: 1.5.0:update_55, 1.5.0:update5, 1.4.2_38
  half = v.split(':')                       # split main version from update part
  vs = half[0].split('.')                                 # split main version into major/minor/rev parts
  
  # the 1.4.2_38 case
  vs2 = vs[2].split('_')
  if len(vs2) > 1:
    vs[2] = vs2[0]
    vs.append(vs2[1]) # awful TODO

  if len(half) > 1:                                       # contains update_ prefix?
    vs.append(re.sub("[^0-9]", "", half[1]))              # remove non-numeric chars 

  while len(vs) < 4:
    vs.append(0)
  
  vs = map(int, vs)                                       # cast strings to ints

  return vs