#!/usr/bin/env python

import sys, os, logging
from database import Database

logging.basicConfig(level=logging.INFO, format="%(name)-8s: %(levelname)-8s %(message)s")
logger = logging.getLogger("setupdb")

if len(sys.argv) < 2:
  sys.exit("Usage: %s [new sqlite db file]" % (sys.argv[0]))

#if os.path.exists(sys.argv[1]):
#  sys.exit("Error: path '%s' already exists" % (sys.argv[1]))

filename = sys.argv[1]

logger.info("%s db in %s.." % (("Reading" if os.path.exists(filename) else "Creating"), filename))

d = Database(filename)
