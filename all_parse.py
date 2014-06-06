#!/bin/sh

./parse.py data/nvdcve-2.0-2*.xml data/nvdcve-2.0-recent.xml --products "$1"
