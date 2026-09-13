#!/usr/bin/env python
"""
Asphalt CLI entry point for setuptools.
"""
import sys
import os

# Add src to path (in case it's not there)
src_dir = os.path.join(os.path.dirname(__file__))
if src_dir not in sys.path:
    sys.path.insert(0, src_dir)

from asphalt_cli.main import cli

if __name__ == "__main__":
    cli()