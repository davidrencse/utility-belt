#!/usr/bin/env python
"""
Asphalt CLI launcher - run this as your main command.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

# Import and run the CLI
from asphalt_cli.main import cli

if __name__ == "__main__":
    cli()