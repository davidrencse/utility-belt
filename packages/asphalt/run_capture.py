#!/usr/bin/env python
"""
Asphalt CLI - Use this as your main command.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

import click

@click.group()
def cli():
    """Asphalt - Wireshark-grade packet capture and analysis."""
    pass

# Import and add commands
from asphalt_cli.capture import capture
cli.add_command(capture)

if __name__ == "__main__":
    cli()
