#!/usr/bin/env python
"""
Asphalt launcher - use this as your CLI.
"""
import sys
import os

# Add src to path
current_dir = os.path.dirname(os.path.abspath(__file__))
src_path = os.path.join(current_dir, 'src')
sys.path.insert(0, src_path)

# Import and run
from asphalt_cli.capture import capture

if __name__ == "__main__":
    # Handle --help globally
    if "--help" in sys.argv or "-h" in sys.argv or len(sys.argv) == 1:
        print("Asphalt - Packet Capture Tool")
        print("=" * 50)
        print("\nUsage:")
        print("  asphalt --interface list")
        print("  asphalt --interface <name> --duration <seconds>")
        print("\nExamples:")
        print("  asphalt --interface Ethernet --duration 5")
        print("  asphalt --interface Ethernet --filter 'tcp port 80'")
        sys.exit(0)
    
    capture()
