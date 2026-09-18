import os
import sys

# Mirror the app entrypoints (run.py, asphalt_cli.py, ui_app.py), which put src/ on the path.
SRC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src")
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)
