import os
import sys

# Add the `src/core` directory to the Python path
core_dir = os.path.dirname(os.path.abspath(__file__))
if core_dir not in sys.path:
    sys.path.insert(0, core_dir)