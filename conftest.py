"""
conftest.py – Makes the project root importable during tests.
"""
import sys
from pathlib import Path

# Ensure 'app' is importable from the project root
sys.path.insert(0, str(Path(__file__).parent))
