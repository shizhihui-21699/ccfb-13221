"""Convenience runner: python3 tests/run_tests.py"""
import os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import unittest
if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.discover(os.path.dirname(os.path.abspath(__file__)))
    sys.exit(0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1)
