#!/usr/bin/env python3
"""
agent/simulator.py — Proxy runner for simulator.py in the project root.
"""
import os
import sys

root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, root_dir)

from simulator import main

if __name__ == "__main__":
    main()
