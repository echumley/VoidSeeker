#!/usr/bin/env python3
"""
VoidSeeker - Deep Web Service Enumeration & Fingerprinting

A Python-based reconnaissance tool for discovering and fingerprinting hidden
services, management interfaces, and infrastructure endpoints using multi-source
intelligence (DNS, HTTP, Shodan, port scanning).

Version: 1.0.0
Author: VoidSeeker Contributors
License: MIT
"""
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from config.logging_config import setup_logging
from voidseeker.core.menu import main

__version__ = "1.0.0"
__author__ = "VoidSeeker Contributors"

# Initialize logging
logger = setup_logging("voidseeker.main")

if __name__ == "__main__":
    try:
        logger.info("=" * 80)
        logger.info(f"VoidSeeker v{__version__} started")
        logger.info("=" * 80)
        main()
        logger.info("VoidSeeker completed successfully")
    except KeyboardInterrupt:
        logger.info("VoidSeeker interrupted by user (CTRL+C)")
        print("\nExiting...")
        sys.exit(0)
    except Exception as e:
        logger.exception(f"Fatal error: {type(e).__name__}: {e}")
        print(f"\nFatal error: {e}", file=sys.stderr)
        sys.exit(1)


