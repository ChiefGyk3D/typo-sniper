"""
Typo Sniper - Advanced Domain Typosquatting Detection Tool

A powerful tool for detecting and monitoring potential typosquatting domains.
"""

__version__ = "1.0.3"
__author__ = "chiefgyk3d"
__license__ = "MPL-2.0"

from .config import Config
from .cache import Cache
from .scanner import DomainScanner

__all__ = ['Config', 'Cache', 'DomainScanner']
