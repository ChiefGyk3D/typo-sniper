"""
Typo Sniper - Advanced Domain Typosquatting Detection Tool

A powerful tool for detecting and monitoring potential typosquatting domains.
"""

__version__ = "1.1"
__author__ = "chiefgyk3d"
__license__ = "AGPL-3.0-or-later"

from .config import Config
from .cache import Cache
from .scanner import DomainScanner

__all__ = ['Config', 'Cache', 'DomainScanner']
