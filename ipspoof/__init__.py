"""ipspoof — HTTP header/IP allowlist bypass discovery tool."""

__version__ = "2.0.3"
__author__ = "Exript (S. Engin ÖZLEM)"
__license__ = "MIT"

from .cli import main

__all__ = ["main", "__version__"]
