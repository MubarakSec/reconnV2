"""Database module for persistent storage."""

from pathlib import Path

DB_PATH = Path(__file__).parent.parent.parent / "data" / "recon.db"
