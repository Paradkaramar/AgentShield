# Backward-compatibility shim for existing starter imports
from .db.database import connect, init_db, DB_PATH

__all__ = ["connect", "init_db", "DB_PATH"]
