# import pytest
import os
from ida_domain_mcp.ida_tools import open_database, close_database, idb_meta

base_dir = os.path.dirname(__file__)
binary_path = os.path.join(base_dir, "challenge", "binaries", "device_main")

def test_db():
    db = open_database(binary_path)
    print(idb_meta())
    close_database(db)

test_db()
