#!/usr/bin/env python3
# Author: 8891689
# Assist in creation ：gemini
# sudo apt update
# sudo apt install python3-bsddb3 libdb-dev # ro pip install bsddb3
import sys
import os
import sqlite3
import binascii
import struct
import argparse

# Try importing bsddb3 for BDB support
try:
    from bsddb3 import db

    BSDB3_AVAILABLE = True
except ImportError:
    db = None # Define db as None if import fails

    BSDB3_AVAILABLE = False
    # Optional: Print a warning here or check BSDB3_AVAILABLE later if needed
    # print("Warning: bsddb3 library not found. BDB wallet support disabled.", file=sys.stderr)

# Constant for SQLite mkey key (keep this too)
SQLITE_SPECIAL_MKEY_KEY = b'\x04mkey\x01\x00\x00\x00'

# ... (BCDataStream class definition follows) ...
# ... (other function definitions like read_bdb_data, read_sqlite_data etc.) ...

# Helper to convert bytes to hex string

def to_hex(data_bytes):
    return binascii.hexlify(data_bytes).decode('ascii') if data_bytes else ''

# Read CompactSize integer from byte array helper

def read_compact_size(data, cursor_ref):
    size = data[cursor_ref[0]]
    cursor_ref[0] += 1
    if size < 253:
        return size
    if size == 253:
        val = struct.unpack('<H', data[cursor_ref[0]:cursor_ref[0]+2])[0]
        cursor_ref[0] += 2
        return val
    if size == 254:
        val = struct.unpack('<I', data[cursor_ref[0]:cursor_ref[0]+4])[0]
        cursor_ref[0] += 4
        return val
    if size == 255:
        val = struct.unpack('<Q', data[cursor_ref[0]:cursor_ref[0]+8])[0]
        cursor_ref[0] += 8
        return val
    raise ValueError("Invalid CompactSize")

def read_bdb_data(filename: str) -> dict[bytes, bytes] | None:
    """Reads all key-value pairs from a BDB file (Final Error Handling)."""
    if not BSDB3_AVAILABLE:
        return None

    d = None
    cursor = None
    try:
        data_map = {}
        d = db.DB()
        # Use "main" - necessary for standard BDB wallets like 0.0014.dat
        # This will raise DBInvalidArgError for non-standard files like 8891689.dat
        d.open(filename, "main", db.DB_BTREE, db.DB_RDONLY)
        cursor = d.cursor()

        record = cursor.first()
        while record:
            key, value = record
            data_map[key] = value
            record = cursor.next()

        # Success path: close cursor and db *before* returning
        # These operations should succeed if we reached this point
        if cursor:
            cursor.close()
            cursor = None # Optional: clear reference
        if d:
            d.close()
            d = None    # Optional: clear reference

        return data_map

    except db.DBError as e:
        # This block catches errors during open, cursor creation, or reading.
        # If d.open() failed (e.g., DBInvalidArgError for non-BDB files),
        # we land here. The 'd' object might be in an invalid state.
        # The *only* safe action is to report failure.
        # DO NOT attempt cleanup (like d.close()) here, as it can cause secondary errors.
        # print(f"Debug: BDB operation failed for {filename}: {e}", file=sys.stderr) # Optional
        return None # Signal that reading as BDB failed

    except Exception as e:
        # Catch any other *unexpected* errors during BDB processing
        print(f"Unexpected non-DBError reading BDB {filename}: {e}", file=sys.stderr)
        # For truly unexpected errors, attempting cleanup might be considered,
        # but given the previous issues, it might be safer to just return None.
        # Let's keep it simple and avoid cleanup attempts here too.
        return None

    # No 'finally' block needed with this structure
        
# Parse mkey record for BDB

def parse_mkey_bdb(data_map):
    for key, value in data_map.items():
        # detect 'mkey' type
        try:
            cursor = [0]
            name_len = read_compact_size(key, cursor)
            name = key[cursor[0]:cursor[0]+name_len]
            if name != b'mkey':
                continue
        except Exception:
            continue
        # parse value blob
        try:
            cursor = [0]
            enc_len = read_compact_size(value, cursor)
            enc = value[cursor[0]:cursor[0]+enc_len]
            cursor[0] += enc_len
            salt_len = read_compact_size(value, cursor)
            salt = value[cursor[0]:cursor[0]+salt_len]
            cursor[0] += salt_len
            if len(value) - cursor[0] >= 8:
                method = struct.unpack('<I', value[cursor[0]:cursor[0]+4])[0]
                iters = struct.unpack('<I', value[cursor[0]+4:cursor[0]+8])[0]
            else:
                method, iters = 0, 1
            return enc, salt, iters, method
        except Exception:
            return None, None, None, None
    return None, None, None, None

# --- SQLite support ---

def read_sqlite_data(filename):
    try:
        conn = sqlite3.connect(f'file:{filename}?mode=ro', uri=True)
        cursor = conn.cursor()
        cursor.execute('SELECT key,value FROM main')
        data_map = {}
        for k, v in cursor.fetchall():
            if isinstance(k, (bytes, bytearray)) and isinstance(v, (bytes, bytearray)):
                data_map[bytes(k)] = bytes(v)
        conn.close()
        return data_map
    except Exception:
        return None

# Parse mkey record for SQLite map

def parse_mkey_sqlite(data_map):
    # key is fixed SQLITE_SPECIAL_MKEY_KEY
    if SQLITE_SPECIAL_MKEY_KEY not in data_map:
        return None, None, None, None
    value = data_map[SQLITE_SPECIAL_MKEY_KEY]
    try:
        cursor = [0]
        enc_len = read_compact_size(value, cursor)
        enc = value[cursor[0]:cursor[0]+enc_len]
        cursor[0] += enc_len
        salt_len = read_compact_size(value, cursor)
        salt = value[cursor[0]:cursor[0]+salt_len]
        cursor[0] += salt_len
        if len(value) - cursor[0] >= 8:
            method = struct.unpack('<I', value[cursor[0]:cursor[0]+4])[0]
            iters = struct.unpack('<I', value[cursor[0]+4:cursor[0]+8])[0]
        else:
            method, iters = 0, 1
        return enc, salt, iters, method
    except Exception:
        return None, None, None, None

# Generate JtR-compatible $bitcoin$ hash string

def generate_hash_string(enc, salt, iters, method):
    if not enc or len(enc) < 32 or not salt:
        return None
    master = enc[-32:]
    hx_master = to_hex(master)
    hx_salt = to_hex(salt)
    return f"$bitcoin${len(hx_master)}${hx_master}${len(hx_salt)}${hx_salt}${iters}$2$00$2$00"

# Main entry point

def main():
    parser = argparse.ArgumentParser(description="Extract Bitcoin wallet hash for JtR, auto-detecting BDB/SQLite.")
    parser.add_argument('files', nargs='*', help="Wallet .dat files to process. Scans CWD if none given.")
    args = parser.parse_args()

    files = args.files if args.files else [f for f in os.listdir('.') if f.lower().endswith('.dat')]
    if not files:
        sys.stderr.write("No wallet .dat files specified or found.\n")
        sys.exit(1)

    for fn in files:
        if not os.path.isfile(fn):
            sys.stderr.write(f"Warning: file not found: {fn}\n")
            continue
        # try BDB first
        data_map = read_bdb_data(fn)
        mode = 'bdb' if data_map is not None else None
        if data_map is None:
            # fallback to SQLite
            data_map = read_sqlite_data(fn)
            mode = 'sqlite' if data_map is not None else None
        if mode is None:
            sys.stderr.write(f"{fn}: not a BDB or SQLite wallet\n")
            continue
        # parse accordingly
        if mode == 'bdb':
            enc, salt, iters, method = parse_mkey_bdb(data_map)
        else:
            enc, salt, iters, method = parse_mkey_sqlite(data_map)
        if enc is None:
            sys.stderr.write(f"{fn}: failed to parse mkey record\n")
            continue
        hash_str = generate_hash_string(enc, salt, iters, method)
        if not hash_str:
            sys.stderr.write(f"{fn}: failed to generate hash string\n")
            continue
        print(hash_str)

if __name__ == '__main__':
    main()

