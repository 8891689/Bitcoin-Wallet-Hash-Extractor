//  g++ -o wallet_Details wallet_Details.cpp libdb.a libsqlite3.a
//  author: https://github.com/8891689
#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <stdexcept>
#include <cstdint>
#include <cstring>
#include <algorithm>
#include <cctype>
#include <dirent.h>
#include <db.h>      // Berkeley DB header
#include <sqlite3.h> // SQLite header
#include <iomanip>   // For std::setw, std::setfill
#include <cstdlib>   // For EXIT_FAILURE, EXIT_SUCCESS (although returning 0 or 1 is more common)
#include <map>
#include <set>       // Not used in current code, but kept from original
#include <cstdio>    // For sprintf in alternative toHex
#include <system_error> // For opendir error reporting

// --- Constants and Error Class ---
const size_t INITIAL_BUFFER_SIZE = 4 * 1024;
const size_t MAX_BUFFER_SIZE = 4 * 1024 * 4096; // Limit record size

class SerializationError : public std::runtime_error {
public:
    explicit SerializationError(const std::string& msg) : std::runtime_error(msg) {}
};

// --- BCDataStream Class (Corrected version with explicit little-endian reads) ---
class BCDataStream {
private:
    const uint8_t* data_ptr;
    size_t data_size;
    size_t read_cursor;

public:
    BCDataStream() : data_ptr(nullptr), data_size(0), read_cursor(0) {}

    void setInput(const uint8_t* ptr, size_t size) {
        data_ptr = ptr;
        data_size = size;
        read_cursor = 0;
    }
    // Overload for vector convenience
    void setInput(const std::vector<uint8_t>& data) {
        setInput(data.data(), data.size());
    }

    void clear() { data_ptr = nullptr; data_size = 0; read_cursor = 0; }
    size_t size() const { return data_size - read_cursor; } // Returns remaining size
    bool empty() const { return read_cursor >= data_size; }
    size_t getCursor() const { return read_cursor; }
    void setCursor(size_t cursor) { // Be careful setting cursor, ensure it's within bounds
        if (cursor > data_size) throw std::out_of_range("Cursor set past end of buffer");
        read_cursor = cursor;
    }

    const uint8_t* peekBytes(size_t length) const {
        if (read_cursor + length > data_size) throw SerializationError("Attempt to peek past end of buffer");
        return data_ptr + read_cursor;
    }

    std::vector<uint8_t> readBytes(size_t length) {
        if (read_cursor + length > data_size) {
            std::ostringstream oss; oss << "Attempt to read " << length << " bytes past end of buffer. Cursor: " << read_cursor << ", Size: " << data_size;
            throw SerializationError(oss.str());
        }
        // Use pointer arithmetic for potentially better performance than vector iterators
        std::vector<uint8_t> out(data_ptr + read_cursor, data_ptr + read_cursor + length);
        read_cursor += length;
        return out;
    }

    void skipBytes(size_t length) {
        if (read_cursor + length > data_size) {
            std::ostringstream oss; oss << "Attempt to skip " << length << " bytes past end of buffer. Cursor: " << read_cursor << ", Size: " << data_size;
            throw SerializationError(oss.str());
        }
        read_cursor += length;
    }

    // Explicit Little-Endian Reads
    uint16_t readUint16() {
         if (read_cursor + 2 > data_size) throw SerializationError("Attempt to read past end of buffer (uint16)");
         uint16_t val = (static_cast<uint16_t>(data_ptr[read_cursor + 0])) |
                        (static_cast<uint16_t>(data_ptr[read_cursor + 1]) << 8);
         read_cursor += 2;
         return val;
    }

    uint32_t readUint32() {
        if (read_cursor + 4 > data_size) throw SerializationError("Attempt to read past end of buffer (uint32)");
        uint32_t val = (static_cast<uint32_t>(data_ptr[read_cursor + 0]))       |
                       (static_cast<uint32_t>(data_ptr[read_cursor + 1]) << 8)  |
                       (static_cast<uint32_t>(data_ptr[read_cursor + 2]) << 16) |
                       (static_cast<uint32_t>(data_ptr[read_cursor + 3]) << 24);
        read_cursor += 4;
        return val;
    }

    uint64_t readUint64() {
        if (read_cursor + 8 > data_size) throw SerializationError("Attempt to read past end of buffer (uint64)");
         uint64_t val = (static_cast<uint64_t>(data_ptr[read_cursor+0]))       |
                        (static_cast<uint64_t>(data_ptr[read_cursor+1]) << 8)  |
                        (static_cast<uint64_t>(data_ptr[read_cursor+2]) << 16) |
                        (static_cast<uint64_t>(data_ptr[read_cursor+3]) << 24) |
                        (static_cast<uint64_t>(data_ptr[read_cursor+4]) << 32) |
                        (static_cast<uint64_t>(data_ptr[read_cursor+5]) << 40) |
                        (static_cast<uint64_t>(data_ptr[read_cursor+6]) << 48) |
                        (static_cast<uint64_t>(data_ptr[read_cursor+7]) << 56);
        read_cursor += 8;
        return val;
    }


    uint64_t readCompactSize() {
        if (read_cursor >= data_size) throw SerializationError("Attempt to read past end of buffer (compact size indicator)");
        uint8_t c = data_ptr[read_cursor++];
        if (c < 253) return c;
        else if (c == 253) { return readUint16(); } // Use LE reader
        else if (c == 254) { return readUint32(); } // Use LE reader
        else { /* c == 255 */ return readUint64(); } // Use LE reader
        // Original code had specific error checks before calling memcpy, now handled by readUintXX
        // Original code also threw error for 255, corrected to read uint64
    }

    std::string readStringWithCompactSize() {
        uint64_t len = readCompactSize();
        if (len > MAX_BUFFER_SIZE) { // Check against a reasonable limit
             std::ostringstream oss; oss << "String length (" << len << ") exceeds limit (" << MAX_BUFFER_SIZE << ")";
             throw SerializationError(oss.str());
        }
        if (read_cursor + static_cast<size_t>(len) > data_size) { // Ensure len fits size_t after check
             std::ostringstream oss; oss << "String read length (" << len << ") exceeds buffer size. Cursor: " << read_cursor << ", Available: " << (data_size - read_cursor);
            throw SerializationError(oss.str());
        }
        auto bytes = readBytes(static_cast<size_t>(len));
        return std::string(bytes.begin(), bytes.end());
    }
};

// --- Data structures ---
struct MKeyData { std::vector<uint8_t> encrypted_key, salt; uint32_t derivationMethod = 0, derivationIterations = 0; bool found = false;};
struct KeyData { std::vector<uint8_t> private_key, public_key; uint32_t timestamp = 0; };
struct AddressData { std::string address; std::string label; };

// Type alias for the in-memory map
using WalletDataMap = std::map<std::vector<uint8_t>, std::vector<uint8_t>>;

// Enum to indicate the source database type
enum class DbSourceType { UNKNOWN, BDB, SQLITE_SPECIAL };

// --- Utility Functions ---
// toHex (using iomanip for potentially cleaner output)
static std::string toHex(const uint8_t* data, size_t len) {
    if (!data || len == 0) return "";
    std::ostringstream oss;
    oss << std::hex << std::setfill('0'); // Set flags once
    for (size_t i = 0; i < len; ++i) {
        oss << std::setw(2) << static_cast<int>(data[i]);
    }
    return oss.str();
}
static std::string toHex(const std::vector<uint8_t>& data) {
    return toHex(data.data(), data.size());
}

// toHex_sprintf (alternative, kept for reference)
static std::string toHex_sprintf(const uint8_t* data, size_t len) {
    if (data == nullptr || len == 0) return "[null or zero len]";
    std::string result;
    result.reserve(len * 2);
    char hexbuf[3];
    for (size_t i = 0; i < len; ++i) {
        sprintf(hexbuf, "%02x", data[i]);
        result.append(hexbuf);
    }
    return result;
}
static std::string toHex_sprintf(const std::vector<uint8_t>& data) {
    return toHex_sprintf(data.data(), data.size());
}


// BDB db_cursor_get (needed for read_all_bdb)
int db_cursor_get(DBC* cursor, DBT* keyt, DBT* valt, uint32_t flags,
                  std::vector<uint8_t>& key_buf, std::vector<uint8_t>& val_buf) {
    // Reset sizes, set user memory flags
    keyt->data = key_buf.data(); keyt->ulen = key_buf.size(); keyt->size = 0; keyt->flags = DB_DBT_USERMEM;
    valt->data = val_buf.data(); valt->ulen = val_buf.size(); valt->size = 0; valt->flags = DB_DBT_USERMEM;

    int ret = cursor->c_get(cursor, keyt, valt, flags);

    if (ret == DB_BUFFER_SMALL) {
        if (keyt->size > MAX_BUFFER_SIZE || valt->size > MAX_BUFFER_SIZE) {
            std::cerr << "Error: BDB record size exceeds MAX_BUFFER_SIZE limit. Key req: " << keyt->size << ", Val req: " << valt->size << std::endl;
            return DB_BUFFER_SMALL; // Return the error code, let caller handle it
        }
        try {
            // Resize slightly larger than needed to avoid repeated small resizes
            if (key_buf.size() < keyt->size) key_buf.resize(keyt->size + 1024);
            if (val_buf.size() < valt->size) val_buf.resize(valt->size + 1024);
        } catch (const std::bad_alloc& ba) {
            std::cerr << "Error: Memory allocation failed resizing BDB buffer: " << ba.what() << std::endl;
            return -1; // Indicate critical memory error
        }
        // Update DBT pointers and sizes after resize
        keyt->data = key_buf.data(); keyt->ulen = key_buf.size();
        valt->data = val_buf.data(); valt->ulen = val_buf.size();
        // Retry getting the *same* record (usually DB_CURRENT is the right flag here)
        ret = cursor->c_get(cursor, keyt, valt, DB_CURRENT);
        if (ret != 0) {
             std::cerr << "Error: Failed BDB c_get (DB_CURRENT) after resize: " << db_strerror(ret) << std::endl;
        }
    }
    return ret;
}

// --- Database Reading Functions ---
// Reads all data from a Berkeley DB file into the map
bool read_all_bdb(const char* walletfile, WalletDataMap& data_map) {
    DB* dbp = nullptr;
    DBC* cursor = nullptr;
    int ret = 0;
    bool success = false;

    std::cout << "Info: Attempting to read all data from BDB: " << walletfile << std::endl;
    ret = db_create(&dbp, nullptr, 0);
    if (ret != 0) { std::cerr << "Error (BDB read_all): db_create failed: " << db_strerror(ret) << std::endl; return false; }

    // Ensure 'main' dbname is used
    ret = dbp->open(dbp, nullptr, walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD, 0);
    if (ret != 0) { std::cerr << "Error (BDB read_all): dbp->open ('" << walletfile << "', 'main') failed: " << db_strerror(ret) << std::endl; if (dbp) dbp->close(dbp, 0); return false; }

    ret = dbp->cursor(dbp, nullptr, &cursor, 0);
    if (ret != 0) { std::cerr << "Error (BDB read_all): dbp->cursor failed: " << db_strerror(ret) << std::endl; dbp->close(dbp, 0); return false; }

    DBT keyt = {0}, valt = {0};
    std::vector<uint8_t> key_buf(INITIAL_BUFFER_SIZE);
    std::vector<uint8_t> val_buf(INITIAL_BUFFER_SIZE);
    int record_count = 0;

    while ((ret = db_cursor_get(cursor, &keyt, &valt, DB_NEXT, key_buf, val_buf)) == 0) {
        try {
             // Copy data into the map (Ensure size is correct from DBT)
             std::vector<uint8_t> current_key(static_cast<uint8_t*>(keyt.data), static_cast<uint8_t*>(keyt.data) + keyt.size);
             std::vector<uint8_t> current_value(static_cast<uint8_t*>(valt.data), static_cast<uint8_t*>(valt.data) + valt.size);
             data_map[std::move(current_key)] = std::move(current_value); // Use move semantics
             record_count++;
        } catch (const std::exception& e) {
             std:: cerr << "Error processing BDB record " << record_count << ": " << e.what() << std::endl;
             // Optionally break or continue on error
        }
    }

    if (ret != DB_NOTFOUND) { // DB_NOTFOUND is normal loop termination
        std::cerr << "Error during BDB cursor iteration (read_all): " << db_strerror(ret);
        if (ret == DB_BUFFER_SMALL) std::cerr << " (Stopped due to MAX_BUFFER_SIZE limit)";
        else if (ret == -1) std::cerr << " (Stopped due to memory allocation failure)";
        std::cerr << std::endl;
        // success remains false
    } else {
        success = true; // Reached end of database successfully
        std::cout << "Info: Successfully read " << record_count << " records from BDB." << std::endl;
    }

    if (cursor) cursor->c_close(cursor);
    if (dbp) dbp->close(dbp, 0);
    return success;
}

// Reads all data from the special SQLite file format ('main' table) into the map
bool read_all_sqlite_special(const char* walletfile, WalletDataMap& data_map) {
    sqlite3 *db_sqlite = nullptr;
    sqlite3_stmt *stmt = nullptr;
    int rc = 0;
    bool success = false;

    std::cout << "Info: Attempting to read all data from SQLite: " << walletfile << std::endl;
    // Use URI for read-only mode if supported, otherwise fallback
    rc = sqlite3_open_v2(walletfile, &db_sqlite, SQLITE_OPEN_READONLY, nullptr);
    if (rc != SQLITE_OK) {
         // Fallback to standard open if URI/RO failed
         rc = sqlite3_open(walletfile, &db_sqlite);
         if (rc != SQLITE_OK) {
              std::cerr << "Error (SQLite read_all): Failed to open file '" << walletfile << "': " << sqlite3_errmsg(db_sqlite) << std::endl;
              if(db_sqlite) sqlite3_close(db_sqlite);
              return false;
         }
         std::cout << "Warning (SQLite read_all): Opened in read-write mode as read-only failed." << std::endl;
    }

    const char *sql = "SELECT key, value FROM main;";
    rc = sqlite3_prepare_v2(db_sqlite, sql, -1, &stmt, nullptr);
    if (rc != SQLITE_OK) { std::cerr << "Error (SQLite read_all): Failed to prepare query '" << sql << "': " << sqlite3_errmsg(db_sqlite) << std::endl; sqlite3_close(db_sqlite); return false; }

    int record_count = 0;
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
         try {
             const void *key_blob = sqlite3_column_blob(stmt, 0); // Use void*
             int key_size = sqlite3_column_bytes(stmt, 0);
             const void *value_blob = sqlite3_column_blob(stmt, 1); // Use void*
             int value_size = sqlite3_column_bytes(stmt, 1);

             // Check for null blobs or zero key size
             if (key_blob && key_size > 0 && value_blob) {
                 // Cast void* to const uint8_t* for vector construction
                 const uint8_t *key_data = static_cast<const uint8_t*>(key_blob);
                 const uint8_t *value_data = static_cast<const uint8_t*>(value_blob);

                 std::vector<uint8_t> current_key(key_data, key_data + key_size);
                 std::vector<uint8_t> current_value(value_data, value_data + value_size);
                 data_map[std::move(current_key)] = std::move(current_value); // Use move semantics
                 record_count++;
             } else {
                  std::cerr << "Warning (SQLite read_all): Skipping record " << record_count << " due to null key/value or zero key size." << std::endl;
             }
         } catch (const std::exception& e) {
              std:: cerr << "Error processing SQLite record " << record_count << ": " << e.what() << std::endl;
              // Optionally break or continue
         }
    }

    if (rc != SQLITE_DONE) {
        std::cerr << "Error during SQLite step execution (read_all): " << sqlite3_errmsg(db_sqlite) << std::endl;
        // success remains false
    } else {
        success = true; // Reached end of results successfully
        std::cout << "Info: Successfully read " << record_count << " records from SQLite." << std::endl;
    }

    sqlite3_finalize(stmt); // Finalize statement before closing DB
    sqlite3_close(db_sqlite);
    return success;
}

// Tries BDB first, then SQLite if BDB fails for *any* reason during open
bool choose_and_read_all_data(const char* walletfile, WalletDataMap& data_map, DbSourceType& source_type) {
    DB* dbp_check = nullptr;
    int ret_check = db_create(&dbp_check, nullptr, 0);
    bool read_ok = false;
    source_type = DbSourceType::UNKNOWN;

    if (ret_check != 0) {
        std::cerr << "Error: Failed to create BDB check object: " << db_strerror(ret_check) << std::endl;
        return false; // Cannot proceed without BDB check object
    }

    std::cout << "Info: Attempting to open '" << walletfile << "' with BDB ('main' db) for format check..." << std::endl;
    // Check specifically with "main" dbname
    ret_check = dbp_check->open(dbp_check, nullptr, walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD, 0);

    if (ret_check == 0) {
        // BDB opened successfully with "main", this is likely a BDB wallet
        std::cout << "Info: Detected BDB format ('main' database opened)." << std::endl;
        if (dbp_check) dbp_check->close(dbp_check, 0); // Close the check handle
        source_type = DbSourceType::BDB;
        read_ok = read_all_bdb(walletfile, data_map); // Read using the BDB reader
    } else {
        // BDB open failed (e.g., file not found, permission denied, or format error)
        std::string bdb_err_str = db_strerror(ret_check); // Get error string before closing
        if (dbp_check) dbp_check->close(dbp_check, 0); // Close the check handle

        std::cout << "Info: BDB open failed (Reason: " << bdb_err_str << "). Attempting SQLite read as fallback." << std::endl;
        source_type = DbSourceType::SQLITE_SPECIAL;
        read_ok = read_all_sqlite_special(walletfile, data_map); // Try reading using SQLite reader

        // If SQLite also fails, read_ok will remain false, and source_type will be SQLITE_SPECIAL (the last attempt)
    }

    if (!read_ok) {
         std::cerr << "Error: Failed to read wallet data using both BDB and SQLite methods for file: " << walletfile << std::endl;
    }

    return read_ok;
}
// --- Data Parsing Functions (Operating on the map) ---

// Parses all known record types from the in-memory map
bool parse_data_from_map(
    const WalletDataMap& data_map,
    DbSourceType source_type, // Source is now mainly for context/debugging
    MKeyData& mkey_data,
    std::vector<KeyData>& keys,
    std::map<std::vector<uint8_t>, uint32_t>& pubkey_timestamps,
    std::vector<AddressData>& addresses)
{
    BCDataStream kds, vds;
    int parsed_mkey = 0, parsed_keys = 0, parsed_names = 0, parsed_meta = 0;
    bool overall_success = true; // Tracks if any record failed parsing

    std::cout << "Info: Parsing " << data_map.size() << " records from in-memory map..." << std::endl;

    // Define the special SQLite mkey key constant
    const std::vector<uint8_t> SQLITE_MKEY_CONST_KEY = {0x04, 'm', 'k', 'e', 'y', 0x01, 0x00, 0x00, 0x00};

    for (const auto& pair : data_map) {
        const std::vector<uint8_t>& raw_key = pair.first;
        const std::vector<uint8_t>& raw_value = pair.second;

        // Skip empty keys or values if they somehow exist
        if (raw_key.empty() || raw_value.empty()) {
             std::cerr << "Warning: Skipping record with empty key or value." << std::endl;
             continue;
        }

        kds.clear(); // Clear streams for each record
        vds.clear();
        kds.setInput(raw_key);
        vds.setInput(raw_value);

        std::string type;
        bool is_mkey_record = false;

        // --- Determine record type and if it's the mkey ---
        try {
            // For SQLite, check if the key matches the special mkey constant
            if (source_type == DbSourceType::SQLITE_SPECIAL && raw_key == SQLITE_MKEY_CONST_KEY) {
                type = "mkey"; // Treat it as type "mkey" for unified logic
                is_mkey_record = true;
                 //std::cout << "DEBUG: Found SQLite special mkey constant key." << std::endl;
            } else {
                // For BDB (or potentially other records in SQLite), parse type from key
                type = kds.readStringWithCompactSize(); // Read type from key stream
                 if (type == "mkey") {
                     is_mkey_record = true;
                     //std::cout << "DEBUG: Found 'mkey' type string in key." << std::endl;
                 }
            }
        } catch (const SerializationError& e) {
            std::cerr << "Warning: Failed to parse key header for record with key [" << toHex(raw_key) << "]: " << e.what() << std::endl;
            overall_success = false;
            continue; // Skip this record
        } catch (const std::exception& e) { // Catch other potential errors like bad_alloc
            std::cerr << "Warning: Unexpected error parsing key header for record with key [" << toHex(raw_key) << "]: " << e.what() << std::endl;
            overall_success = false;
            continue;
        }

        // --- Process based on determined type ---
        try {
            if (is_mkey_record) {
                if (mkey_data.found) { // Should only be one mkey
                    std::cerr << "Warning: Found multiple 'mkey' records in map. Using first one found." << std::endl;
                    continue; // Skip subsequent mkey records
                }
                //std::cout << "DEBUG: Parsing value for mkey record..." << std::endl;

                // --- Unified Parsing Logic for BDB Value or SQLite Blob using BCDataStream ---
                // The internal format of the mkey value is the same.
                // 1. Read Encrypted Key
                uint64_t enc_key_len = vds.readCompactSize();
                if (enc_key_len > vds.size()) throw SerializationError("mkey enc_key length exceeds buffer");
                mkey_data.encrypted_key = vds.readBytes(static_cast<size_t>(enc_key_len));

                // 2. Read Salt
                uint64_t salt_len = vds.readCompactSize();
                if (salt_len > vds.size()) throw SerializationError("mkey salt length exceeds buffer");
                mkey_data.salt = vds.readBytes(static_cast<size_t>(salt_len));

                // 3. Read optional derivation info (Method + Iterations)
                if (vds.size() >= 8) { // Check if enough bytes remain
                    mkey_data.derivationMethod = vds.readUint32();     // Use BCDataStream's LE read
                    mkey_data.derivationIterations = vds.readUint32(); // Use BCDataStream's LE read
                } else {
                    mkey_data.derivationMethod = 0; // Defaults for older wallets
                    mkey_data.derivationIterations = 0; // Using 0 as default
                }
                // --- End Unified Parsing Logic ---

                // Validate parsed mkey data (basic check)
                if (!mkey_data.salt.empty() && !mkey_data.encrypted_key.empty()) {
                    mkey_data.found = true;
                    parsed_mkey++;
                    std::cout << "Info: Successfully parsed 'mkey' data." << std::endl;
                    //std::cout << "DEBUG: Parsed Salt Hex: " << toHex(mkey_data.salt) << std::endl;
                    //std::cout << "DEBUG: Parsed Method: " << mkey_data.derivationMethod << std::endl;
                    //std::cout << "DEBUG: Parsed Iterations: " << mkey_data.derivationIterations << std::endl;
                } else {
                    throw SerializationError("Parsed mkey is invalid (e.g., empty salt or key)");
                }

            // --- Key/CKey Parsing ---
            } else if (type == "key" || type == "ckey") {
                KeyData kd;
                // Read public key from the rest of the key stream (kds)
                // Assuming key format is: CompactSize(type_len), type_str, CompactSize(pubkey_len), pubkey_data
                uint64_t pubkey_len = kds.readCompactSize(); // Read after type string was read
                if (pubkey_len == 0 || pubkey_len > kds.size()) throw SerializationError("Invalid pubkey length in key record");
                kd.public_key = kds.readBytes(static_cast<size_t>(pubkey_len));

                // Read private key from value stream (vds)
                // Assuming value format is: CompactSize(privkey_len), privkey_data, [optional timestamp]
                uint64_t privkey_data_len = vds.readCompactSize();
                if (privkey_data_len > vds.size()) throw SerializationError("Private key data length exceeds value buffer");
                kd.private_key = vds.readBytes(static_cast<size_t>(privkey_data_len));

                // Read optional timestamp from value stream if bytes remain
                if (vds.size() >= 4) {
                     // Simple check: assume remaining 4 bytes are timestamp if present
                     // More robust check might involve looking at timestamp range if known
                     try { kd.timestamp = vds.readUint32(); }
                     catch (const SerializationError&) { kd.timestamp = 0; } // Ignore error if no timestamp bytes
                } else { kd.timestamp = 0;}

                keys.push_back(std::move(kd)); // Use move
                parsed_keys++;

            // --- Name Parsing ---
            } else if (type == "name") {
                 AddressData ad;
                 // Read address string from the rest of the key stream (kds)
                 // Assuming key format: CompactSize(type_len), "name", CompactSize(addr_len), addr_str
                 ad.address = kds.readStringWithCompactSize(); // Read after type string

                 // Read label from value stream (vds)
                 // Assuming value format: CompactSize(label_len), label_str
                 ad.label = vds.readStringWithCompactSize();

                 addresses.push_back(std::move(ad)); // Use move
                 parsed_names++;

            // --- KeyMeta Parsing ---
            } else if (type == "keymeta") {
                // Read pubkey from key stream (kds)
                // Assuming key format: CompactSize(type_len), "keymeta", CompactSize(pubkey_len), pubkey_data
                uint64_t pubkey_len = kds.readCompactSize(); // Read after type string
                if (pubkey_len == 0 || pubkey_len > kds.size()) throw SerializationError("Invalid pubkey length in keymeta record");
                std::vector<uint8_t> keymeta_pubkey = kds.readBytes(static_cast<size_t>(pubkey_len));

                // Read version and timestamp from value stream (vds)
                // Assuming value format: version (uint32), timestamp (uint32)
                if (vds.size() >= 8) {
                    uint32_t version = vds.readUint32(); // Read version (typically unused?)
                    uint32_t timestamp = vds.readUint32();
                    pubkey_timestamps[keymeta_pubkey] = timestamp; // Store timestamp keyed by pubkey
                    parsed_meta++;
                } else { throw SerializationError("Keymeta value too short for version+timestamp"); }
            }
            // --- Add handling for other known types if necessary ---
        } catch (const SerializationError& e) {
            std::cerr << "Warning: Failed to parse record type '" << type << "' with key [" << toHex(raw_key) << "]: " << e.what() << std::endl;
            overall_success = false; // Mark as partially failed if any record fails
        } catch (const std::exception& e) {
            std::cerr << "Warning: Unexpected error parsing record type '" << type << "' with key [" << toHex(raw_key) << "]: " << e.what() << std::endl;
            overall_success = false;
        }
    } // End map iteration

    std::cout << "Info: Parsing complete. Found: "
              << parsed_mkey << " mkey, "
              << parsed_keys << " keys, "
              << parsed_names << " names, "
              << parsed_meta << " keymeta." << std::endl;

    return overall_success; // Returns true if all records parsed without throwing, false otherwise
}

// --- print_info (Operates on parsed data structs) ---
void print_info(
    const std::string& filename,
    const MKeyData& mkey,
    const std::vector<KeyData>& keys,
    const std::map<std::vector<uint8_t>, uint32_t>& pubkey_timestamps,
    const std::vector<AddressData>& addresses)
{
    std::cout << "\n--- Wallet Info: " << filename << " ---\n";

    bool encrypted = mkey.found;
    std::cout << "Encryption Status: " << (encrypted ? "Encrypted" : "Plain/NotFound/Error") << "\n";

    if (encrypted) {
        std::cout << "  Salt: " << toHex(mkey.salt) << "\n";
        std::cout << "  Derivation Method: " << mkey.derivationMethod << "\n";
        std::cout << "  Derivation Iterations: " << mkey.derivationIterations << "\n";
        if (!mkey.encrypted_key.empty() && mkey.encrypted_key.size() >= 32) {
             // Calculate the JtR hash string here if needed
             std::vector<uint8_t> cry_master(mkey.encrypted_key.end() - 32, mkey.encrypted_key.end());
             std::string hex_master = toHex(cry_master);
             std::string hex_salt   = toHex(mkey.salt);
             std::cout << "  JtR Hash: $bitcoin$" << hex_master.size() << "$"
                       << hex_master << "$" << hex_salt.size() << "$" << hex_salt << "$"
                       << mkey.derivationIterations << "$2$00$2$00" // Assuming method 0 uses these constants
                       << "\n";
             std::cout << "  Encrypted Master Key Data (Full Size: " << mkey.encrypted_key.size() << " bytes)\n"; // Optional: Print full key if desired
        } else {
            std::cout << "  Encrypted Master Key Data: [Invalid Size or Empty]\n";
        }
    } else {
         std::cout << "  Master Key (mkey) record not found or invalid." << std::endl;
    }

    if (!keys.empty()) {
        std::cout << "\nExtracted Keys (" << keys.size() << "):\n";
        int key_count = 0;
        for (const auto& k : keys) {
            key_count++;
            std::cout << "Key #" << key_count << ":\n";
            if (!encrypted) { // Only show private key if wallet is not encrypted
                 if (!k.private_key.empty()) { std::cout << "  Private Key: " << toHex(k.private_key) << " (size " << k.private_key.size() << " bytes)\n"; }
                 else { std::cout << "  Private Key: [Empty]\n"; }
            } else { std::cout << "  Private Key: [Encrypted]\n"; }
            std::cout << "  Public Key:  " << toHex(k.public_key) << " (size " << k.public_key.size() << " bytes)\n";
            auto it = pubkey_timestamps.find(k.public_key);
            uint32_t effective_timestamp = (it != pubkey_timestamps.end()) ? it->second : k.timestamp;
            //if (effective_timestamp != 0) { std::cout << "  Timestamp:   " << effective_timestamp << " (Unix time)\n"; }
            //else { std::cout << "  Timestamp:   [Not Found]\n"; }
            // std::cout << "-------------------\n"; // Reduce verbosity
        }
         if (encrypted) { std::cout << "\nNote: Private keys are encrypted and not shown in plain text.\n"; }
    } else {
         std::cout << "\nNo Key records (type 'key' or 'ckey') parsed.\n";
    }

    if (!addresses.empty()) {
        std::cout << "\nExtracted Addresses & Labels (" << addresses.size() << "):\n";
        int addr_count = 0;
        for (const auto& ad : addresses) {
            addr_count++;
            std::cout << "Address #" << addr_count << ": " << ad.address;
            if (!ad.label.empty()) { std::cout << " (Label: " << ad.label << ")\n"; }
            else { std::cout << "\n"; }
            // std::cout << "-------------------\n"; // Reduce verbosity
        }
    } else {
         std::cout << "\nNo Address/Label records (type 'name') parsed.\n";
    }

    std::cout << "--- End Wallet Info ---\n\n";
}

// --- main function (Revised structure) ---
int main(int argc, char* argv[]) {
    std::vector<std::string> files;
    // --- File finding logic ---
    if (argc < 2) {
        std::cout << "Info: No wallet file specified, scanning current directory for .dat files..." << std::endl;
        DIR* dp = opendir(".");
        if (!dp) {
             // Use std::system_error for better OS error reporting
             std::error_code ec(errno, std::system_category());
             std::cerr << "Error opening current directory: " << ec.message() << std::endl;
            return 1;
        }
        struct dirent* ep;
        while ((ep = readdir(dp)) != nullptr) {
            // Skip "." and ".." entries
            if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0) {
                continue;
            }
            std::string n(ep->d_name);
            if (n.length() >= 4) {
                std::string suffix = n.substr(n.length() - 4);
                // Simple case-insensitive compare (might need better method on some systems)
                if (strcasecmp(suffix.c_str(), ".dat") == 0) {

                     files.push_back(n); // Add without stat check for simplicity
                 }
            }
        }
        closedir(dp);
    } else {
         std::cout << "Info: Processing files specified on command line." << std::endl;
         for (int i = 1; i < argc; i++) { files.emplace_back(argv[i]); }
    }

    if (files.empty()) {
         std::cerr << "Error: No .dat wallet files found or specified.\nUsage: " << argv[0] << " [wallet_file1.dat ...]\n";
         return 1;
    }

    // Process each file
    for (const auto& f : files) {
        std::cout << "========================================\n";
        std::cout << "Processing file: " << f << std::endl;
        std::cout << "========================================\n";
        WalletDataMap data_map;
        DbSourceType source_type = DbSourceType::UNKNOWN;

        // 1. Read all data (tries BDB then SQLite)
        bool read_success = choose_and_read_all_data(f.c_str(), data_map, source_type);

        if (read_success && !data_map.empty()) {
             // 2. Parse data from map
             MKeyData mkey_data;
             std::vector<KeyData> keys;
             std::map<std::vector<uint8_t>, uint32_t> pubkey_timestamps;
             std::vector<AddressData> addresses;

             bool parse_success = parse_data_from_map(data_map, source_type, mkey_data, keys, pubkey_timestamps, addresses);
             if (!parse_success) {
                  std::cerr << "Warning: Some records failed to parse for file '" << f << "'. Results may be incomplete." << std::endl;
             }

             // 3. Print info (includes JtR hash if encrypted)
             print_info(f, mkey_data, keys, pubkey_timestamps, addresses);

        } else {
            // Handle read failure or empty wallet
            if (!read_success) {
                std::cerr << "Critical Error: Failed to read data from wallet file '" << f << "' using both BDB and SQLite methods." << std::endl;
            } else { // read_success is true but map is empty
                std::cerr << "Warning: Wallet file '" << f << "' was read successfully but appears to be empty or contains no recognizable records." << std::endl;
            }
            // Print empty info frame for consistency
             MKeyData mkey_data; std::vector<KeyData> keys; std::map<std::vector<uint8_t>, uint32_t> ts; std::vector<AddressData> addrs;
             print_info(f, mkey_data, keys, ts, addrs);
        }
    } // End loop over files

    std::cout << "\nAll specified files processed." << std::endl;
    return 0; // Indicate successful execution
}
