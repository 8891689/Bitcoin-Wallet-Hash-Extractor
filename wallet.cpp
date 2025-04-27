// g++ -O2 -o wallet wallet.cpp libdb.a libsqlite3.a
/*Author: 8891689
 * Assist in creation ：gemini
 */
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
#include <db.h>
#include <sqlite3.h>
#include <iomanip>
#include <map>
#include <system_error>

// --- Constants and Error Class ---
const size_t MAX_BUFFER_SIZE = 4 * 1024 * 1024; // 4MB limit for record size

class SerializationError : public std::runtime_error {
public:
    explicit SerializationError(const std::string& msg) : std::runtime_error(msg) {}
};

// --- TYPE DEFINITIONS and ENUMS --- (Define types before they are used)
struct MKeyData {
    std::vector<uint8_t> encrypted_key;
    std::vector<uint8_t> salt;
    uint32_t derivationMethod = 0;
    uint32_t derivationIterations = 0;
    bool found = false;
};
// Type alias for the in-memory map
using WalletDataMap = std::map<std::vector<uint8_t>, std::vector<uint8_t>>;
// Enum to indicate the source database type
enum class DbSourceType { UNKNOWN, BDB, SQLITE_SPECIAL };

// --- BCDataStream Class Definition ---
class BCDataStream {
private:
    const uint8_t* data_ptr;
    size_t data_size;
    size_t read_cursor;

public:
    BCDataStream() : data_ptr(nullptr), data_size(0), read_cursor(0) {}

    void setInput(const uint8_t* ptr, size_t size) {
        data_ptr = ptr; data_size = size; read_cursor = 0;
    }
    void setInput(const std::vector<uint8_t>& data) {
        setInput(data.data(), data.size());
    }
    void clear() { data_ptr = nullptr; data_size = 0; read_cursor = 0; }
    size_t size() const { return (data_size > read_cursor) ? (data_size - read_cursor) : 0; }

    std::vector<uint8_t> readBytes(size_t length) {
        if (read_cursor + length > data_size) { throw SerializationError("Read bytes past end"); }
        std::vector<uint8_t> out(data_ptr + read_cursor, data_ptr + read_cursor + length);
        read_cursor += length; return out;
    }
    uint16_t readUint16() {
        if (read_cursor + 2 > data_size) { throw SerializationError("Read uint16 past end"); }
        uint16_t val = (static_cast<uint16_t>(data_ptr[read_cursor + 0])) | (static_cast<uint16_t>(data_ptr[read_cursor + 1]) << 8);
        read_cursor += 2; return val;
    }
    uint32_t readUint32() {
        if (read_cursor + 4 > data_size) { throw SerializationError("Read uint32 past end"); }
        uint32_t val = (static_cast<uint32_t>(data_ptr[read_cursor + 0])) | (static_cast<uint32_t>(data_ptr[read_cursor + 1]) << 8) | (static_cast<uint32_t>(data_ptr[read_cursor + 2]) << 16) | (static_cast<uint32_t>(data_ptr[read_cursor + 3]) << 24);
        read_cursor += 4; return val;
    }
    uint64_t readUint64() {
        if (read_cursor + 8 > data_size) { throw SerializationError("Read uint64 past end"); }
        uint64_t val = (static_cast<uint64_t>(data_ptr[read_cursor+0])) | (static_cast<uint64_t>(data_ptr[read_cursor+1]) << 8) | (static_cast<uint64_t>(data_ptr[read_cursor+2]) << 16) | (static_cast<uint64_t>(data_ptr[read_cursor+3]) << 24) | (static_cast<uint64_t>(data_ptr[read_cursor+4]) << 32) | (static_cast<uint64_t>(data_ptr[read_cursor+5]) << 40) | (static_cast<uint64_t>(data_ptr[read_cursor+6]) << 48) | (static_cast<uint64_t>(data_ptr[read_cursor+7]) << 56);
        read_cursor += 8; return val;
    }
    uint64_t readCompactSize() {
        if (read_cursor >= data_size) { throw SerializationError("Read compact size indicator past end"); }
        uint8_t c = data_ptr[read_cursor++];
        if (c < 253) return c;
        else if (c == 253) { return readUint16(); }
        else if (c == 254) { return readUint32(); }
        else { /* c == 255 */ return readUint64(); }
    }
     std::string readStringWithCompactSize() {
         uint64_t len = readCompactSize();
         if (len > MAX_BUFFER_SIZE) { std::ostringstream oss; oss << "String length (" << len << ") exceeds limit"; throw SerializationError(oss.str()); }
         size_t read_len = static_cast<size_t>(len);
         if (read_cursor + read_len > data_size) { throw SerializationError("String read length exceeds buffer"); }
         auto bytes = readBytes(read_len);
         return std::string(bytes.begin(), bytes.end());
    }
};

// --- Utility Function DECLARATION ---
static std::string toHex(const std::vector<uint8_t>& data);

// --- Core Function DECLARATIONS (Prototypes) ---
bool read_all_bdb(const char* walletfile, WalletDataMap& data_map);
bool read_all_sqlite_special(const char* walletfile, WalletDataMap& data_map);
bool choose_and_read_all_data(const char* walletfile, WalletDataMap& data_map, DbSourceType& source_type);
bool find_and_parse_mkey(const WalletDataMap& data_map, DbSourceType source_type, MKeyData& mkey_data);
void extract_and_print_hash(const char* filename);

// --- Core Function DEFINITIONS ---

// Reads all data from a Berkeley DB file into the map (Improved DB_BUFFER_SMALL handling)
// Errors printed here go to STDERR
bool read_all_bdb(const char* walletfile, WalletDataMap& data_map) {
    DB* dbp = nullptr; DBC* cursor = nullptr; int ret = 0; bool success = false;
    if ((ret = db_create(&dbp, nullptr, 0)) != 0) {
         // C++ Error to STDERR
         std::cerr << "Error: db_create failed in read_all_bdb for " << walletfile << ": " << db_strerror(ret) << std::endl;
         return false;
    }
    if ((ret = dbp->open(dbp, nullptr, walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD, 0)) != 0) {
         // C++ Error to STDERR
         std::cerr << "Error: dbp->open failed in read_all_bdb for " << walletfile << ": " << db_strerror(ret) << std::endl;
         if (dbp) dbp->close(dbp, 0); return false;
    }
    if ((ret = dbp->cursor(dbp, nullptr, &cursor, 0)) != 0) {
        // C++ Error to STDERR
        std::cerr << "Error: dbp->cursor failed for " << walletfile << ": " << db_strerror(ret) << std::endl;
        dbp->close(dbp, 0); return false;
    }

    DBT keyt = {0}, valt = {0};
    std::vector<uint8_t> key_buf(1024);
    std::vector<uint8_t> val_buf(4096);

    while (true) { // Loop until break
        keyt.data = key_buf.data(); keyt.ulen = key_buf.size(); keyt.flags = DB_DBT_USERMEM;
        valt.data = val_buf.data(); valt.ulen = val_buf.size(); valt.flags = DB_DBT_USERMEM;

        ret = cursor->c_get(cursor, &keyt, &valt, DB_NEXT); // Try to get next record

        if (ret == 0) {
             try {
                 data_map[std::vector<uint8_t>(static_cast<uint8_t*>(keyt.data), static_cast<uint8_t*>(keyt.data) + keyt.size)] =
                     std::vector<uint8_t>(static_cast<uint8_t*>(valt.data), static_cast<uint8_t*>(valt.data) + valt.size);
             } catch(...) { ret = -1; /* C++ Error to STDERR */ std::cerr << "Error: Memory allocation failed during map insertion for " << walletfile << std::endl; break; }
        } else if (ret == DB_BUFFER_SMALL) {
            size_t req_key_size = keyt.size; size_t req_val_size = valt.size;
            if (req_key_size > MAX_BUFFER_SIZE || req_val_size > MAX_BUFFER_SIZE) {
                // C++ Warning to STDERR
                std::cerr << "Warning: Record in " << walletfile << " exceeds MAX_BUFFER_SIZE limit. Stopping BDB read." << std::endl;
                break;
            }
            try {
                 if (key_buf.size() < req_key_size) key_buf.resize(req_key_size + 512);
                 if (val_buf.size() < req_val_size) val_buf.resize(req_val_size + 2048);
            } catch (...) { ret = -1; /* C++ Error to STDERR */ std::cerr << "Error: Memory allocation failed during buffer resize for " << walletfile << std::endl; break; }

            keyt.data = key_buf.data(); keyt.ulen = key_buf.size(); keyt.flags = DB_DBT_USERMEM;
            valt.data = val_buf.data(); valt.ulen = val_buf.size(); valt.flags = DB_DBT_USERMEM;

            ret = cursor->c_get(cursor, &keyt, &valt, DB_CURRENT);
            if (ret == 0) {
                 try {
                     data_map[std::vector<uint8_t>(static_cast<uint8_t*>(keyt.data), static_cast<uint8_t*>(keyt.data) + keyt.size)] =
                         std::vector<uint8_t>(static_cast<uint8_t*>(valt.data), static_cast<uint8_t*>(valt.data) + valt.size);
                 } catch(...) { ret = -1; /* C++ Error to STDERR */ std::cerr << "Error: Memory allocation failed during map insertion (after retry) for " << walletfile << std::endl; break; }
            } else {
                 // C++ Warning to STDERR
                 std::cerr << "Warning: BDB c_get retry failed after resize for " << walletfile << ": " << db_strerror(ret) << std::endl;
                 break;
            }
        } else if (ret == DB_NOTFOUND) {
            success = true; break;
        } else {
            // C++ Warning to STDERR
            std::cerr << "Warning: BDB read for " << walletfile << " ended with error: " << db_strerror(ret) << std::endl;
            break;
        }
    } // End while loop

    if (cursor) cursor->c_close(cursor);
    if (dbp) dbp->close(dbp, 0);
    return success;
}

// Reads all data from the special SQLite file format into the map
// Errors printed here go to STDERR
bool read_all_sqlite_special(const char* walletfile, WalletDataMap& data_map) {
    sqlite3 *db_sqlite = nullptr; sqlite3_stmt *stmt = nullptr; int rc = 0; bool success = false;
    if ((rc = sqlite3_open_v2(walletfile, &db_sqlite, SQLITE_OPEN_READONLY, nullptr)) != SQLITE_OK) {
        if ((rc = sqlite3_open(walletfile, &db_sqlite)) != SQLITE_OK) {
             // C++ Error to STDERR
             std::cerr << "Error: SQLite failed to open file '" << walletfile << "': " << sqlite3_errmsg(db_sqlite) << std::endl;
             if(db_sqlite) sqlite3_close(db_sqlite);
             return false;
        }
    }
    const char *sql = "SELECT key, value FROM main;";
    if ((rc = sqlite3_prepare_v2(db_sqlite, sql, -1, &stmt, nullptr)) != SQLITE_OK) {
         // C++ Error to STDERR
         std::cerr << "Error: SQLite failed to prepare statement for " << walletfile << ": " << sqlite3_errmsg(db_sqlite) << std::endl;
         sqlite3_close(db_sqlite); return false;
    }
    while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
        const void *k_ptr = sqlite3_column_blob(stmt, 0); int k_len = sqlite3_column_bytes(stmt, 0);
        const void *v_ptr = sqlite3_column_blob(stmt, 1); int v_len = sqlite3_column_bytes(stmt, 1);
        if (k_ptr && k_len > 0 && v_ptr) {
             try {
                 data_map[std::vector<uint8_t>(static_cast<const uint8_t*>(k_ptr), static_cast<const uint8_t*>(k_ptr) + k_len)] =
                     std::vector<uint8_t>(static_cast<const uint8_t*>(v_ptr), static_cast<const uint8_t*>(v_ptr) + v_len);
             } catch (...) { rc = SQLITE_NOMEM; /* C++ Error to STDERR */ std::cerr << "Error: Memory allocation failed during SQLite map insertion for " << walletfile << std::endl; break; }
        }
    }
    if (rc == SQLITE_DONE) success = true;
    else if (rc != SQLITE_NOMEM) { // Don't print error again if it was memory
         // C++ Warning to STDERR
         std::cerr << "Warning: SQLite read for " << walletfile << " ended with error code: " << rc << " (" << sqlite3_errmsg(db_sqlite) << ")" << std::endl;}
    sqlite3_finalize(stmt);
    sqlite3_close(db_sqlite);
    return success;
}

// Tries BDB first, then SQLite. Suppresses printing BDB error only if it's code 22.
// BDB library itself might still print its own error to stderr.
bool choose_and_read_all_data(const char* walletfile, WalletDataMap& data_map, DbSourceType& source_type) {
    DB* dbp_check = nullptr;
    int ret_check = 0;
    bool read_ok = false;
    source_type = DbSourceType::UNKNOWN;

    ret_check = db_create(&dbp_check, nullptr, 0);
    if (ret_check != 0) {
        // C++ Error to STDERR
        std::cerr << "Error: Failed to create BDB check object for " << walletfile << ": " << db_strerror(ret_check) << std::endl;
        return false; // Cannot proceed
    }

    // Attempt to open the DB file. BDB library might print format error directly to stderr here.
    ret_check = dbp_check->open(dbp_check, nullptr, walletfile, "main", DB_BTREE, DB_RDONLY | DB_THREAD, 0);
    int bdb_open_errno = ret_check;
    if (dbp_check) dbp_check->close(dbp_check, 0); // Clean up check handle

    if (bdb_open_errno == 0) { // BDB opened successfully during check
        source_type = DbSourceType::BDB;
        read_ok = read_all_bdb(walletfile, data_map); // Use the function that prints its own errors to stderr
    } else { // BDB open failed during check
        // Check the specific error code returned to C++
        if (bdb_open_errno != 22) { // Use numeric code 22 for EINVAL/"Invalid argument"
            // If the error is NOT just an invalid format/argument, print a C++ warning to STDERR.
            std::cerr << "Warning: BDB open check failed for '" << walletfile
                      << "' with unexpected error: " << db_strerror(bdb_open_errno)
                      << " (Code: " << bdb_open_errno << "). Attempting SQLite fallback." << std::endl;
        }
        // Always try SQLite as fallback regardless of the BDB error code
        source_type = DbSourceType::SQLITE_SPECIAL;
        read_ok = read_all_sqlite_special(walletfile, data_map); // Use the function that prints its own errors to stderr
    }
    return read_ok;
}


// Finds and parses the mkey record from the data map
// Errors printed here go to STDERR
bool find_and_parse_mkey(const WalletDataMap& data_map, DbSourceType source_type, MKeyData& mkey_data) {
    BCDataStream kds, vds;
    const std::vector<uint8_t> SQLITE_MKEY_CONST_KEY = {0x04, 'm', 'k', 'e', 'y', 0x01, 0x00, 0x00, 0x00};
    bool found_potential_mkey = false;

    for (const auto& pair : data_map) {
        const std::vector<uint8_t>& raw_key = pair.first;
        const std::vector<uint8_t>& raw_value = pair.second;
        if (raw_key.empty() || raw_value.empty()) continue;

        bool is_this_mkey = false;
        if (source_type == DbSourceType::SQLITE_SPECIAL && raw_key == SQLITE_MKEY_CONST_KEY) {
            is_this_mkey = true;
        } else if (source_type == DbSourceType::BDB) {
            try {
                kds.clear(); kds.setInput(raw_key);
                if (kds.readStringWithCompactSize() == "mkey") is_this_mkey = true;
            } catch (...) { /* Ignore key parsing errors silently */ }
        }

        if (is_this_mkey) {
             found_potential_mkey = true;
            try {
                vds.clear(); vds.setInput(raw_value);
                uint64_t enc_key_len = vds.readCompactSize();
                if (enc_key_len > vds.size()) throw SerializationError("mkey enc_key length");
                mkey_data.encrypted_key = vds.readBytes(static_cast<size_t>(enc_key_len));

                uint64_t salt_len = vds.readCompactSize();
                if (salt_len > vds.size()) throw SerializationError("mkey salt length");
                mkey_data.salt = vds.readBytes(static_cast<size_t>(salt_len));

                if (vds.size() >= 8) {
                    mkey_data.derivationMethod = vds.readUint32();
                    mkey_data.derivationIterations = vds.readUint32();
                } else {
                    mkey_data.derivationMethod = 0; mkey_data.derivationIterations = 0;
                }

                if (!mkey_data.salt.empty() && !mkey_data.encrypted_key.empty()) {
                    mkey_data.found = true;
                    return true; // Found and parsed successfully
                } else {
                    throw SerializationError("Parsed mkey invalid (empty salt/key)");
                }
            } catch (const std::exception& e) {
                // C++ Error to STDERR
                std::cerr << "Error parsing potential mkey record for " << toHex(raw_key) << ": " << e.what() << std::endl;
                 mkey_data.found = false;
            }
        } // end if is_this_mkey
    } // end for loop

    if (found_potential_mkey && !mkey_data.found) {
         // C++ Error to STDERR
         std::cerr << "Error: Found mkey record(s) but all failed to parse value correctly." << std::endl;
    } else if (!found_potential_mkey) {
         // C++ Error to STDERR
         std::cerr << "Error: 'mkey' record not found in wallet data." << std::endl;
    }

    return mkey_data.found;
}

// Extracts hash from a single file and prints ONLY the hash to STDOUT on success.
// All other messages go to STDERR.
void extract_and_print_hash(const char* filename) {
    WalletDataMap data_map;
    DbSourceType source_type = DbSourceType::UNKNOWN;
    MKeyData mkey;

    // choose_and_read_all_data will print its own errors to stderr if needed
    if (!choose_and_read_all_data(filename, data_map, source_type) || data_map.empty()) {
        // Add a generic message here if read failed very early or map is empty after successful read attempt
        if (data_map.empty() && source_type != DbSourceType::UNKNOWN) { // Source type known but map empty
            // C++ Error to STDERR
            std::cerr << "Error: Successfully identified format but failed to read data or wallet is empty: " << filename << std::endl;
        } else if (source_type == DbSourceType::UNKNOWN && data_map.empty()) { // choose_and_read failed early (already printed its error) or map stayed empty
             // C++ Error to STDERR (optional, as choose_and_read likely printed something)
             // std::cerr << "Error: Failed to determine format or read data for wallet file: " << filename << std::endl;
        }
        return; // Stop processing this file
    }

    // find_and_parse_mkey will print its own errors to stderr if mkey not found/parsed
    if (!find_and_parse_mkey(data_map, source_type, mkey)) {
        return; // Stop processing this file
    }

    // Check for unsupported features or invalid data, print errors to STDERR
    if (mkey.derivationMethod != 0) {
        std::cerr << "Error: Unsupported derivation method (" << mkey.derivationMethod << ") for: " << filename << std::endl;
        return;
    }
    if (mkey.encrypted_key.size() < 32) {
         std::cerr << "Error: Invalid mkey data (encrypted key too short < 32 bytes) for: " << filename << std::endl;
         return;
    }
     if (mkey.salt.empty()) {
         std::cerr << "Error: Invalid mkey data (salt is empty) for: " << filename << std::endl;
         return;
    }

    // Try to generate and print the hash string ONLY to STDOUT
    try {
        std::vector<uint8_t> cry_master(mkey.encrypted_key.end() - 32, mkey.encrypted_key.end());
        std::string hex_master = toHex(cry_master);
        std::string hex_salt   = toHex(mkey.salt);

        // *** This is the ONLY output to STDOUT ***
        std::cout << "$bitcoin$" << hex_master.size() << "$" << hex_master
                  << "$" << hex_salt.size() << "$" << hex_salt
                  << "$" << mkey.derivationIterations
                  << "$2$00$2$00"
                  << std::endl;
    } catch (const std::exception& e) {
         // C++ Error to STDERR
         std::cerr << "Error generating hash string for " << filename << ": " << e.what() << std::endl;
    }
}

// --- main function ---
int main(int argc, char* argv[]) {
    // Disable buffering for stderr for immediate error output
    setvbuf(stderr, NULL, _IONBF, 0);

    if (argc == 1) {
        DIR* dp = opendir(".");
        if (!dp) {
            std::error_code ec(errno, std::system_category());
            // C++ Error to STDERR
            std::cerr << "Error opening current directory: " << ec.message() << std::endl;
            return 1;
        }
        struct dirent* ep;
        while ((ep = readdir(dp)) != nullptr) {
            if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0) continue;
            std::string name = ep->d_name;
            // Basic check for .dat extension (case-insensitive)
            if (name.length() >= 4) {
                 std::string lower_name = name;
                 std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(), ::tolower);
                 if (lower_name.substr(lower_name.length() - 4) == ".dat")
                 {
                      // Process the file. Errors/Hash output handled inside.
                      extract_and_print_hash(name.c_str());
                 }
            }
        }
        closedir(dp);
    } else {
        for (int i = 1; i < argc; ++i) {
             // Process the file. Errors/Hash output handled inside.
            extract_and_print_hash(argv[i]);
        }
    }
    return 0; // Indicate overall success (individual file errors printed to stderr)
}

// --- Utility Function DEFINITION ---
static std::string toHex(const std::vector<uint8_t>& data) {
    if (data.empty()) return "";
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (const auto& b : data) { // Use range-based for loop
        oss << std::setw(2) << static_cast<int>(b);
    }
    return oss.str();
}
