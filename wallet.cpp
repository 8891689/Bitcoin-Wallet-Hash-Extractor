/*Author: 8891689
 * Assist in creation ：ChatGPT 
 */
// g++ -o wallet wallet.cpp libdb.a
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

// ===== BCDataStream =====
class SerializationError : public std::runtime_error {
public:
    explicit SerializationError(const std::string& msg)
        : std::runtime_error(msg) {}
};

class BCDataStream {
private:
    std::vector<uint8_t> input;
    size_t read_cursor;

    uint64_t _readNum(size_t size) {
        if (read_cursor + size > input.size())
            throw SerializationError("Attempt to read past end of buffer");
        uint64_t val = 0;
        std::memcpy(&val, input.data() + read_cursor, size);
        read_cursor += size;
        return val;
    }

public:
    BCDataStream() : read_cursor(0) {}
    void clear() {
        input.clear();
        read_cursor = 0;
    }
    void write(const std::vector<uint8_t>& bytes) {
        input.insert(input.end(), bytes.begin(), bytes.end());
    }
    std::string readString() {
        if (read_cursor >= input.size())
            throw SerializationError("No data to deserialize");
        uint64_t len = readCompactSize();
        auto v = readBytes(len);
        return std::string(v.begin(), v.end());
    }
    std::vector<uint8_t> readBytes(size_t length) {
        if (read_cursor + length > input.size())
            throw SerializationError("Attempt to read past end of buffer");
        auto it = input.begin() + read_cursor;
        std::vector<uint8_t> out(it, it + length);
        read_cursor += length;
        return out;
    }
    uint32_t readUint32() {
        if (read_cursor + 4 > input.size())
            throw SerializationError("Attempt to read past end of buffer");
        uint32_t x;
        std::memcpy(&x, input.data() + read_cursor, 4);
        read_cursor += 4;
        return x;
    }
    uint64_t readCompactSize() {
        if (read_cursor >= input.size())
            throw SerializationError("Attempt to read past end of buffer");
        uint8_t c = input[read_cursor++];
        if (c < 253) {
            return c;
        } else if (c == 253) {
            return _readNum(2);
        } else if (c == 254) {
            return _readNum(4);
        } else {
            throw SerializationError("Unsupported compact size format");
        }
    }
};

// ===== wallet parsing =====
struct MKeyData {
    std::vector<uint8_t> encrypted_key;
    std::vector<uint8_t> salt;
    uint32_t derivationMethod = 0;
    uint32_t derivationIterations = 0;
};

static std::string toHex(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex;
    for (auto b : data) {
        oss.width(2);
        oss.fill('0');
        oss << (int)b;
    }
    return oss.str();
}

int read_wallet(const char* walletfile, MKeyData& mkey) {
    DB* dbp = nullptr;
    if (db_create(&dbp, nullptr, 0) != 0) {
        std::cerr << "DB create error\n";
        return -1;
    }
    int ret = dbp->open(dbp, nullptr, walletfile, "main",
                        DB_BTREE, DB_RDONLY | DB_THREAD, 0);
    if (ret != 0) {
        dbp->close(dbp, 0);
        return -1;
    }

    DBC* cursor = nullptr;
    if (dbp->cursor(dbp, nullptr, &cursor, 0) != 0) {
        dbp->close(dbp, 0);
        return -1;
    }

    DBT keyt = {0}, valt = {0};
    BCDataStream kds, vds;
    std::string type;

    while (cursor->c_get(cursor, &keyt, &valt, DB_NEXT) == 0) {
        std::vector<uint8_t> keyVec(
            (uint8_t*)keyt.data,
            (uint8_t*)keyt.data + keyt.size);
        std::vector<uint8_t> valVec(
            (uint8_t*)valt.data,
            (uint8_t*)valt.data + valt.size);

        kds.clear(); kds.write(keyVec);
        vds.clear(); vds.write(valVec);

        try {
            type = kds.readString();
        } catch (...) {
            continue;
        }
        if (type == "mkey") {
            uint64_t len = vds.readCompactSize();
            mkey.encrypted_key = vds.readBytes(len);
            len = vds.readCompactSize();
            mkey.salt = vds.readBytes(len);
            mkey.derivationMethod     = vds.readUint32();
            mkey.derivationIterations = vds.readUint32();
            break;
        }
    }

    cursor->c_close(cursor);
    dbp->close(dbp, 0);

    if (mkey.salt.empty() || mkey.encrypted_key.size() < 32)
        return -1;
    return 0;
}

// ===== print one wallet's hash =====
void print_hash_for(const std::string& filename) {
    MKeyData mkey;
    if (read_wallet(filename.c_str(), mkey) != 0) {
        std::cerr << filename << ": not an encrypted wallet or parse error\n";
        return;
    }
    if (mkey.derivationMethod != 0) {
        std::cerr << filename << ": unsupported derivation method\n";
        return;
    }
    // 取最后 32 字节
    std::vector<uint8_t> cry_master(
        mkey.encrypted_key.end() - 32,
        mkey.encrypted_key.end()
    );
    std::string hex_master = toHex(cry_master);
    std::string hex_salt   = toHex(mkey.salt);
    std::cout
      << filename << ": "
      << "$bitcoin$" << hex_master.size() << "$"
      << hex_master << "$"
      << hex_salt.size()  << "$"
      << hex_salt   << "$"
      << mkey.derivationIterations
      << "$2$00$2$00\n";
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        // 无参数：扫描当前目录下所有 .dat/.DAT 文件
        DIR* dp = opendir(".");
        if (!dp) {
            std::perror("opendir");
            return 1;
        }
        struct dirent* ep;
        while ((ep = readdir(dp)) != nullptr) {
            std::string name = ep->d_name;
            if (name.size() >= 4) {
                std::string ext = name.substr(name.size()-4);
                std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
                if (ext == ".dat") {
                    print_hash_for(name);
                }
            }
        }
        closedir(dp);
    } else {
        // 带参数：逐个处理 argv[1..]
        for (int i = 1; i < argc; ++i) {
            print_hash_for(argv[i]);
        }
    }
    return 0;
}

