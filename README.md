# Bitcoin Wallet Hash Extractor

A simple tool to extract encrypted master keys and salts from Bitcoin wallet files (.dat) for security analysis.

## Features
- Automatically scan all `.dat` files in the current directory
- Supports specifying a single wallet file path
- Outputs encrypted information in Hashcat format (supports method 0 export)

## Compile
```bash
g++ -O2 -o wallet wallet.cpp libdb.a libsqlite3.a

or

g++ -O2 -o wallet_Details wallet_Details.cpp libdb.a libsqlite3.a

```
# ⚙️ Dependencies

1. C++11 compiler
2. Berkeley DB The Berkeley DB library is required
3. SQLite3 development kit, which is a library that must be used for parsing in the latest wallet. Installation example: sudo apt install libdb-dev libsqlite3-dev
4. I have packaged the Berkeley DB and SQLite3 libraries as static libraries, just link and compile.

# Scan all .dat files in the current directory
```
./wallet
$bitcoin$64$6b45588e745d8490f2432c68533407e0f2040ff12debd840270f47543ad47c16$16$0af493ab2796f208$99974$2$00$2$00
$bitcoin$64$f83d2783f238d5fde0e082e20686ff85cb92bb0737da214e2e39fd61b828bf6c$16$adfbb9cfa83e9cf6$135318$2$00$2$00
$bitcoin$64$bcf883ce2bf5e8e38df49ceae92c946d4cc78614131d89365e11078423350bf7$16$8bbb805fa36b918e$63241$2$00$2$00
$bitcoin$64$a50dd3829378f5ee40bf6a6b0a47b0c3ae0a83ccf35ca487742765623a2df714$16$2236f42204c91a50$129704$2$00$2$00
$bitcoin$64$49aa9a07b86a9ba3f29f847b7c4d58e581137ebea7e50414c142c05dd942ac28$16$ea58017c72d4a60f$19929$2$00$2$00
$bitcoin$64$f5e148a769865de007677b4235d60559c84360eb97b5d29c1f3744a3ef1992a5$16$ebd71877389b36c4$118376$2$00$2$00

```
# Specify single or multiple wallet files
```
./wallet 11.26827053.dat 14.09013974.dat
$bitcoin$64$6b45588e745d8490f2432c68533407e0f2040ff12debd840270f47543ad47c16$16$0af493ab2796f208$99974$2$00$2$00
$bitcoin$64$f83d2783f238d5fde0e082e20686ff85cb92bb0737da214e2e39fd61b828bf6c$16$adfbb9cfa83e9cf6$135318$2$00$2$00
```

# To view information such as the public key address and iteration count, please use the detailed version.
```
./wallet_Details 0.07.dat
Info: Processing files specified on command line.
========================================
Processing file: 0.07.dat
========================================
Info: Attempting to open '0.07.dat' with BDB ('main' db) for format check...
Info: Detected BDB format ('main' database opened).
Info: Attempting to read all data from BDB: 0.07.dat
Info: Successfully read 209 records from BDB.
Info: Parsing 208 records from in-memory map...
Info: Successfully parsed 'mkey' data.
Info: Parsing complete. Found: 1 mkey, 101 keys, 1 names, 0 keymeta.

--- Wallet Info: 0.07.dat ---
Encryption Status: Encrypted
  Salt: dff2b89e4d885c28
  Derivation Method: 0
  Derivation Iterations: 35714
  JtR Hash: $bitcoin$64$617c4b22fabd578e0f4d030245a0cbebd9da426fbee49c2feb885fa190b65096$16$dff2b89e4d885c28$35714$2$00$2$00
  Encrypted Master Key Data (Full Size: 48 bytes)

Extracted Keys (101):
Key #1:
  Private Key: [Encrypted]
  Public Key:  040477a76f008c9869899e0924ef185c5e41a8ca464a775b2e69be6a7a9ce8edd3cb6599ce9e0f9675c20c6ed42fd057ae43fc08c80e651ff82856ae949b312c8a (size 65 bytes)
Key #2:
  Private Key: [Encrypted]
  Public Key:  0407a080418c2e24fe0f220e4eef1730ab0ef9039954ef0f4393a088ab56227f4fdf9bda5787ecb8de8c637fe2db1bc510568739046c7fc71ad9ffa1fb8928ce1f (size 65 bytes)
.
.
.

Key #100:
  Private Key: [Encrypted]
  Public Key:  04f9c512d95f18618e399132f8ab709a11f0100f3dee513c874119768aad1c29a9639b212b4c102edb08bdb267fc35e93233a2fd74e4122b7da06a19c80261e4e3 (size 65 bytes)
Key #101:
  Private Key: [Encrypted]
  Public Key:  04fc18da237cc9ad2b568950a8bcd59b342bc84749f632e3616a4dc6a23aeb9c73fd12cabcdbb09ce1c91f2d05f37344565bb8d5647f8670e068ad8752422489a3 (size 65 bytes)

Note: Private keys are encrypted and not shown in plain text.

Extracted Addresses & Labels (1):
Address #1: 12vdxXV3m5xRTi6vAAwMkQQkVL5rh9LESE
--- End Wallet Info ---


All specified files processed.
```

Notes
1. Update support for new BTC wallets and make them compatible with old wallets, because the bitcoin2john.py script only supports old wallets and cannot extract the hash value of new wallets, so this project can only be redeveloped.
2. The output results can be used for password recovery or cracking tools, such as Hashcat.


# Acknowledgements

Help create: gemini

# Sponsorship
If this project is helpful to you, please consider sponsoring. Your support is greatly appreciated. Thank you!
```
BTC: bc1qt3nh2e6gjsfkfacnkglt5uqghzvlrr6jahyj2k
ETH: 0xD6503e5994bF46052338a9286Bc43bC1c3811Fa1
DOGE: DTszb9cPALbG9ESNJMFJt4ECqWGRCgucky
TRX: TAHUmjyzg7B3Nndv264zWYUhQ9HUmX4Xu4
```
# 📜 Disclaimer
This code is only for learning and understanding how it works.
Please make sure the program runs in a safe environment and comply with local laws and regulations!
The developer is not responsible for any financial losses or legal liabilities caused by the use of this code.
