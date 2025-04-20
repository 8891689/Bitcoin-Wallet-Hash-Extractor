# Bitcoin Wallet Hash Extractor

A simple tool to extract encrypted master keys and salts from Bitcoin wallet files (.dat) for security analysis.

## Features
- Automatically scan all `.dat` files in the current directory
- Supports specifying a single wallet file path
- Outputs encrypted information in Hashcat format (supports method 0 export)

## Compile
```bash
g++ -o wallet wallet.cpp libdb.a
```
# ⚙️ Dependencies

1. C++11 compiler
2. Berkeley DB
Requires Berkeley DB library (installation example: sudo apt install libdb-dev)
3. I have packaged the Berkeley DB library as a static library, just link and compile.

# Scan all .dat files in the current directory
```
./wallet
11.26827053.dat: $bitcoin$64$6b45588e745d8490f2432c68533407e0f2040ff12debd840270f47543ad47c16$16$0af493ab2796f208$99974$2$00$2$00
14.09013974.dat: $bitcoin$64$f83d2783f238d5fde0e082e20686ff85cb92bb0737da214e2e39fd61b828bf6c$16$adfbb9cfa83e9cf6$135318$2$00$2$00
28.12063817.dat: $bitcoin$64$bcf883ce2bf5e8e38df49ceae92c946d4cc78614131d89365e11078423350bf7$16$8bbb805fa36b918e$63241$2$00$2$00
358.47919037.dat: $bitcoin$64$a50dd3829378f5ee40bf6a6b0a47b0c3ae0a83ccf35ca487742765623a2df714$16$2236f42204c91a50$129704$2$00$2$00
wallet_51,99.dat: $bitcoin$64$49aa9a07b86a9ba3f29f847b7c4d58e581137ebea7e50414c142c05dd942ac28$16$ea58017c72d4a60f$19929$2$00$2$00
wallet_6910.dat: $bitcoin$64$f5e148a769865de007677b4235d60559c84360eb97b5d29c1f3744a3ef1992a5$16$ebd71877389b36c4$118376$2$00$2$00

```
# Specify single or multiple wallet files
```
./wallet 11.26827053.dat 14.09013974.dat
11.26827053.dat: $bitcoin$64$6b45588e745d8490f2432c68533407e0f2040ff12debd840270f47543ad47c16$16$0af493ab2796f208$99974$2$00$2$00
14.09013974.dat: $bitcoin$64$f83d2783f238d5fde0e082e20686ff85cb92bb0737da214e2e39fd61b828bf6c$16$adfbb9cfa83e9cf6$135318$2$00$2$00
```

Notes
1. Only BTC wallets are supported
derivationMethod=0 Indicates that the wallet mainly uses the older BIP44 standard to derive addresses, and can usually only manage traditional Legacy addresses (starting with 1).
This is a fully functional BTC wallet, but does not support address types (such as SegWit, Taproot) derived from newer standards (such as BIP49, BIP84, BIP86).
2. A Bitcoin wallet file .dat in Berkeley DB format is required.
3. The output can be used for password recovery or cracking tools such as Hashcat.

# Acknowledgements

Help create: ChatGPT

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
