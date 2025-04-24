// Copyright (c) 2024 Private Internet Access, Inc.
//
// This file is part of the Private Internet Access Desktop Client.
//
// The Private Internet Access Desktop Client is free software: you can
// redistribute it and/or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of
// the License, or (at your option) any later version.
//
// The Private Internet Access Desktop Client is distributed in the hope that
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with the Private Internet Access Desktop Client.  If not, see
// <https://www.gnu.org/licenses/>.

#include "common.h"
#line SOURCE_FILE("crypto_helpers.cpp")

#include "crypto_helpers.h"
#include "openssl.h"
#include "builtin/path.h"
#include <QDebug>
#include <QLibrary>

// Forward declaration of helper function
static bool try_openssl_x25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key);

#if defined(Q_OS_WIN)
    #if defined(_M_X64)
        static const QString libsslName = QStringLiteral("libssl-3-x64.dll");
        static const QString libcryptoName = QStringLiteral("libcrypto-3-x64.dll");
    #elif defined(_M_ARM64)
        static const QString libsslName = QStringLiteral("libssl-3-arm64.dll");
        static const QString libcryptoName = QStringLiteral("libcrypto-3-arm64.dll");
    #else
        #error Unsupported OS/arch
    #endif
#elif defined(Q_OS_MACOS)
        static const QString libsslName = QStringLiteral("libssl.3.dylib");
        static const QString libcryptoName = QStringLiteral("libcrypto.3.dylib");
#elif defined(Q_OS_LINUX)
        static const QString libsslName = QStringLiteral("libssl.so.3");
        static const QString libcryptoName = QStringLiteral("libcrypto.so.3");
#endif

// OpenSSL type declarations are now in the header file

// OpenSSL functions we need to resolve - export these to be used by the rest of the project
EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int, ENGINE*) = nullptr;
void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX*) = nullptr;
EVP_PKEY* (*EVP_PKEY_new_raw_private_key)(int, ENGINE*, const unsigned char*, size_t) = nullptr;
EVP_PKEY* (*EVP_PKEY_new_raw_public_key)(int, ENGINE*, const unsigned char*, size_t) = nullptr;
void (*EVP_PKEY_free)(EVP_PKEY*) = nullptr;
int (*EVP_PKEY_derive_init)(EVP_PKEY_CTX*) = nullptr;
int (*EVP_PKEY_derive_set_peer)(EVP_PKEY_CTX*, EVP_PKEY*) = nullptr;
int (*EVP_PKEY_derive)(EVP_PKEY_CTX*, unsigned char*, size_t*) = nullptr;

EVP_CIPHER_CTX* (*EVP_CIPHER_CTX_new)() = nullptr;
void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX*) = nullptr;
int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX*, int, int, void*) = nullptr;
int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) = nullptr;
int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int) = nullptr;
int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX*, unsigned char*, int*) = nullptr;
const EVP_CIPHER* (*EVP_chacha20_poly1305)() = nullptr;

// Error handling function pointers
unsigned long (*ERR_get_error)() = nullptr;
void (*ERR_error_string_n)(unsigned long, char*, size_t) = nullptr;

// These constants are now defined in the header file

// Helper for loading OpenSSL functions dynamically
static bool loadCryptoFunctions()
{
    static bool attempted = false, successful = false;

    if (successful)
        return true;
    if (attempted)
        return false;

    attempted = true;

    // Use the LibraryDir path from Path::LibraryDir, similar to how openssl.cpp does
    const auto &libcryptoPath = Path::LibraryDir / libcryptoName;
    // The library is never unloaded
    QLibrary libcrypto{libcryptoPath};

    if(!libcrypto.load())
    {
        qWarning() << "Unable to load libcrypto from" << libcryptoPath
            << "-" << libcrypto.errorString();
        return false;
    }

    qInfo() << "Loaded libcrypto for crypto_helpers from" << libcrypto.fileName();

#define TRY_RESOLVE_OPENSSL_FUNCTION(name) \
    (name = reinterpret_cast<decltype(name)>(libcrypto.resolve(#name)))
#define RESOLVE_OPENSSL_FUNCTION(name) \
    if (!TRY_RESOLVE_OPENSSL_FUNCTION(name)) { qError() << "Unable to resolve symbol" << #name; return false; } else ((void)0)

    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_CTX_new_id);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_CTX_free);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_new_raw_private_key);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_new_raw_public_key);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_free);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_derive_init);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_derive_set_peer);
    RESOLVE_OPENSSL_FUNCTION(EVP_PKEY_derive);

    RESOLVE_OPENSSL_FUNCTION(EVP_CIPHER_CTX_new);
    RESOLVE_OPENSSL_FUNCTION(EVP_CIPHER_CTX_free);
    RESOLVE_OPENSSL_FUNCTION(EVP_CIPHER_CTX_ctrl);
    RESOLVE_OPENSSL_FUNCTION(EVP_DecryptInit_ex);
    RESOLVE_OPENSSL_FUNCTION(EVP_DecryptUpdate);
    RESOLVE_OPENSSL_FUNCTION(EVP_DecryptFinal_ex);
    RESOLVE_OPENSSL_FUNCTION(EVP_chacha20_poly1305);
    
    // Error handling functions
    RESOLVE_OPENSSL_FUNCTION(ERR_get_error);
    RESOLVE_OPENSSL_FUNCTION(ERR_error_string_n);

#undef RESOLVE_OPENSSL_FUNCTION
#undef TRY_RESOLVE_OPENSSL_FUNCTION

    successful = true;
    return true;
}

// X25519 key exchange function
bool curve25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key)
{
    if (!loadCryptoFunctions()) {
        qWarning() << "Failed to load OpenSSL functions";
        return false;
    }
    
    // Create a normalized copy of the private key (clamping as per curve25519 requirements)
    unsigned char clamped_private_key[32];
    memcpy(clamped_private_key, private_key, 32);
    
    // Clamp the key according to curve25519 specification (RFC 7748)
    clamped_private_key[0] &= 248;  // Clear bottom 3 bits
    clamped_private_key[31] &= 127; // Clear top bit
    clamped_private_key[31] |= 64;  // Set second-highest bit
    
    bool keys_needed_clamping = (memcmp(clamped_private_key, private_key, 32) != 0);
    
    // Diagnostic logging for key data
    QString privKeyHex, pubKeyHex, clampedKeyHex;
    for (int i = 0; i < 32; i++) {
        privKeyHex.append(QString("%1").arg(private_key[i] & 0xFF, 2, 16, QChar('0')));
        pubKeyHex.append(QString("%1").arg(public_key[i] & 0xFF, 2, 16, QChar('0')));
        clampedKeyHex.append(QString("%1").arg(clamped_private_key[i] & 0xFF, 2, 16, QChar('0')));
    }
    qInfo() << "Using curve25519 with:";
    qInfo() << "  Private key (first/last 4 bytes): " 
            << privKeyHex.left(8) << "..." << privKeyHex.right(8);
            
    // TODO: SECURITY - Remove full key logging before release
    qInfo() << "  Private key (full for debugging): " << privKeyHex;
    
    qInfo() << "  Public key (full): " << pubKeyHex;
    
    if (keys_needed_clamping) {
        qInfo() << "  Private key needed clamping. Clamped version: " 
                << clampedKeyHex.left(8) << "..." << clampedKeyHex.right(8);
        
        // TODO: SECURITY - Remove full key logging before release
        qInfo() << "  Clamped private key (full for debugging): " << clampedKeyHex;
    } else {
        qInfo() << "  Private key was already properly clamped";
    }
    
    // Try different approaches to key exchange
    bool result = false;
    
    // Attempt 1: OpenSSL EVP API standard approach
    qInfo() << "Attempt 1: Using OpenSSL EVP API for X25519";
    result = try_openssl_x25519(out, clamped_private_key, public_key);
    
    // If standard approach failed, try with reversed keys
    if (!result) {
        qInfo() << "Attempt 2: Trying with byte-reversed public key";
        unsigned char reversed_public_key[32];
        for (int i = 0; i < 32; i++) {
            reversed_public_key[i] = public_key[31 - i];
        }
        
        // Log the reversed public key for debugging
        QString reversedPubKeyHex;
        for (int i = 0; i < 32; i++) {
            reversedPubKeyHex.append(QString("%1").arg(reversed_public_key[i] & 0xFF, 2, 16, QChar('0')));
        }
        
        // TODO: SECURITY - Remove full key logging before release
        qInfo() << "  Reversed public key (full for debugging): " << reversedPubKeyHex;
        
        result = try_openssl_x25519(out, clamped_private_key, reversed_public_key);
    }
    
    // If all attempts failed, log the failure
    if (!result) {
        // Zero out the output buffer for consistent failure behavior
        memset(out, 0, 32);
        qWarning() << "All key derivation approaches failed";
    }
    
    return result;
}

// Helper function to try OpenSSL X25519
static bool try_openssl_x25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key)
{
    if (!loadCryptoFunctions()) {
        qWarning() << "Failed to load crypto functions";
        return false;
    }
    
    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY *peerkey = nullptr;
    bool result = false;
    size_t outlen = 32; // X25519 key size
    
    // Create context
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!ctx) {
        qWarning() << "Failed to create X25519 context";
        return false;
    }
    
    // Create private key
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key, 32);
    if (!pkey) {
        qWarning() << "Failed to create private key";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Create public key
    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key, 32);
    if (!peerkey) {
        qWarning() << "Failed to create peer key";
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Initialize key derivation context
    if (EVP_PKEY_derive_init(ctx) <= 0) {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to initialize key derivation:" << errstr;
        EVP_PKEY_free(peerkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Set peer key
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to set peer key:" << errstr;
        EVP_PKEY_free(peerkey);
        EVP_PKEY_free(pkey);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    // Derive shared secret
    if (EVP_PKEY_derive(ctx, out, &outlen) > 0) {
        result = true;
        // Log success with derived key
        QString outHex;
        for (int i = 0; i < 32; i++) {
            outHex.append(QString("%1").arg(out[i] & 0xFF, 2, 16, QChar('0')));
        }
        qInfo() << "Successfully computed shared secret: " << outHex.left(8) << "..." << outHex.right(8);
    } else {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Key derivation failed:" << errstr;
    }
    
    // Clean up resources
    EVP_PKEY_free(peerkey);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    
    return result;
}

// ChaCha20-Poly1305 AEAD decryption - optimized to match Go implementation
bool decrypt_chacha20poly1305(
    unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key, size_t key_len)
{
    if (!loadCryptoFunctions()) {
        qWarning() << "Failed to load OpenSSL functions";
        return false;
    }

    // Parameter validation based on ChaCha20-Poly1305 requirements
    static const size_t TAG_SIZE = 16;
    static const size_t CHACHA20_POLY1305_NONCE_SIZE = 12;
    static const size_t CHACHA20_POLY1305_KEY_SIZE = 32;
    
    if (!plaintext || !ciphertext || !nonce || !key) {
        qWarning() << "Invalid parameters: null pointers provided";
        return false;
    }
    
    if (plaintext_len < (ciphertext_len - TAG_SIZE)) {
        qWarning() << "Output buffer too small for decryption - need at least" 
                  << (ciphertext_len - TAG_SIZE) << "bytes, got" << plaintext_len;
        return false;
    }
    
    if (ciphertext_len <= TAG_SIZE) {
        qWarning() << "Ciphertext too short, must include 16-byte tag";
        return false;
    }
    
    if (nonce_len != CHACHA20_POLY1305_NONCE_SIZE) {
        qWarning() << "Invalid nonce length for ChaCha20-Poly1305: got" << nonce_len 
                  << "expected" << CHACHA20_POLY1305_NONCE_SIZE;
        return false;
    }
    
    if (key_len != CHACHA20_POLY1305_KEY_SIZE) {
        qWarning() << "Invalid key length for ChaCha20-Poly1305: got" << key_len 
                  << "expected" << CHACHA20_POLY1305_KEY_SIZE;
        return false;
    }
    
    // Debugging info for keys (only first/last 4 bytes for security)
    QString keyHex, nonceHex, tagHex;
    for (size_t i = 0; i < key_len; i++) {
        if (i < 4 || i >= key_len - 4) {
            keyHex.append(QString("%1").arg(key[i] & 0xFF, 2, 16, QChar('0')));
        }
    }
    
    // Build full key hex for debugging
    QString fullKeyHex;
    for (size_t i = 0; i < key_len; i++) {
        fullKeyHex.append(QString("%1").arg(key[i] & 0xFF, 2, 16, QChar('0')));
    }
    
    for (size_t i = 0; i < nonce_len; i++) {
        nonceHex.append(QString("%1").arg(nonce[i] & 0xFF, 2, 16, QChar('0')));
    }
    
    for (size_t i = 0; i < TAG_SIZE; i++) {
        tagHex.append(QString("%1").arg(ciphertext[ciphertext_len - TAG_SIZE + i] & 0xFF, 2, 16, QChar('0')));
    }
    
    qInfo() << "Decrypting with ChaCha20-Poly1305:";
    qInfo() << "  Key (first/last 4 bytes): " << keyHex.left(8) << "..." << keyHex.right(8);
    
    // TODO: SECURITY - Remove full key logging before release
    qInfo() << "  Key (full for debugging): " << fullKeyHex;
    
    qInfo() << "  Nonce: " << nonceHex;
    qInfo() << "  Auth tag: " << tagHex;
    qInfo() << "  Ciphertext length: " << ciphertext_len - TAG_SIZE << " + 16 bytes tag";

    // OpenSSL-based ChaCha20-Poly1305 AEAD decryption
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    int plaintext_offset = 0;
    
    // Create and initialize the context - similar to Go's chacha20poly1305.New()
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to create cipher context:" << errstr;
        return false;
    }
    
    // Initialize with ChaCha20-Poly1305 cipher
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to initialize ChaCha20-Poly1305 decryption:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Set IV length to match Go's chacha20poly1305 implementation
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, nullptr) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to set nonce length:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Initialize with key and nonce - equivalent to creating the AEAD in Go
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to set key and nonce:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Process AAD data if provided (matches Go's aead.Open with additional data)
    if (aad && aad_len > 0)
    {
        if (EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1)
        {
            unsigned long error = ERR_get_error();
            char errstr[256];
            ERR_error_string_n(error, errstr, sizeof(errstr));
            qWarning() << "Failed to process additional authenticated data:" << errstr;
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
    }
    
    // Process ciphertext - separating the ciphertext from the tag
    // Similar to Go's slicing of ciphertext[:len(ciphertext)-16]
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len - TAG_SIZE) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to process ciphertext:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    plaintext_offset = len;
    
    // Set expected tag value (last 16 bytes of ciphertext)
    // Equivalent to Go's tag extraction and verification
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_SIZE, (void*)(ciphertext + ciphertext_len - TAG_SIZE)) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Failed to set authentication tag:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Finalize decryption and verify tag
    // This performs the actual authentication check similar to Go's poly1305 verification
    if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_offset, &len) != 1)
    {
        unsigned long error = ERR_get_error();
        char errstr[256];
        ERR_error_string_n(error, errstr, sizeof(errstr));
        qWarning() << "Authentication failed or decryption error:" << errstr;
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }
    
    // Add the final bytes to our count
    plaintext_offset += len;
    
    // Show success information
    qInfo() << "ChaCha20-Poly1305 decryption successful - plaintext length:" << plaintext_offset;
    
    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    return true;
}

// WireGuard encrypted IP decryption implementation
QString decrypt_wireguard_ip(const QByteArray &encryptedData, const unsigned char *privateKey, const unsigned char *serverPubkey)
{
    if (!loadCryptoFunctions()) {
        qWarning() << "Failed to load OpenSSL functions";
        throw std::runtime_error("Failed to load OpenSSL functions");
    }
    
    static const int NonceSize = 12; // ChaCha20-Poly1305 nonce size
    static const int TagSize = 16;   // Poly1305 tag size
    static const int PrivKeySize = 32; // X25519 key size
    
    // Check if we have enough data
    if (encryptedData.size() < NonceSize + TagSize) {
        qWarning() << "Encrypted data too short, need at least" << NonceSize + TagSize << "bytes";
        qWarning() << "Actual size:" << encryptedData.size();
        throw std::runtime_error("Encrypted data too short");
    }
    
    // Extract nonce and ciphertext
    const unsigned char* nonce = reinterpret_cast<const unsigned char*>(encryptedData.data());
    const unsigned char* ciphertext = nonce + NonceSize;
    size_t ciphertext_len = encryptedData.size() - NonceSize;
    
    qInfo() << "WireGuard IP decryption - Encrypted data size:" << encryptedData.size() 
            << "- Nonce size:" << NonceSize 
            << "- Ciphertext size:" << ciphertext_len;
    
    // Diagnostic logging for key data
    QString privKeyHex, pubKeyHex, nonceHex;
    for (int i = 0; i < PrivKeySize; i++) {
        privKeyHex.append(QString("%1").arg(privateKey[i] & 0xFF, 2, 16, QChar('0')));
        pubKeyHex.append(QString("%1").arg(serverPubkey[i] & 0xFF, 2, 16, QChar('0')));
    }
    for (int i = 0; i < NonceSize; i++) {
        nonceHex.append(QString("%1").arg(nonce[i] & 0xFF, 2, 16, QChar('0')));
    }
    
    qInfo() << "WireGuard decryption using keys:";
    qInfo() << "  Private key (first/last 4 bytes): " 
            << privKeyHex.left(8) << "..." << privKeyHex.right(8);
    qInfo() << "  Server public key (first/last 4 bytes): " 
            << pubKeyHex.left(8) << "..." << pubKeyHex.right(8);
    qInfo() << "  Nonce: " << nonceHex;
    
    // Step 1: X25519 Key Exchange
    unsigned char clamped_private_key[32];
    memcpy(clamped_private_key, privateKey, 32);
    
    // Clamp the key according to curve25519 specification (RFC 7748)
    clamped_private_key[0] &= 248;  // Clear bottom 3 bits
    clamped_private_key[31] &= 127; // Clear top bit
    clamped_private_key[31] |= 64;  // Set second-highest bit
    
    bool keys_needed_clamping = (memcmp(clamped_private_key, privateKey, 32) != 0);
    if (keys_needed_clamping) {
        qInfo() << "  Private key needed clamping";
    } else {
        qInfo() << "  Private key was already properly clamped";
    }
    
    // Derive the shared secret
    unsigned char shared_secret[32];
    
    // Use curve25519 for key exchange
    if (!curve25519(shared_secret, clamped_private_key, serverPubkey)) {
        qWarning() << "Failed to create shared secret via curve25519";
        throw std::runtime_error("Failed to derive shared secret");
    }
    
    // Log the derived shared secret
    QString secretHex;
    for (size_t i = 0; i < 32; i++) {
        secretHex.append(QString("%1").arg(shared_secret[i] & 0xFF, 2, 16, QChar('0')));
    }
    qInfo() << "WireGuard - derived shared secret (first/last 4 bytes): " 
            << secretHex.left(8) << "..." << secretHex.right(8);
    
    // Step 2: ChaCha20-Poly1305 decryption
    QByteArray plaintext(ciphertext_len - TagSize, 0);
    
    if (!decrypt_chacha20poly1305(
        reinterpret_cast<unsigned char*>(plaintext.data()),
        plaintext.size(),
        ciphertext,
        ciphertext_len,
        nonce,
        NonceSize,
        nullptr, 0, // No additional data
        shared_secret,
        32)) {
        qWarning() << "Failed to decrypt data with ChaCha20-Poly1305";
        throw std::runtime_error("Failed to decrypt data");
    }
    
    // Decode the message
    QString message = QString::fromUtf8(plaintext);
    qInfo() << "Successfully decrypted data: " << message;
    
    // Parse message to extract IP
    const QString start_delim = "###.";
    const QString end_delim = ".###";
    
    int startIndex = message.indexOf(start_delim);
    if (startIndex == -1) {
        qWarning() << "Invalid message format in decrypted data - missing start delimiter '###.'";
        qWarning() << "Decrypted content: " << message;
        throw std::runtime_error("Invalid message format - missing start delimiter");
    }
    startIndex += start_delim.length(); // Skip the "###." marker
    
    int endIndex = message.indexOf(end_delim, startIndex);
    if (endIndex == -1) {
        qWarning() << "Invalid message format in decrypted data - missing end delimiter '.###'";
        qWarning() << "Decrypted content: " << message;
        throw std::runtime_error("Invalid message format - missing end delimiter");
    }
    
    QString ip = message.mid(startIndex, endIndex - startIndex);
    qInfo() << "Successfully extracted IP address:" << ip;
    
    return ip;
}