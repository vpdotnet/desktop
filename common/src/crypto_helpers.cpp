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

// Include OpenSSL headers for compilation but not for runtime implementation
// We'll use dynamic loading for the actual implementation
#include <openssl/evp.h>
#include <openssl/err.h>

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

// OpenSSL types are already included from headers

// OpenSSL functions we need to resolve
static EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int, ENGINE*) = nullptr;
static void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX*) = nullptr;
static EVP_PKEY* (*EVP_PKEY_new_raw_private_key)(int, ENGINE*, const unsigned char*, size_t) = nullptr;
static EVP_PKEY* (*EVP_PKEY_new_raw_public_key)(int, ENGINE*, const unsigned char*, size_t) = nullptr;
static void (*EVP_PKEY_free)(EVP_PKEY*) = nullptr;
static int (*EVP_PKEY_derive_init)(EVP_PKEY_CTX*) = nullptr;
static int (*EVP_PKEY_derive_set_peer)(EVP_PKEY_CTX*, EVP_PKEY*) = nullptr;
static int (*EVP_PKEY_derive)(EVP_PKEY_CTX*, unsigned char*, size_t*) = nullptr;

static EVP_CIPHER_CTX* (*EVP_CIPHER_CTX_new)() = nullptr;
static void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX*) = nullptr;
static int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX*, int, int, void*) = nullptr;
static int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*) = nullptr;
static int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int) = nullptr;
static int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX*, unsigned char*, int*) = nullptr;
static const EVP_CIPHER* (*EVP_chacha20_poly1305)() = nullptr;

// We'll use the direct functions from the headers for error reporting
// This avoids redefinition errors since we're including the OpenSSL headers directly

enum
{
    EVP_PKEY_X25519 = 1034, // NID_X25519
    EVP_CTRL_AEAD_SET_IVLEN = 0x9,
    EVP_CTRL_AEAD_SET_TAG = 0x11
};

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
    
    // Error reporting functions are used directly from the headers

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
    // Some implementations require the private key to be "clamped" (bits masked according to curve25519 spec)
    unsigned char clamped_private_key[32];
    memcpy(clamped_private_key, private_key, 32);
    
    // Clamp the key according to curve25519 specification
    clamped_private_key[0] &= 248;  // Clear bottom 3 bits
    clamped_private_key[31] &= 127; // Clear top bit
    clamped_private_key[31] |= 64;  // Set second-highest bit
    
    bool keys_needed_clamping = (memcmp(clamped_private_key, private_key, 32) != 0);
    
    // Diagnostic logging for key data - using QString instead of QByteArray
    QString privKeyHex, pubKeyHex, clampedKeyHex;
    for (int i = 0; i < 32; i++) {
        privKeyHex.append(QString("%1").arg(private_key[i] & 0xFF, 2, 16, QChar('0')));
        pubKeyHex.append(QString("%1").arg(public_key[i] & 0xFF, 2, 16, QChar('0')));
        clampedKeyHex.append(QString("%1").arg(clamped_private_key[i] & 0xFF, 2, 16, QChar('0')));
    }
    qInfo() << "Using curve25519 with:";
    qInfo() << "  Private key (first/last 4 bytes): " 
            << privKeyHex.left(8) << "..." << privKeyHex.right(8);
    qInfo() << "  Public key (full): " << pubKeyHex;
    
    if (keys_needed_clamping) {
        qInfo() << "  Private key needed clamping. Clamped version: " 
                << clampedKeyHex.left(8) << "..." << clampedKeyHex.right(8);
    } else {
        qInfo() << "  Private key was already properly clamped";
    }

    EVP_PKEY_CTX *ctx = nullptr;
    EVP_PKEY *pkey = nullptr;
    EVP_PKEY *peerkey = nullptr;
    bool result = false;
    size_t outlen = 32; // X25519 key size
    
    // Create a context for X25519
    if(!(ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr)))
    {
        qWarning() << "Failed to create X25519 context";
        goto cleanup;
    }
    
    // Load private key - use the clamped version
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, clamped_private_key, 32);
    if (!pkey)
    {
        qWarning() << "Failed to load private key";
        goto cleanup;
    }
    
    // Load peer's public key
    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, public_key, 32);
    if (!peerkey)
    {
        qWarning() << "Failed to load public key";
        goto cleanup;
    }
    
    // Initialize key derivation with our private key
    if (EVP_PKEY_derive_init(ctx) <= 0)
    {
        qWarning() << "Failed to initialize key derivation";
        goto cleanup;
    }
    
    // Set peer's public key
    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0)
    {
        qWarning() << "Failed to set peer key";
        goto cleanup;
    }
    
    // Derive shared secret with additional error diagnostics
    if (EVP_PKEY_derive(ctx, out, &outlen) <= 0)
    {
        // These are linked directly from the OpenSSL headers
        unsigned long openssl_error = ERR_get_error();
        char error_string[256];
        ERR_error_string_n(openssl_error, error_string, sizeof(error_string));
        qWarning() << "Failed to derive shared secret. OpenSSL error:" << openssl_error 
                   << "Description:" << error_string;
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    EVP_PKEY_free(pkey);
    EVP_PKEY_free(peerkey);
    EVP_PKEY_CTX_free(ctx);
    
    return result;
}

// ChaCha20-Poly1305 AEAD decryption
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

    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    bool result = false;
    int ret = 0;
    
    // Create and initialize the context
    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        qWarning() << "Failed to create cipher context";
        goto cleanup;
    }
    
    // Initialize decryption operation
    if(EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), nullptr, nullptr, nullptr) != 1)
    {
        qWarning() << "Failed to initialize ChaCha20-Poly1305 decryption";
        goto cleanup;
    }
    
    // Set IV length
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, nonce_len, nullptr) != 1)
    {
        qWarning() << "Failed to set IV length";
        goto cleanup;
    }
    
    // Initialize key and IV
    if(EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce) != 1)
    {
        qWarning() << "Failed to set key and IV";
        goto cleanup;
    }
    
    // Provide AAD data if present
    if(aad && aad_len > 0)
    {
        if(EVP_DecryptUpdate(ctx, nullptr, &len, aad, aad_len) != 1)
        {
            qWarning() << "Failed to provide AAD";
            goto cleanup;
        }
    }
    
    // Provide ciphertext
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len - 16) != 1) // 16 is the tag size
    {
        qWarning() << "Failed to decrypt ciphertext";
        goto cleanup;
    }
    
    // Set expected tag value (last 16 bytes of ciphertext)
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, (void*)(ciphertext + ciphertext_len - 16)) != 1)
    {
        qWarning() << "Failed to set tag";
        goto cleanup;
    }
    
    // Finalize decryption
    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if(ret != 1)
    {
        qWarning() << "Failed to finalize decryption or tag verification failed";
        goto cleanup;
    }
    
    result = true;
    
cleanup:
    EVP_CIPHER_CTX_free(ctx);
    
    return result;
}