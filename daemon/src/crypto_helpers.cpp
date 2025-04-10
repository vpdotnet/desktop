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

#include <common/src/common.h>
#line SOURCE_FILE("crypto_helpers.cpp")

#include "crypto_helpers.h"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <QDebug>

// X25519 key exchange function
bool curve25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key)
{
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
    
    // Load private key
    pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, private_key, 32);
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
    
    // Derive shared secret
    if (EVP_PKEY_derive(ctx, out, &outlen) <= 0)
    {
        qWarning() << "Failed to derive shared secret";
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
    EVP_CIPHER_CTX *ctx = nullptr;
    int len = 0;
    bool result = false;
    
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
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
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