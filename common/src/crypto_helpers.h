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
#line HEADER_FILE("crypto_helpers.h")

#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <cstddef>
#include "openssl.h" // Include OpenSSL headers for the required types

// Forward declarations for OpenSSL types
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct engine_st ENGINE;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_cipher_st EVP_CIPHER;

#ifdef __cplusplus
extern "C" {
#endif

// X25519 key exchange function
COMMON_EXPORT bool curve25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key);

// Make the OpenSSL function pointers accessible to other files in the project
// For X25519 key exchange
extern EVP_PKEY_CTX* (*EVP_PKEY_CTX_new_id)(int, ENGINE*);
extern EVP_PKEY_CTX* (*EVP_PKEY_CTX_new)(EVP_PKEY*, ENGINE*);
extern void (*EVP_PKEY_CTX_free)(EVP_PKEY_CTX*);
extern EVP_PKEY* (*EVP_PKEY_new_raw_private_key)(int, ENGINE*, const unsigned char*, size_t);
extern EVP_PKEY* (*EVP_PKEY_new_raw_public_key)(int, ENGINE*, const unsigned char*, size_t);
extern void (*EVP_PKEY_free)(EVP_PKEY*);
extern int (*EVP_PKEY_derive_init)(EVP_PKEY_CTX*);
extern int (*EVP_PKEY_derive_set_peer)(EVP_PKEY_CTX*, EVP_PKEY*);
extern int (*EVP_PKEY_derive)(EVP_PKEY_CTX*, unsigned char*, size_t*);

// For ChaCha20-Poly1305 decryption
extern EVP_CIPHER_CTX* (*EVP_CIPHER_CTX_new)();
extern void (*EVP_CIPHER_CTX_free)(EVP_CIPHER_CTX*);
extern int (*EVP_CIPHER_CTX_ctrl)(EVP_CIPHER_CTX*, int, int, void*);
extern int (*EVP_DecryptInit_ex)(EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*);
extern int (*EVP_DecryptUpdate)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int);
extern int (*EVP_DecryptFinal_ex)(EVP_CIPHER_CTX*, unsigned char*, int*);
extern const EVP_CIPHER* (*EVP_chacha20_poly1305)();

// For error handling
extern unsigned long (*ERR_get_error)();
extern void (*ERR_error_string_n)(unsigned long, char*, size_t);

// Constants
#ifndef EVP_PKEY_X25519
#define EVP_PKEY_X25519 1034 // NID_X25519
#endif
#ifndef EVP_CTRL_AEAD_SET_IVLEN
#define EVP_CTRL_AEAD_SET_IVLEN 0x9
#endif
#ifndef EVP_CTRL_AEAD_SET_TAG
#define EVP_CTRL_AEAD_SET_TAG 0x11
#endif

// ChaCha20-Poly1305 AEAD decryption
COMMON_EXPORT bool decrypt_chacha20poly1305(
    unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key, size_t key_len);

#ifdef __cplusplus
}
#endif

// WireGuard encrypted IP decryption using X25519 key exchange and ChaCha20-Poly1305
// This function is not part of the C API because it returns a QString
COMMON_EXPORT QString decrypt_wireguard_ip(
    const QByteArray &encryptedData,
    const unsigned char *privateKey,
    const unsigned char *serverPubkey);


#endif // CRYPTO_HELPERS_H