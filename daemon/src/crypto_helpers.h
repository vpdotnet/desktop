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
#line HEADER_FILE("crypto_helpers.h")

#ifndef CRYPTO_HELPERS_H
#define CRYPTO_HELPERS_H

#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// X25519 key exchange function
bool curve25519(unsigned char *out, const unsigned char *private_key, const unsigned char *public_key);

// ChaCha20-Poly1305 AEAD decryption
bool decrypt_chacha20poly1305(
    unsigned char *plaintext, size_t plaintext_len,
    const unsigned char *ciphertext, size_t ciphertext_len,
    const unsigned char *nonce, size_t nonce_len,
    const unsigned char *aad, size_t aad_len,
    const unsigned char *key, size_t key_len);

#ifdef __cplusplus
}
#endif

#endif // CRYPTO_HELPERS_H