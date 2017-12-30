
///
/// \file sha.h
/// \brief SHA1, SHA2 implementations
/// \see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define SHA1_DIGEST_SIZE   20 ///< SHA-1 digest size in bytes
#define SHA224_DIGEST_SIZE 28 ///< SHA-224 digest size in bytes
#define SHA256_DIGEST_SIZE 32 ///< SHA-256 digest size in bytes
#define SHA384_DIGEST_SIZE 48 ///< SHA-384 digest size in bytes
#define SHA512_DIGEST_SIZE 64 ///< SHA-512 digest size in bytes

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))               ///< CH function (4.1) (4.2) (4.8)
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) ///< MAJ function (4.1) (4.3) (4.9)
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))                      ///< PARITY function (4.1)

#define SIGMA256_0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22)) ///< SHA-224 SHA-256 SIGMA0 function (4.4)
#define SIGMA256_1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25)) ///< SHA-224 SHA-256 SIGMA1 function (4.5)
#define sigma256_0(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^    SHR(x,  3)) ///< SHA-224 SHA-256 sigma0 function (4.6)
#define sigma256_1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^    SHR(x, 10)) ///< SHA-224 SHA-256 sigma1 function (4.7)

#define SIGMA512_0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39)) ///< SHA-384 SHA-512 SHA-512/224 SHA-512/256 SIGMA0 function (4.10)
#define SIGMA512_1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41)) ///< SHA-384 SHA-512 SHA-512/224 SHA-512/256 SIGMA1 function (4.11)
#define sigma512_0(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^    SHR(x,  7)) ///< SHA-384 SHA-512 SHA-512/224 SHA-512/256 sigma0 function (4.12)
#define sigma512_1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^    SHR(x,  6)) ///< SHA-384 SHA-512 SHA-512/224 SHA-512/256 sigma1 function (4.13)

/// \brief SHA-1 hash
/// \param[out] dig The digest buffer \see SHA1_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha1(void* dig, const void* msg, size_t size);


