
///
/// \file sha3.h
/// \brief SHA3-224, SHA3-256, SHA3-384, SHA3-512 implementations
/// \see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
/// \see https://keccak.team/keccak_specs_summary.html
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define SHA3_224_DIGEST_SIZE 28 ///< SHA3-224 digest size in bytes
#define SHA3_256_DIGEST_SIZE 32 ///< SHA3-256 digest size in bytes
#define SHA3_384_DIGEST_SIZE 48 ///< SHA3-384 digest size in bytes
#define SHA3_512_DIGEST_SIZE 64 ///< SHA3-512 digest size in bytes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// \brief SHA3-224 hash
/// \param[out] d The digest buffer \see SHA3_224_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha3_224(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA3-256 hash
/// \param[out] d The digest buffer \see SHA3_256_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha3_256(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA3-384 hash
/// \param[out] d The digest buffer \see SHA3_384_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha3_384(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA3-512 hash
/// \param[out] d The digest buffer \see SHA3_512_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha3_512(uint8_t* d, const uint8_t* m, const size_t s);

#ifdef __cplusplus
}
#endif // __cplusplus


