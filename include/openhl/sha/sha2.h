
///
/// \file sha2.h
/// \brief SHA-256, SHA-224, SHA-512, SHA-384, SHA-512/256, SHA-512/224 implementations
/// \see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define SHA224_DIGEST_SIZE 28 ///< SHA-224 digest size in bytes
#define SHA256_DIGEST_SIZE 32 ///< SHA-256 digest size in bytes
#define SHA512_DIGEST_SIZE 64 ///< SHA-512 digest size in bytes
#define SHA384_DIGEST_SIZE 48 ///< SHA-384 digest size in bytes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// \brief SHA-256 hash
/// \param[out] d The digest buffer \see SHA256_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha256(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA-224 hash
/// \param[out] d The digest buffer \see SHA224_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha224(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA-512 hash
/// \param[out] d The digest buffer \see SHA512_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha512(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA-384 hash
/// \param[out] d The digest buffer \see SHA384_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha384(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA-512/256 hash
/// \param[out] d The digest buffer \see SHA256_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha512_256(uint8_t* d, const uint8_t* m, const size_t s);

/// \brief SHA-512/224 hash
/// \param[out] d The digest buffer \see SHA224_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void sha512_224(uint8_t* d, const uint8_t* m, const size_t s);

#ifdef __cplusplus
}
#endif // __cplusplus


