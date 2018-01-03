
///
/// \file sha.h
/// \brief SHA1, SHA2 implementations
/// \see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define SHA1_DIGEST_SIZE   20 ///< SHA-1 digest size in bytes
#define SHA224_DIGEST_SIZE 28 ///< SHA-224 digest size in bytes
#define SHA256_DIGEST_SIZE 32 ///< SHA-256 digest size in bytes
#define SHA384_DIGEST_SIZE 48 ///< SHA-384 digest size in bytes
#define SHA512_DIGEST_SIZE 64 ///< SHA-512 digest size in bytes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// \brief SHA-1 hash
/// \param[out] dig The digest buffer \see SHA1_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha1(void* dig, const void* msg, size_t size);

/// \brief SHA-256 hash
/// \param[out] dig The digest buffer \see SHA256_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha256(void* dig, const void* msg, size_t size);

/// \brief SHA-224 hash
/// \param[out] dig The digest buffer \see SHA224_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha224(void* dig, const void* msg, size_t size);

/// \brief SHA-512 hash
/// \param[out] dig The digest buffer \see SHA512_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha512(void* dig, const void* msg, size_t size);

/// \brief SHA-384 hash
/// \param[out] dig The digest buffer \see SHA384_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha384(void* dig, const void* msg, size_t size);

/// \brief SHA-512/256 hash
/// \param[out] dig The digest buffer \see SHA256_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha512_256(void* dig, const void* msg, size_t size);

/// \brief SHA-512/224 hash
/// \param[out] dig The digest buffer \see SHA224_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* sha512_224(void* dig, const void* msg, size_t size);

#ifdef __cplusplus
}
#endif // __cplusplus


