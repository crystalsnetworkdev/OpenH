
///
/// \file md.h
/// \brief MD4, MD5 implementations
/// \see https://tools.ietf.org/html/rfc1186
/// \see https://tools.ietf.org/html/rfc1321
/// \see https://en.wikipedia.org/wiki/MD4
/// \see https://en.wikipedia.org/wiki/MD5
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define MD4_DIGEST_SIZE 16 ///< MD4 digest size in bytes
#define MD5_DIGEST_SIZE 16 ///< MD5 digest size in bytes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// \brief MD4 hash
/// \param[out] dig The digest buffer \see MD4_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* md4(void* dig, const void* msg, size_t size);

/// \brief MD5 hash
/// \param[out] dig The digest buffer \see MD5_DIGEST_SIZE
/// \param[in] msg The message buffer to hash
/// \param[in] size The size of the message buffer to hash in bytes
/// \return NULL if an error occured, a pointer to the digest buffer otherwise
///
void* md5(void* dig, const void* msg, size_t size);

#ifdef __cplusplus
}
#endif // __cplusplus

