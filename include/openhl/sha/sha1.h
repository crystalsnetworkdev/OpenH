
///
/// \file sha1.h
/// \brief SHA1 implementation
/// \see http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define SHA1_DIGEST_SIZE 20 ///< SHA-1 digest size in bytes

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

#ifdef __cplusplus
}
#endif // __cplusplus


