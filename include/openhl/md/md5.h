
///
/// \file md5.h
/// \brief MD5 implementation
/// \see https://tools.ietf.org/html/rfc1321
/// \see https://en.wikipedia.org/wiki/MD5
///

#pragma once

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <openhl/utils.h>

#define MD5_DIGEST_SIZE 16 ///< MD5 digest size in bytes

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/// \brief MD4 hash
/// \param[out] d The digest buffer \see MD5_DIGEST_SIZE
/// \param[in] m The message buffer to hash
/// \param[in] s The size of the message buffer to hash in bytes
///
void md5(uint8_t* d, const uint8_t* m, const size_t s);

#ifdef __cplusplus
}
#endif // __cplusplus


