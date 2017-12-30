
///
/// \file utils.h
/// \brief OpenHL utils macros
///

#pragma once

#define BSWAP32(x) __builtin_bswap32(x) ///< 32-bit byte swap
#define BSWAP64(x) __builtin_bswap64(x) ///< 64-bit byte swap

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n)))) ///< Left rotation 32-bit
#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n)))) ///< Left rotation 64-bit

#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n)))) ///< Right rotation 32-bit
#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n)))) ///< Right rotation 64-bit

#define SHL(x, n) ((x) << (n)) ///< Left shift
#define SHR(x, n) ((x) >> (n)) ///< Right shift

