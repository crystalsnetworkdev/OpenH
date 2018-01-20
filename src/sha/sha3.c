
#include <openhl/sha/sha3.h>

#define SHA3_KECCAK_WIDTH  200 // the width of the keccak function
#define SHA3_KECCAK_ROUNDS  24 // the number of rounds of the keccak function

static const uint64_t RC[SHA3_KECCAK_ROUNDS] =
{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
	0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
	0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
	0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
	0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
};

void __sha3_keccak_theta(uint64_t* A)
{
	// step 1
	uint64_t C[5];
	C[0] = A[ 0] ^ A[ 5] ^ A[10] ^ A[15] ^ A[20];
	C[1] = A[ 1] ^ A[ 6] ^ A[11] ^ A[16] ^ A[21];
	C[2] = A[ 2] ^ A[ 7] ^ A[12] ^ A[17] ^ A[22];
	C[3] = A[ 3] ^ A[ 8] ^ A[13] ^ A[18] ^ A[23];
	C[4] = A[ 4] ^ A[ 9] ^ A[14] ^ A[19] ^ A[24];

	// step 2
	uint64_t D[5];
	D[0] = C[4] ^ ROTL64(C[1], 1);
	D[1] = C[0] ^ ROTL64(C[2], 1);
	D[2] = C[1] ^ ROTL64(C[3], 1);
	D[3] = C[2] ^ ROTL64(C[4], 1);
	D[4] = C[3] ^ ROTL64(C[0], 1);

	// step 3
	A[ 0] ^= D[0];
	A[ 1] ^= D[1];
	A[ 2] ^= D[2];
	A[ 3] ^= D[3];
	A[ 4] ^= D[4];
	A[ 5] ^= D[0];
	A[ 6] ^= D[1];
	A[ 7] ^= D[2];
	A[ 8] ^= D[3];
	A[ 9] ^= D[4];
	A[10] ^= D[0];
	A[11] ^= D[1];
	A[12] ^= D[2];
	A[13] ^= D[3];
	A[14] ^= D[4];
	A[15] ^= D[0];
	A[16] ^= D[1];
	A[17] ^= D[2];
	A[18] ^= D[3];
	A[19] ^= D[4];
	A[20] ^= D[0];
	A[21] ^= D[1];
	A[22] ^= D[2];
	A[23] ^= D[3];
	A[24] ^= D[4];
}

void __sha3_keccak_rho(uint64_t* A)
{
	// y = 0
	A[ 1] = ROTL64(A[ 1],  1);
	A[ 2] = ROTL64(A[ 2], 62);
	A[ 3] = ROTL64(A[ 3], 28);
	A[ 4] = ROTL64(A[ 4], 27);

	// y = 1
	A[ 5] = ROTL64(A[ 5], 36);
	A[ 6] = ROTL64(A[ 6], 44);
	A[ 7] = ROTL64(A[ 7],  6);
	A[ 8] = ROTL64(A[ 8], 55);
	A[ 9] = ROTL64(A[ 9], 20);

	// y = 2
	A[10] = ROTL64(A[10],  3);
	A[11] = ROTL64(A[11], 10);
	A[12] = ROTL64(A[12], 43);
	A[13] = ROTL64(A[13], 25);
	A[14] = ROTL64(A[14], 39);

	// y = 3
	A[15] = ROTL64(A[15], 41);
	A[16] = ROTL64(A[16], 45);
	A[17] = ROTL64(A[17], 15);
	A[18] = ROTL64(A[18], 21);
	A[19] = ROTL64(A[19],  8);

	// y = 4
	A[20] = ROTL64(A[20], 18);
	A[21] = ROTL64(A[21],  2);
	A[22] = ROTL64(A[22], 61);
	A[23] = ROTL64(A[23], 56);
	A[24] = ROTL64(A[24], 14);
}

void __sha3_keccak_pi(uint64_t* A)
{
	uint64_t a1 = A[1];

	A[ 1] = A[ 6];
	A[ 6] = A[ 9];
	A[ 9] = A[22];
	A[22] = A[14];
	A[14] = A[20];
	A[20] = A[ 2];
	A[ 2] = A[12];
	A[12] = A[13];
	A[13] = A[19];
	A[19] = A[23];
	A[23] = A[15];
	A[15] = A[ 4];
	A[ 4] = A[24];
	A[24] = A[21];
	A[21] = A[ 8];
	A[ 8] = A[16];
	A[16] = A[ 5];
	A[ 5] = A[ 3];
	A[ 3] = A[18];
	A[18] = A[17];
	A[17] = A[11];
	A[11] = A[ 7];
	A[ 7] = A[10];
	A[10] = a1;
}

void __sha3_keccak_chi(uint64_t* A)
{
	uint64_t a0, a1;

	// y = 0
	a0 = A[0];
	a1 = A[1];
	A[ 0] ^= ~a1    & A[ 2];
	A[ 1] ^= ~A[ 2] & A[ 3];
	A[ 2] ^= ~A[ 3] & A[ 4];
	A[ 3] ^= ~A[ 4] &    a0;
	A[ 4] ^= ~a0    &    a1;

	// y = 1
	a0 = A[5];
	a1 = A[6];
	A[ 5] ^= ~a1    & A[ 7];
	A[ 6] ^= ~A[ 7] & A[ 8];
	A[ 7] ^= ~A[ 8] & A[ 9];
	A[ 8] ^= ~A[ 9] &    a0;
	A[ 9] ^= ~a0    &    a1;

	// y = 2
	a0 = A[10];
	a1 = A[11];
	A[10] ^= ~a1    & A[12];
	A[11] ^= ~A[12] & A[13];
	A[12] ^= ~A[13] & A[14];
	A[13] ^= ~A[14] &    a0;
	A[14] ^= ~a0    &    a1;

	// y = 3
	a0 = A[15];
	a1 = A[16];
	A[15] ^= ~a1    & A[17];
	A[16] ^= ~A[17] & A[18];
	A[17] ^= ~A[18] & A[19];
	A[18] ^= ~A[19] &    a0;
	A[19] ^= ~a0    &    a1;

	// y = 4
	a0 = A[20];
	a1 = A[21];
	A[20] ^= ~a1    & A[22];
	A[21] ^= ~A[22] & A[23];
	A[22] ^= ~A[23] & A[24];
	A[23] ^= ~A[24] &    a0;
	A[24] ^= ~a0    &    a1;
}

void __sha3_keccak_iota(uint64_t* A, const size_t i)
{
	// apply the round constant
	A[0] ^= RC[i];
}

void __sha3_keccak(uint8_t* S)
{
	// the state matrix 5x5x64
	uint64_t* A = (uint64_t*)S;

	// execute the round function
	for(size_t i = 0; i < SHA3_KECCAK_ROUNDS; ++i)
	{
		// rnd(A, i) = iota(chi(pi(rho(theta(A)))), i)
		__sha3_keccak_theta(A);
		__sha3_keccak_rho(A);
		__sha3_keccak_pi(A);
		__sha3_keccak_chi(A);
		__sha3_keccak_iota(A, i);
	}
}

// sponge function for SHA3-224, SHA3-256, SHA3-384, SHA3-512 hash functions
// d is the digest buffer pointer
// m is the input buffer pointer
// ms is the input size (in bytes)
// ds is the digest size (in bytes)
// r is the rate (in bytes)
void __sha3_sponge_hash(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds, const size_t r)
{
	// compute the number of blocks
	size_t blocks_cnt = ms / r;

	// the state buffer
	uint8_t S[SHA3_KECCAK_WIDTH];

	// zero the state buffer
	memset(S, 0x00, SHA3_KECCAK_WIDTH);

	// process the state buffer
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		for(size_t j = 0; j < r; ++j)
		{
			S[j] ^= m[i * r + j];
		}

		__sha3_keccak(S);
	}

	// the last block
	uint8_t last_block[SHA3_KECCAK_WIDTH];

	// compute the last block size
	size_t last_block_size = ms % r;

	// copy the last block
	memcpy(last_block, m + blocks_cnt * r, last_block_size);

	// compute the number of padding bytes
	size_t pad_bytes_cnt = r - last_block_size;

	// pad the last block
	// see table 6
	if(pad_bytes_cnt == 1)
	{
		// append 0110 0001 bit string
		last_block[last_block_size] = 0x86;
	}
	else
	{
		// compute the number of zero bytes
		size_t pad_zeros_cnt = pad_bytes_cnt - 2;

		// append 0110 0000 bit string
		last_block[last_block_size] = 0x06;
		
		// append 0 bits
		memset(last_block + last_block_size + 1, 0x00, pad_zeros_cnt);

		// append 0000 0001 bit string
		last_block[last_block_size + pad_zeros_cnt + 1] = 0x80;
	}

	// process the last block
	for(size_t j = 0; j < r; ++j)
	{
		S[j] ^= last_block[j];
	}

	__sha3_keccak(S);

	// copy the digest buffer
	memcpy(d, S, ds);
}

// sponge function for SHAKE128, SHAKE256 hash functions
// d is the digest buffer pointer
// m is the input buffer pointer
// ms is the input size (in bytes)
// ds is the digest size (in bytes)
// r is the rate (in bytes)
void __sha3_sponge_xof(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds, const size_t r)
{
	// compute the number of blocks
	size_t blocks_cnt = ms / r;

	// the state buffer
	uint8_t S[SHA3_KECCAK_WIDTH];

	// zero the state buffer
	memset(S, 0x00, SHA3_KECCAK_WIDTH);

	// process the state buffer
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		for(size_t j = 0; j < r; ++j)
		{
			S[j] ^= m[i * r + j];
		}

		__sha3_keccak(S);
	}

	// the last block
	uint8_t last_block[SHA3_KECCAK_WIDTH];

	// compute the last block size
	size_t last_block_size = ms % r;

	// copy the last block
	memcpy(last_block, m + blocks_cnt * r, last_block_size);

	// compute the number of padding bytes
	size_t pad_bytes_cnt = r - last_block_size;

	// pad the last block
	// see table 6
	if(pad_bytes_cnt == 1)
	{
		// append 0110 0001 bit string
		last_block[last_block_size] = 0x9F;
	}
	else
	{
		// compute the number of zero bytes
		size_t pad_zeros_cnt = pad_bytes_cnt - 2;

		// append 0110 0000 bit string
		last_block[last_block_size] = 0x1F;
		
		// append 0 bits
		memset(last_block + last_block_size + 1, 0x00, pad_zeros_cnt);

		// append 0000 0001 bit string
		last_block[last_block_size + pad_zeros_cnt + 1] = 0x80;
	}

	// process the last block
	for(size_t j = 0; j < r; ++j)
	{
		S[j] ^= last_block[j];
	}

	__sha3_keccak(S);

	// compute the number of digest blocks
	size_t digest_blocks_cnt = ds / r;

	// compose the digest buffer
	for(size_t i = 0; i < digest_blocks_cnt; ++i)
	{
		// copy the digest block
		memcpy(d + i * r, S, r);

		__sha3_keccak(S);
	}

	// compute the last digest block size
	size_t last_digest_block_size = ds % r;

	// copy the last digest block
	memcpy(d + digest_blocks_cnt * r, S, last_digest_block_size);
}

void sha3_224(uint8_t* d, const uint8_t* m, const size_t s)
{
	const size_t c = SHA3_224_DIGEST_SIZE * 2;

	__sha3_sponge_hash(d, m, s, SHA3_224_DIGEST_SIZE, SHA3_KECCAK_WIDTH - c);
}

void sha3_256(uint8_t* d, const uint8_t* m, const size_t s)
{
	const size_t c = SHA3_256_DIGEST_SIZE * 2;

	__sha3_sponge_hash(d, m, s, SHA3_256_DIGEST_SIZE, SHA3_KECCAK_WIDTH - c);
}

void sha3_384(uint8_t* d, const uint8_t* m, const size_t s)
{
	const size_t c = SHA3_384_DIGEST_SIZE * 2;

	__sha3_sponge_hash(d, m, s, SHA3_384_DIGEST_SIZE, SHA3_KECCAK_WIDTH - c);
}

void sha3_512(uint8_t* d, const uint8_t* m, const size_t s)
{
	const size_t c = SHA3_512_DIGEST_SIZE * 2;

	__sha3_sponge_hash(d, m, s, SHA3_512_DIGEST_SIZE, SHA3_KECCAK_WIDTH - c);
}

void shake128(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds)
{
	__sha3_sponge_xof(d, m, ms, ds, SHA3_KECCAK_WIDTH - 32);
}

void shake256(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds)
{
	__sha3_sponge_xof(d, m, ms, ds, SHA3_KECCAK_WIDTH - 64);
}


