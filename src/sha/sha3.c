
#include <openhl/sha/sha3.h>

#define SHA3_KECCAK_WIDTH  200 // the width of the underlying function in bytes
#define SHA3_KECCAK_ROUNDS  24 // the number of rounds of the underlying function

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
	// a temporary state matrix 5x5x64
	uint64_t s[25];

	// y = 0
	s[ 0] = A[ 0] ^ (~A[ 1] & A[ 2]);
	s[ 1] = A[ 1] ^ (~A[ 2] & A[ 3]);
	s[ 2] = A[ 2] ^ (~A[ 3] & A[ 4]);
	s[ 3] = A[ 3] ^ (~A[ 4] & A[ 0]);
	s[ 4] = A[ 4] ^ (~A[ 0] & A[ 1]);

	// y = 1
	s[ 5] = A[ 5] ^ (~A[ 6] & A[ 7]);
	s[ 6] = A[ 6] ^ (~A[ 7] & A[ 8]);
	s[ 7] = A[ 7] ^ (~A[ 8] & A[ 9]);
	s[ 8] = A[ 8] ^ (~A[ 9] & A[ 5]);
	s[ 9] = A[ 9] ^ (~A[ 5] & A[ 6]);

	// y = 2
	s[10] = A[10] ^ (~A[11] & A[12]);
	s[11] = A[11] ^ (~A[12] & A[13]);
	s[12] = A[12] ^ (~A[13] & A[14]);
	s[13] = A[13] ^ (~A[14] & A[10]);
	s[14] = A[14] ^ (~A[10] & A[11]);

	// y = 3
	s[15] = A[15] ^ (~A[16] & A[17]);
	s[16] = A[16] ^ (~A[17] & A[18]);
	s[17] = A[17] ^ (~A[18] & A[19]);
	s[18] = A[18] ^ (~A[19] & A[15]);
	s[19] = A[19] ^ (~A[15] & A[16]);

	// y = 4
	s[20] = A[20] ^ (~A[21] & A[22]);
	s[21] = A[21] ^ (~A[22] & A[23]);
	s[22] = A[22] ^ (~A[23] & A[24]);
	s[23] = A[23] ^ (~A[24] & A[20]);
	s[24] = A[24] ^ (~A[20] & A[21]);

	// copy the temporary state matrix
	memcpy(A, s, SHA3_KECCAK_WIDTH);
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

void __sha3_hash(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds)
{
	// the capacity is double the digest size in bytes
	size_t capacity = ds * 2;

	// the rate of the sponge function in bytes
	size_t rate = SHA3_KECCAK_WIDTH - capacity;

	// compute the number of blocks
	size_t blocks_cnt = ms / rate;

	// the state buffer
	uint8_t S[SHA3_KECCAK_WIDTH];

	// zero the state buffer
	memset(S, 0x00, SHA3_KECCAK_WIDTH);

	// process the state buffer
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		for(size_t j = 0; j < rate; ++j)
		{
			S[j] ^= m[i * rate + j];
		}

		__sha3_keccak(S);
	}

	// the last blocks
	uint8_t last_blocks[2 * SHA3_KECCAK_WIDTH];

	// compute the last block size
	size_t last_m_block_size = ms % rate;

	// copy the last block
	memcpy(last_blocks, m + blocks_cnt * rate, last_m_block_size);

	// compute the number of padding bytes
	size_t padding_cnt = rate - (ms % rate);

	// compute the number of zero bytes
	size_t padding_zeros_cnt = padding_cnt - 2;

	// pad the message
	// see table 6
	switch(padding_cnt)
	{
		case 1:
			last_blocks[last_m_block_size] = 0x86;
			break;
		case 2:
			last_blocks[last_m_block_size    ] = 0x06;
			last_blocks[last_m_block_size + 1] = 0x80;
			break;
		default:
			last_blocks[last_m_block_size] = 0x06;
			memset(last_blocks + last_m_block_size + 1, 0x00, padding_zeros_cnt);
			last_blocks[last_m_block_size + 1 + padding_zeros_cnt] = 0x80;
			break;
	}

	// compute the last blocks size
	size_t last_blocks_size = last_m_block_size + padding_cnt;

	// compute the number of last blocks
	size_t last_blocks_cnt = last_blocks_size / rate;

	// process the last blocks
	for(size_t i = 0; i < last_blocks_cnt; ++i)
	{
		for(size_t j = 0; j < rate; ++j)
		{
			S[j] ^= last_blocks[i * rate + j];
		}

		__sha3_keccak(S);
	}

	// the Z buffer
	uint8_t Z[SHA3_KECCAK_WIDTH];

	// the Z buffer size
	size_t z_size = 0;

	// execute the last stage
	while(1)
	{
		memcpy(Z + z_size, S, rate);

		z_size += rate;

		if(z_size >= ds)
			break;

		__sha3_keccak(S);
	}

	// copy the digest
	memcpy(d, Z, ds);
}

void sha3_224(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha3_hash(d, m, s, SHA3_224_DIGEST_SIZE);
}

void sha3_256(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha3_hash(d, m, s, SHA3_256_DIGEST_SIZE);
}

void sha3_384(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha3_hash(d, m, s, SHA3_384_DIGEST_SIZE);
}

void sha3_512(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha3_hash(d, m, s, SHA3_512_DIGEST_SIZE);
}


