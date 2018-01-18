
#include <openhl/sha/sha3.h>

#define SHA3_KECCAK_P_WIDTH   200 // the width of the underlying function in bytes
#define SHA3_KECCAK_P_ROUNDS   24 // the number of rounds of the underlying function

static const uint64_t RC[SHA3_KECCAK_P_ROUNDS] =
{
	0x0000000000000001,
	0x0000000000008082,
	0x800000000000808A,
	0x8000000080008000,
	0x000000000000808B,
	0x0000000080000001,
	0x8000000080008081,
	0x8000000000008009,
	0x000000000000008A,
	0x0000000000000088,
	0x0000000080008009,
	0x000000008000000A,
	0x000000008000808B,
	0x800000000000008B,
	0x8000000000008089,
	0x8000000000008003,
	0x8000000000008002,
	0x8000000000000080,
	0x000000000000800A,
	0x800000008000000A,
	0x8000000080008081,
	0x8000000000008080,
	0x0000000080000001,
	0x8000000080008008
};

void __sha3_keccak_theta(uint64_t state[25])
{
	// step 1
	uint64_t C[5];
	C[0] = state[ 0] ^ state[ 5] ^ state[10] ^ state[15] ^ state[20];
	C[1] = state[ 1] ^ state[ 6] ^ state[11] ^ state[16] ^ state[21];
	C[2] = state[ 2] ^ state[ 7] ^ state[12] ^ state[17] ^ state[22];
	C[3] = state[ 3] ^ state[ 8] ^ state[13] ^ state[18] ^ state[23];
	C[4] = state[ 4] ^ state[ 9] ^ state[14] ^ state[19] ^ state[24];

	// step 2
	uint64_t D[5];
	D[0] = C[4] ^ ROTL64(C[1], 1);
	D[1] = C[0] ^ ROTL64(C[2], 1);
	D[2] = C[1] ^ ROTL64(C[3], 1);
	D[3] = C[2] ^ ROTL64(C[4], 1);
	D[4] = C[3] ^ ROTL64(C[0], 1);

	// step 3
	state[ 0] ^= D[0];
	state[ 1] ^= D[1];
	state[ 2] ^= D[2];
	state[ 3] ^= D[3];
	state[ 4] ^= D[4];
	state[ 5] ^= D[0];
	state[ 6] ^= D[1];
	state[ 7] ^= D[2];
	state[ 8] ^= D[3];
	state[ 9] ^= D[4];
	state[10] ^= D[0];
	state[11] ^= D[1];
	state[12] ^= D[2];
	state[13] ^= D[3];
	state[14] ^= D[4];
	state[15] ^= D[0];
	state[16] ^= D[1];
	state[17] ^= D[2];
	state[18] ^= D[3];
	state[19] ^= D[4];
	state[20] ^= D[0];
	state[21] ^= D[1];
	state[22] ^= D[2];
	state[23] ^= D[3];
	state[24] ^= D[4];
}

void __sha3_keccak_rho(uint64_t state[25])
{
	// y = 0
	state[ 1] = ROTL64(state[ 1],  1);
	state[ 2] = ROTL64(state[ 2], 62);
	state[ 3] = ROTL64(state[ 3], 28);
	state[ 4] = ROTL64(state[ 4], 27);

	// y = 1
	state[ 5] = ROTL64(state[ 5], 36);
	state[ 6] = ROTL64(state[ 6], 44);
	state[ 7] = ROTL64(state[ 7],  6);
	state[ 8] = ROTL64(state[ 8], 55);
	state[ 9] = ROTL64(state[ 9], 20);

	// y = 2
	state[10] = ROTL64(state[10],  3);
	state[11] = ROTL64(state[11], 10);
	state[12] = ROTL64(state[12], 43);
	state[13] = ROTL64(state[13], 25);
	state[14] = ROTL64(state[14], 39);

	// y = 3
	state[15] = ROTL64(state[15], 41);
	state[16] = ROTL64(state[16], 45);
	state[17] = ROTL64(state[17], 15);
	state[18] = ROTL64(state[18], 21);
	state[19] = ROTL64(state[19],  8);

	// y = 4
	state[20] = ROTL64(state[20], 18);
	state[21] = ROTL64(state[21],  2);
	state[22] = ROTL64(state[22], 61);
	state[23] = ROTL64(state[23], 56);
	state[24] = ROTL64(state[24], 14);
}

void __sha3_keccak_pi(uint64_t state[25])
{
	uint64_t tmp = state[13];
	state[13] = state[19];
	state[19] = state[23];
	state[23] = state[15];
	state[15] = state[ 4];
	state[ 4] = state[24];
	state[24] = state[21];
	state[21] = state[ 8];
	state[ 8] = state[16];
	state[16] = state[ 5];
	state[ 5] = state[ 3];
	state[ 3] = state[18];
	state[18] = state[17];
	state[17] = state[11];
	state[11] = state[ 7];
	state[ 7] = state[10];
	state[10] = state[ 1];
	state[ 1] = state[ 6];
	state[ 6] = state[ 9];
	state[ 9] = state[22];
	state[22] = state[14];
	state[14] = state[20];
	state[20] = state[ 2];
	state[ 2] = state[12];
	state[12] = tmp;
}

void __sha3_keccak_chi(uint64_t state[25])
{
	// a temporary state matrix 5x5x64
	uint64_t s[25];

	// y = 0
	s[ 0] = state[ 0] ^ (~state[ 1] & state[ 2]);
	s[ 1] = state[ 1] ^ (~state[ 2] & state[ 3]);
	s[ 2] = state[ 2] ^ (~state[ 3] & state[ 4]);
	s[ 3] = state[ 3] ^ (~state[ 4] & state[ 0]);
	s[ 4] = state[ 4] ^ (~state[ 0] & state[ 1]);

	// y = 1
	s[ 5] = state[ 5] ^ (~state[ 6] & state[ 7]);
	s[ 6] = state[ 6] ^ (~state[ 7] & state[ 8]);
	s[ 7] = state[ 7] ^ (~state[ 8] & state[ 9]);
	s[ 8] = state[ 8] ^ (~state[ 9] & state[ 5]);
	s[ 9] = state[ 9] ^ (~state[ 5] & state[ 6]);

	// y = 2
	s[10] = state[10] ^ (~state[11] & state[12]);
	s[11] = state[11] ^ (~state[12] & state[13]);
	s[12] = state[12] ^ (~state[13] & state[14]);
	s[13] = state[13] ^ (~state[14] & state[10]);
	s[14] = state[14] ^ (~state[10] & state[11]);

	// y = 3
	s[15] = state[15] ^ (~state[16] & state[17]);
	s[16] = state[16] ^ (~state[17] & state[18]);
	s[17] = state[17] ^ (~state[18] & state[19]);
	s[18] = state[18] ^ (~state[19] & state[15]);
	s[19] = state[19] ^ (~state[15] & state[16]);

	// y = 4
	s[20] = state[20] ^ (~state[21] & state[22]);
	s[21] = state[21] ^ (~state[22] & state[23]);
	s[22] = state[22] ^ (~state[23] & state[24]);
	s[23] = state[23] ^ (~state[24] & state[20]);
	s[24] = state[24] ^ (~state[20] & state[21]);

	// copy the temporary state matrix
	memcpy(state, s, 25 * sizeof(uint64_t));
}

void __sha3_keccak_iota(uint64_t state[25], const size_t i)
{
	// apply the round constant
	state[ 0] ^= RC[i];
}

void __sha3_keccak(uint8_t S[SHA3_KECCAK_P_WIDTH])
{
	// the state matrix 5x5x64
	uint64_t state[25];

	// copy the S buffer
	memcpy(state, S, SHA3_KECCAK_P_WIDTH);

	// execute the round function
	for(size_t i = 0; i < SHA3_KECCAK_P_ROUNDS; ++i)
	{
		// rnd(A, i) = iota(chi(pi(rho(theta(A)))), i)
		__sha3_keccak_theta(state);
		__sha3_keccak_rho(state);
		__sha3_keccak_pi(state);
		__sha3_keccak_chi(state);
		__sha3_keccak_iota(state, i);
	}

	// copy the state buffer
	memcpy(S, state, SHA3_KECCAK_P_WIDTH);
}

void __sha3_hash(uint8_t* d, const uint8_t* m, const size_t ms, const size_t ds)
{
	// the capacity is double the digest size in bytes
	size_t capacity = ds * 2;

	// the rate of the sponge function in bytes
	size_t rate = SHA3_KECCAK_P_WIDTH - capacity;

	// compute the number of blocks
	size_t blocks_cnt = ms / rate;

	// the state buffer
	uint8_t S[SHA3_KECCAK_P_WIDTH];

	// zero the state buffer
	memset(S, 0x00, SHA3_KECCAK_P_WIDTH);

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
	uint8_t last_blocks[2 * SHA3_KECCAK_P_WIDTH];

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
	uint8_t Z[SHA3_KECCAK_P_WIDTH];

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


