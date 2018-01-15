
#include <openhl/sha/sha2.h>

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))                      // CH function (4.2) (4.8)
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))        // MAJ function (4.3) (4.9)

#define SIGMA256_0(x) (ROTR32(x,  2) ^ ROTR32(x, 13) ^ ROTR32(x, 22)) // SHA-224 SHA-256 SIGMA0 function (4.4)
#define SIGMA256_1(x) (ROTR32(x,  6) ^ ROTR32(x, 11) ^ ROTR32(x, 25)) // SHA-224 SHA-256 SIGMA1 function (4.5)
#define sigma256_0(x) (ROTR32(x,  7) ^ ROTR32(x, 18) ^    SHR(x,  3)) // SHA-224 SHA-256 sigma0 function (4.6)
#define sigma256_1(x) (ROTR32(x, 17) ^ ROTR32(x, 19) ^    SHR(x, 10)) // SHA-224 SHA-256 sigma1 function (4.7)

#define SIGMA512_0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39)) // SHA-384 SHA-512 SHA-512/224 SHA-512/256 SIGMA0 function (4.10)
#define SIGMA512_1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41)) // SHA-384 SHA-512 SHA-512/224 SHA-512/256 SIGMA1 function (4.11)
#define sigma512_0(x) (ROTR64(x,  1) ^ ROTR64(x,  8) ^    SHR(x,  7)) // SHA-384 SHA-512 SHA-512/224 SHA-512/256 sigma0 function (4.12)
#define sigma512_1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^    SHR(x,  6)) // SHA-384 SHA-512 SHA-512/224 SHA-512/256 sigma1 function (4.13)

#define SHA256_HASH_STEP(t)                                       \
	T1 = h + SIGMA256_1(e) + CH(e, f, g) + K256[(t)] + w[(t)];    \
	T2 = SIGMA256_0(a) + MAJ(a, b, c);                            \
	h = g;                                                        \
	g = f;                                                        \
	f = e;                                                        \
	e = d + T1;                                                   \
	d = c;                                                        \
	c = b;                                                        \
	b = a;                                                        \
	a = T1 + T2;

#define SHA512_HASH_STEP(t)                                       \
	T1 = h + SIGMA512_1(e) + CH(e, f, g) + K512[(t)] + w[(t)];    \
	T2 = SIGMA512_0(a) + MAJ(a, b, c);                            \
	h = g;                                                        \
	g = f;                                                        \
	f = e;                                                        \
	e = d + T1;                                                   \
	d = c;                                                        \
	c = b;                                                        \
	b = a;                                                        \
	a = T1 + T2;

static const uint32_t K256[64] =
{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static const uint64_t K512[80] =
{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
};

static const uint32_t InitialHashSHA256[8] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t InitialHashSHA224[8] =
{
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

static const uint64_t InitialHashSHA512[8] =
{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1, 0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179
};

static const uint64_t InitialHashSHA384[8] =
{
	0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939, 0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4
};

static const uint64_t InitialHashSHA512_256[8] =
{
	0x22312194FC2BF72C, 0x9F555FA3C84C64C2, 0x2393B86B6F53B151, 0x963877195940EABD, 0x96283EE2A88EFFE3, 0xBE5E1E2553863992, 0x2B0199FC2C85B8AA, 0x0EB72DDC81C52CA2 
};

static const uint64_t InitialHashSHA512_224[8] =
{
	0x8C3D37C819544DA2, 0x73E1996689DCD4D6, 0x1DFAB7AE32FF9C82, 0x679DD514582F9FCF, 0x0F6D2B697BD44DA8, 0x77E36F7304C48942, 0x3F9D85A86A1D36C8, 0x1112E6AD91D692A1 
};

void __sha256_transform(uint32_t H[8], const uint32_t* block, const size_t n)
{
	// the message schedule
	uint32_t w[64];

	// the eight working variables
	uint32_t a, b, c, d, e, f, g, h;

	// two temporary variables used in the hash loop
	uint32_t T1, T2;

	// for each block of m
	for(size_t i = 0; i < n; ++i, block += 16)
	{
		// prepare the message schedule
		for(size_t t =  0; t < 16; ++t)
		{
			w[t] = BIG_ENDIAN32(block[t]);
		}

		for(size_t t = 16; t < 64; ++t)
		{
			w[t] = sigma256_1(w[t-2]) + w[t-7] + sigma256_0(w[t-15]) + w[t-16];
		}

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		// hash loop
		for(size_t t = 0; t < 64; t += 8)
		{
			SHA256_HASH_STEP(t+0)
			SHA256_HASH_STEP(t+1)
			SHA256_HASH_STEP(t+2)
			SHA256_HASH_STEP(t+3)
			SHA256_HASH_STEP(t+4)
			SHA256_HASH_STEP(t+5)
			SHA256_HASH_STEP(t+6)
			SHA256_HASH_STEP(t+7)
		}

		// compute the intermediate ith hash value
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}
}

void __sha512_transform(uint64_t H[8], const uint64_t* block, const size_t n)
{
	// the message schedule
	uint64_t w[80];

	// the eight working variables
	uint64_t a, b, c, d, e, f, g, h;

	// two temporary variables used in the hash loop
	uint64_t T1, T2;

	// for each block of m
	for(size_t i = 0; i < n; ++i, block += 16)
	{
		// prepare the message schedule
		for(size_t t =  0; t < 16; ++t)
		{
			w[t] = BIG_ENDIAN64(block[t]);
		}

		for(size_t t = 16; t < 80; ++t)
		{
			w[t] = sigma512_1(w[t-2]) + w[t-7] + sigma512_0(w[t-15]) + w[t-16];
		}

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];

		// hash loop
		for(size_t t = 0; t < 80; t += 8)
		{
			SHA512_HASH_STEP(t+0)
			SHA512_HASH_STEP(t+1)
			SHA512_HASH_STEP(t+2)
			SHA512_HASH_STEP(t+3)
			SHA512_HASH_STEP(t+4)
			SHA512_HASH_STEP(t+5)
			SHA512_HASH_STEP(t+6)
			SHA512_HASH_STEP(t+7)
		}

		// compute the intermediate ith hash value
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
		H[5] += f;
		H[6] += g;
		H[7] += h;
	}
}

void __sha256(uint8_t* d, const uint8_t* m, const size_t s, const uint32_t ih[8])
{
	// set the initial hash value
	uint32_t H[8];
	memcpy(H, ih, 8 * sizeof(uint32_t));

	// compute the number of blocks
	size_t blocks_cnt = s / 64;

	// hash process for each block
	__sha256_transform(H, (uint32_t*)m, blocks_cnt);

	// the last blocks buffer
	uint8_t last_blocks[2 * 64];

	// compute the size of the last message block
	size_t last_m_block_size = s & 0x3F;

	// compute the last blocks size
	size_t last_blocks_size = (last_m_block_size + 1 + sizeof(uint64_t) + 63) & ~0x3F;

	// copy the last block message
	memcpy(last_blocks, m + blocks_cnt * 64, last_m_block_size);

	// append 1 bit
	last_blocks[last_m_block_size] = 0x80;

	// append 0 bits
	memset(last_blocks + last_m_block_size + 1, 0x00, last_blocks_size - last_m_block_size - 1 - sizeof(uint64_t));

	// compute and append the length in bits of the message
	uint64_t length = BIG_ENDIAN64(s * 8);
	memcpy(last_blocks + last_blocks_size - sizeof(uint64_t), &length, sizeof(uint64_t));

	// hash process the last blocks
	__sha256_transform(H, (uint32_t*)last_blocks, last_blocks_size / 64);

	// compose the digest
	((uint32_t*)d)[0] = BIG_ENDIAN32(H[0]);
	((uint32_t*)d)[1] = BIG_ENDIAN32(H[1]);
	((uint32_t*)d)[2] = BIG_ENDIAN32(H[2]);
	((uint32_t*)d)[3] = BIG_ENDIAN32(H[3]);
	((uint32_t*)d)[4] = BIG_ENDIAN32(H[4]);
	((uint32_t*)d)[5] = BIG_ENDIAN32(H[5]);
	((uint32_t*)d)[6] = BIG_ENDIAN32(H[6]);
	((uint32_t*)d)[7] = BIG_ENDIAN32(H[7]);
}

void __sha512(uint8_t* d, const uint8_t* m, const size_t s, const uint64_t ih[8])
{
	// set the initial hash value
	uint64_t H[8];
	memcpy(H, ih, 8 * sizeof(uint64_t));

	// compute the number of blocks
	size_t blocks_cnt = s / 128;

	// hash process for each block
	__sha512_transform(H, (uint64_t*)m, blocks_cnt);

	// the last blocks buffer
	uint8_t last_blocks[2 * 128];

	// compute the size of the last message block
	size_t last_m_block_size = s & 0x7F;

	// compute the last blocks size
	size_t last_blocks_size = (last_m_block_size + 1 + sizeof(uint64_t) + 127) & ~0x7F;

	// copy the last block message
	memcpy(last_blocks, m + blocks_cnt * 128, last_m_block_size);

	// append 1 bit
	last_blocks[last_m_block_size] = 0x80;

	// append 0 bits
	memset(last_blocks + last_m_block_size + 1, 0x00, last_blocks_size - last_m_block_size - 1 - sizeof(uint64_t));

	// compute and append the length in bits of the message
	uint64_t length = BIG_ENDIAN64(s * 8);
	memcpy(last_blocks + last_blocks_size - sizeof(uint64_t), &length, sizeof(uint64_t));

	// hash process the last blocks
	__sha512_transform(H, (uint64_t*)last_blocks, last_blocks_size / 128);

	// compose the digest
	((uint64_t*)d)[0] = BIG_ENDIAN64(H[0]);
	((uint64_t*)d)[1] = BIG_ENDIAN64(H[1]);
	((uint64_t*)d)[2] = BIG_ENDIAN64(H[2]);
	((uint64_t*)d)[3] = BIG_ENDIAN64(H[3]);
	((uint64_t*)d)[4] = BIG_ENDIAN64(H[4]);
	((uint64_t*)d)[5] = BIG_ENDIAN64(H[5]);
	((uint64_t*)d)[6] = BIG_ENDIAN64(H[6]);
	((uint64_t*)d)[7] = BIG_ENDIAN64(H[7]);
}

void sha256(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha256(d, m, s, InitialHashSHA256);
}

void sha224(uint8_t* d, const uint8_t* m, const size_t s)
{
	uint8_t d256[SHA256_DIGEST_SIZE];

	__sha256(d256, m, s, InitialHashSHA224);

	memcpy(d, d256, SHA224_DIGEST_SIZE);
}

void sha512(uint8_t* d, const uint8_t* m, const size_t s)
{
	__sha512(d, m, s, InitialHashSHA512);
}

void sha384(uint8_t* d, const uint8_t* m, const size_t s)
{
	uint8_t d512[SHA512_DIGEST_SIZE];

	__sha512(d512, m, s, InitialHashSHA384);

	memcpy(d, d512, SHA384_DIGEST_SIZE);
}

void sha512_256(uint8_t* d, const uint8_t* m, const size_t s)
{
	uint8_t d512[SHA512_DIGEST_SIZE];

	__sha512(d512, m, s, InitialHashSHA512_256);

	memcpy(d, d512, SHA256_DIGEST_SIZE);
}

void sha512_224(uint8_t* d, const uint8_t* m, const size_t s)
{
	uint8_t d512[SHA512_DIGEST_SIZE];

	__sha512(d512, m, s, InitialHashSHA512_224);

	memcpy(d, d512, SHA224_DIGEST_SIZE);
}


