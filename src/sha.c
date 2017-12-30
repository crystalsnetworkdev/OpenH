
#include "openhl/sha.h"

#define SHA1_HASH_STEP0(t)                                        \
	T = ROTL32(a, 5) + CH(b, c, d) + e + 0x5a827999 + w[(t)];     \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP1(t)                                        \
	T = ROTL32(a, 5) + PARITY(b, c, d) + e + 0x6ed9eba1 + w[(t)]; \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP2(t)                                        \
	T = ROTL32(a, 5) + MAJ(b, c, d) + e + 0x8f1bbcdc + w[(t)];    \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP3(t)                                        \
	T = ROTL32(a, 5) + PARITY(b, c, d) + e + 0xca62c1d6 + w[(t)]; \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

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

static const uint32_t InitialHashSHA256[8] =
{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

static const uint32_t InitialHashSHA224[8] =
{
	0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4
};

void* sha1(void* dig, const void* msg, size_t size)
{
	// compute the size of the m buffer that must be a multiple of 64
	size_t m_size = (size + 1 + sizeof(uint64_t) + 63) & ~0x3F;

	// compute the number of blocks
	size_t block_cnt = m_size / 64;

	// allocate the m buffer
	uint8_t* m = (uint8_t*)malloc(m_size);

	if(!m)
		return NULL;

	// copy the msg buffer
	memcpy(m, msg, size);

	// pad m
	m[size] = 0x80;
	memset(m + size + 1, 0, m_size - size - 1 - sizeof(uint64_t));
	uint64_t l = BSWAP64(size * 8);
	memcpy(m + m_size - sizeof(uint64_t), &l, sizeof(uint64_t));

	// the message schedule
	uint32_t w[80];

	// set the initial hash value
	uint32_t h0, h1, h2, h3, h4;
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;
	h4 = 0xc3d2e1f0;

	// the five working variables
	uint32_t a, b, c, d, e;

	// a temporary variable used in the hash loops
	uint32_t T;

	// for each block of m
	for(size_t i = 0; i < block_cnt; ++i)
	{
		// prepare the message schedule
		for(size_t t =  0; t < 16; ++t)
		{
			w[t] = BSWAP32(((uint32_t*)(m + i * 64))[t]);
		}

		for(size_t t = 16; t < 80; ++t)
		{
			w[t] = ROTL32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
		}

		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;

		// hash loop [ 0, 19 ]
		for(size_t t =  0; t < 20; t += 5)
		{
			SHA1_HASH_STEP0(t+0)
			SHA1_HASH_STEP0(t+1)
			SHA1_HASH_STEP0(t+2)
			SHA1_HASH_STEP0(t+3)
			SHA1_HASH_STEP0(t+4)
		}

		// hash loop [ 20, 39 ]
		for(size_t t = 20; t < 40; t += 5)
		{
			SHA1_HASH_STEP1(t+0)
			SHA1_HASH_STEP1(t+1)
			SHA1_HASH_STEP1(t+2)
			SHA1_HASH_STEP1(t+3)
			SHA1_HASH_STEP1(t+4)
		}

		// hash loop [ 40, 59 ]
		for(size_t t = 40; t < 60; t += 5)
		{
			SHA1_HASH_STEP2(t+0)
			SHA1_HASH_STEP2(t+1)
			SHA1_HASH_STEP2(t+2)
			SHA1_HASH_STEP2(t+3)
			SHA1_HASH_STEP2(t+4)
		}

		// hash loop [ 60, 79 ]
		for(size_t t = 60; t < 80; t += 5)
		{
			SHA1_HASH_STEP3(t+0)
			SHA1_HASH_STEP3(t+1)
			SHA1_HASH_STEP3(t+2)
			SHA1_HASH_STEP3(t+3)
			SHA1_HASH_STEP3(t+4)
		}

		// compute the intermediate ith hash value
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
	}

	free(m);

	// compose the digest
	((uint32_t*)dig)[0] = BSWAP32(h0);
	((uint32_t*)dig)[1] = BSWAP32(h1);
	((uint32_t*)dig)[2] = BSWAP32(h2);
	((uint32_t*)dig)[3] = BSWAP32(h3);
	((uint32_t*)dig)[4] = BSWAP32(h4);

	return dig;
}

// generic internal sha256 hash function
void* __sha256(void* dig, const void* msg, size_t size, const uint32_t ih[8])
{
	// compute the size of the m buffer that must be a multiple of 64
	size_t m_size = (size + 1 + sizeof(uint64_t) + 63) & ~0x3F;

	// compute the number of blocks
	size_t block_cnt = m_size / 64;

	// allocate the m buffer
	uint8_t* m = (uint8_t*)malloc(m_size);

	if(!m)
		return NULL;

	// copy the msg buffer
	memcpy(m, msg, size);

	// pad m
	m[size] = 0x80;
	memset(m + size + 1, 0, m_size - size - 1 - sizeof(uint64_t));
	uint64_t l = BSWAP64(size * 8);
	memcpy(m + m_size - sizeof(uint64_t), &l, sizeof(uint64_t));

	// the message schedule
	uint32_t w[64];

	// set the initial hash value
	uint32_t h0, h1, h2, h3, h4, h5, h6, h7;
	h0 = ih[0];
	h1 = ih[1];
	h2 = ih[2];
	h3 = ih[3];
	h4 = ih[4];
	h5 = ih[5];
	h6 = ih[6];
	h7 = ih[7];

	// the eight working variables
	uint32_t a, b, c, d, e, f, g, h;

	// two temporary variables used in the hash loop
	uint32_t T1, T2;

	// for each block of m
	for(size_t i = 0; i < block_cnt; ++i)
	{
		// prepare the message schedule
		for(size_t t =  0; t < 16; ++t)
		{
			w[t] = BSWAP32(((uint32_t*)(m + i * 64))[t]);
		}

		for(size_t t = 16; t < 64; ++t)
		{
			w[t] = sigma256_1(w[t-2]) + w[t-7] + sigma256_0(w[t-15]) + w[t-16];
		}

		a = h0;
		b = h1;
		c = h2;
		d = h3;
		e = h4;
		f = h5;
		g = h6;
		h = h7;

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
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
		h4 += e;
		h5 += f;
		h6 += g;
		h7 += h;
	}

	free(m);

	// compose the digest
	((uint32_t*)dig)[0] = BSWAP32(h0);
	((uint32_t*)dig)[1] = BSWAP32(h1);
	((uint32_t*)dig)[2] = BSWAP32(h2);
	((uint32_t*)dig)[3] = BSWAP32(h3);
	((uint32_t*)dig)[4] = BSWAP32(h4);
	((uint32_t*)dig)[5] = BSWAP32(h5);
	((uint32_t*)dig)[6] = BSWAP32(h6);
	((uint32_t*)dig)[7] = BSWAP32(h7);

	return dig;
}

void* sha256(void* dig, const void* msg, size_t size)
{
	return __sha256(dig, msg, size, InitialHashSHA256);
}

void* sha224(void* dig, const void* msg, size_t size)
{
	uint8_t dig256[SHA256_DIGEST_SIZE];

	if(!__sha256(dig256, msg, size, InitialHashSHA224))
		return NULL;

	memcpy(dig, dig256, SHA224_DIGEST_SIZE);

	return dig;
}





