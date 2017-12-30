
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


