
#include <openhl/md/md4.h>

#define MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))                        // MD4 F function
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))           // MD4 G function
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))                                   // MD4 H function

#define MD4_HASH_STEP0(t, s)                                               \
	T = a + MD4_F(b, c, d) + ((uint32_t*)(m + i * 64))[t];                 \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b = ROTL32(T, s);

#define MD4_HASH_STEP1(t, s)                                               \
	T = a + MD4_G(b, c, d) + 0x5a827999 + ((uint32_t*)(m + i * 64))[t];    \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b = ROTL32(T, s);

#define MD4_HASH_STEP2(t, s)                                               \
	T = a + MD4_H(b, c, d) + 0x6ed9eba1 + ((uint32_t*)(m + i * 64))[t];    \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b = ROTL32(T, s);

void* md4(void* dig, const void* msg, size_t size)
{
	// compute the size of the m buffer that must be a multiple of 64
	size_t m_size = (size + 1 + sizeof(uint64_t) + 63) & ~0x3F;

	// allocate the m buffer
	uint8_t* m = (uint8_t*)malloc(m_size);

	if(!m)
		return NULL;

	// copy the msg buffer
	memcpy(m, msg, size);

	// pad m
	m[size] = 0x80;
	memset(m + size + 1, 0, m_size - size - 1 - sizeof(uint64_t));
	uint64_t l = LITTLE_ENDIAN64(size * 8);
	memcpy(m + m_size - sizeof(uint64_t), &l, sizeof(uint64_t));

	// compute the number of blocks
	size_t blocks_cnt = m_size / 64;

	// set the initial hash values
	uint32_t h0, h1, h2, h3;
	h0 = 0x67452301;
	h1 = 0xefcdab89;
	h2 = 0x98badcfe;
	h3 = 0x10325476;

	// the four working variables
	uint32_t a, b, c, d;

	// a temporary variable used in the hash process
	uint32_t T;

	// for each block of m
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		a = h0;
		b = h1;
		c = h2;
		d = h3;

		// round 1
		MD4_HASH_STEP0( 0,  3)
		MD4_HASH_STEP0( 1,  7)
		MD4_HASH_STEP0( 2, 11)
		MD4_HASH_STEP0( 3, 19)
		MD4_HASH_STEP0( 4,  3)
		MD4_HASH_STEP0( 5,  7)
		MD4_HASH_STEP0( 6, 11)
		MD4_HASH_STEP0( 7, 19)
		MD4_HASH_STEP0( 8,  3)
		MD4_HASH_STEP0( 9,  7)
		MD4_HASH_STEP0(10, 11)
		MD4_HASH_STEP0(11, 19)
		MD4_HASH_STEP0(12,  3)
		MD4_HASH_STEP0(13,  7)
		MD4_HASH_STEP0(14, 11)
		MD4_HASH_STEP0(15, 19)

		// round 2
		MD4_HASH_STEP1( 0,  3)
		MD4_HASH_STEP1( 4,  5)
		MD4_HASH_STEP1( 8,  9)
		MD4_HASH_STEP1(12, 13)
		MD4_HASH_STEP1( 1,  3)
		MD4_HASH_STEP1( 5,  5)
		MD4_HASH_STEP1( 9,  9)
		MD4_HASH_STEP1(13, 13)
		MD4_HASH_STEP1( 2,  3)
		MD4_HASH_STEP1( 6,  5)
		MD4_HASH_STEP1(10,  9)
		MD4_HASH_STEP1(14, 13)
		MD4_HASH_STEP1( 3,  3)
		MD4_HASH_STEP1( 7,  5)
		MD4_HASH_STEP1(11,  9)
		MD4_HASH_STEP1(15, 13)

		// round 3
		MD4_HASH_STEP2( 0,  3)
		MD4_HASH_STEP2( 8,  9)
		MD4_HASH_STEP2( 4, 11)
		MD4_HASH_STEP2(12, 15)
		MD4_HASH_STEP2( 2,  3)
		MD4_HASH_STEP2(10,  9)
		MD4_HASH_STEP2( 6, 11)
		MD4_HASH_STEP2(14, 15)
		MD4_HASH_STEP2( 1,  3)
		MD4_HASH_STEP2( 9,  9)
		MD4_HASH_STEP2( 5, 11)
		MD4_HASH_STEP2(13, 15)
		MD4_HASH_STEP2( 3,  3)
		MD4_HASH_STEP2(11,  9)
		MD4_HASH_STEP2( 7, 11)
		MD4_HASH_STEP2(15, 15)

		// compute the intermediate ith hash value
		h0 += a;
		h1 += b;
		h2 += c;
		h3 += d;
	}

	// compose the digest
	((uint32_t*)dig)[0] = LITTLE_ENDIAN32(h0);
	((uint32_t*)dig)[1] = LITTLE_ENDIAN32(h1);
	((uint32_t*)dig)[2] = LITTLE_ENDIAN32(h2);
	((uint32_t*)dig)[3] = LITTLE_ENDIAN32(h3);

	return dig;
}


