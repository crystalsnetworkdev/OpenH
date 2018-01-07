
#include <openhl/md/md5.h>

#define MD5_F(x, y, z) (((x) & (y)) | (~(x) & (z)))                        // MD5 F function
#define MD5_G(x, y, z) (((x) & (z)) | ((y) & ~(z)))                        // MD5 G function
#define MD5_H(x, y, z) ((x) ^ (y) ^ (z))                                   // MD5 H function
#define MD5_I(x, y, z) ((y) ^ ((x) | ~(z)))                                // MD5 I function

#define MD5_HASH_STEP0(t, s, k)                                            \
	T = a + MD5_F(b, c, d) + k + ((uint32_t*)(m + i * 64))[t];             \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b += ROTL32(T, s);

#define MD5_HASH_STEP1(t, s, k)                                            \
	T = a + MD5_G(b, c, d) + k + ((uint32_t*)(m + i * 64))[(5*t+1) & 0xF]; \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b += ROTL32(T, s);

#define MD5_HASH_STEP2(t, s, k)                                            \
	T = a + MD5_H(b, c, d) + k + ((uint32_t*)(m + i * 64))[(3*t+5) & 0xF]; \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b += ROTL32(T, s);

#define MD5_HASH_STEP3(t, s, k)                                            \
	T = a + MD5_I(b, c, d) + k + ((uint32_t*)(m + i * 64))[(7*t) & 0xF];   \
	a = d;                                                                 \
	d = c;                                                                 \
	c = b;                                                                 \
	b += ROTL32(T, s);

void* md5(void* dig, const void* msg, size_t size)
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

		// [  0, 15 ]
		MD5_HASH_STEP0( 0,  7, 0xd76aa478)
		MD5_HASH_STEP0( 1, 12, 0xe8c7b756)
		MD5_HASH_STEP0( 2, 17, 0x242070db)
		MD5_HASH_STEP0( 3, 22, 0xc1bdceee)
		MD5_HASH_STEP0( 4,  7, 0xf57c0faf)
		MD5_HASH_STEP0( 5, 12, 0x4787c62a)
		MD5_HASH_STEP0( 6, 17, 0xa8304613)
		MD5_HASH_STEP0( 7, 22, 0xfd469501)
		MD5_HASH_STEP0( 8,  7, 0x698098d8)
		MD5_HASH_STEP0( 9, 12, 0x8b44f7af)
		MD5_HASH_STEP0(10, 17, 0xffff5bb1)
		MD5_HASH_STEP0(11, 22, 0x895cd7be)
		MD5_HASH_STEP0(12,  7, 0x6b901122)
		MD5_HASH_STEP0(13, 12, 0xfd987193)
		MD5_HASH_STEP0(14, 17, 0xa679438e)
		MD5_HASH_STEP0(15, 22, 0x49b40821)

		// [ 16, 31 ]
		MD5_HASH_STEP1(16,  5, 0xf61e2562)
		MD5_HASH_STEP1(17,  9, 0xc040b340)
		MD5_HASH_STEP1(18, 14, 0x265e5a51)
		MD5_HASH_STEP1(19, 20, 0xe9b6c7aa)
		MD5_HASH_STEP1(20,  5, 0xd62f105d)
		MD5_HASH_STEP1(21,  9, 0x02441453)
		MD5_HASH_STEP1(22, 14, 0xd8a1e681)
		MD5_HASH_STEP1(23, 20, 0xe7d3fbc8)
		MD5_HASH_STEP1(24,  5, 0x21e1cde6)
		MD5_HASH_STEP1(25,  9, 0xc33707d6)
		MD5_HASH_STEP1(26, 14, 0xf4d50d87)
		MD5_HASH_STEP1(27, 20, 0x455a14ed)
		MD5_HASH_STEP1(28,  5, 0xa9e3e905)
		MD5_HASH_STEP1(29,  9, 0xfcefa3f8)
		MD5_HASH_STEP1(30, 14, 0x676f02d9)
		MD5_HASH_STEP1(31, 20, 0x8d2a4c8a)

		// [ 32, 47 ]
		MD5_HASH_STEP2(32,  4, 0xfffa3942)
		MD5_HASH_STEP2(33, 11, 0x8771f681)
		MD5_HASH_STEP2(34, 16, 0x6d9d6122)
		MD5_HASH_STEP2(35, 23, 0xfde5380c)
		MD5_HASH_STEP2(36,  4, 0xa4beea44)
		MD5_HASH_STEP2(37, 11, 0x4bdecfa9)
		MD5_HASH_STEP2(38, 16, 0xf6bb4b60)
		MD5_HASH_STEP2(39, 23, 0xbebfbc70)
		MD5_HASH_STEP2(40,  4, 0x289b7ec6)
		MD5_HASH_STEP2(41, 11, 0xeaa127fa)
		MD5_HASH_STEP2(42, 16, 0xd4ef3085)
		MD5_HASH_STEP2(43, 23, 0x04881d05)
		MD5_HASH_STEP2(44,  4, 0xd9d4d039)
		MD5_HASH_STEP2(45, 11, 0xe6db99e5)
		MD5_HASH_STEP2(46, 16, 0x1fa27cf8)
		MD5_HASH_STEP2(47, 23, 0xc4ac5665)

		// [ 48, 63 ]
		MD5_HASH_STEP3(48,  6, 0xf4292244)
		MD5_HASH_STEP3(49, 10, 0x432aff97)
		MD5_HASH_STEP3(50, 15, 0xab9423a7)
		MD5_HASH_STEP3(51, 21, 0xfc93a039)
		MD5_HASH_STEP3(52,  6, 0x655b59c3)
		MD5_HASH_STEP3(53, 10, 0x8f0ccc92)
		MD5_HASH_STEP3(54, 15, 0xffeff47d)
		MD5_HASH_STEP3(55, 21, 0x85845dd1)
		MD5_HASH_STEP3(56,  6, 0x6fa87e4f)
		MD5_HASH_STEP3(57, 10, 0xfe2ce6e0)
		MD5_HASH_STEP3(58, 15, 0xa3014314)
		MD5_HASH_STEP3(59, 21, 0x4e0811a1)
		MD5_HASH_STEP3(60,  6, 0xf7537e82)
		MD5_HASH_STEP3(61, 10, 0xbd3af235)
		MD5_HASH_STEP3(62, 15, 0x2ad7d2bb)
		MD5_HASH_STEP3(63, 21, 0xeb86d391)

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


