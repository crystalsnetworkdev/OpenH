
#include <openhl/md/md4.h>

#define MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))              // MD4 F function
#define MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z))) // MD4 G function
#define MD4_H(x, y, z) ((x) ^ (y) ^ (z))                         // MD4 H function

#define MD4_HASH_STEP0(t, s) \
	T = a + MD4_F(b, c, d) + blocks[i * 16 + (t)];              \
	a = d;                                                      \
	d = c;                                                      \
	c = b;                                                      \
	b = ROTL32(T, (s));

#define MD4_HASH_STEP1(t, s) \
	T = a + MD4_G(b, c, d) + 0x5a827999 + blocks[i * 16 + (t)]; \
	a = d;                                                      \
	d = c;                                                      \
	c = b;                                                      \
	b = ROTL32(T, (s));

#define MD4_HASH_STEP2(t, s) \
	T = a + MD4_H(b, c, d) + 0x6ed9eba1 + blocks[i * 16 + (t)]; \
	a = d;                                                      \
	d = c;                                                      \
	c = b;                                                      \
	b = ROTL32(T, (s));

void __md4_transform(uint32_t H[4], const uint32_t* blocks, const size_t blocks_cnt)
{
	// the four working variables
	uint32_t a, b, c, d;

	// a temporary variable used in the hash process
	uint32_t T;

	// process every block
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];

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

		// compute the intermediate hash value
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
	}
}

void md4(uint8_t* d, const uint8_t* m, const size_t s)
{
	// set the initial hash values
	uint32_t H[4];
	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;

	// compute the number of blocks
	size_t blocks_cnt = s / 64;

	// hash process for each block
	__md4_transform(H, (uint32_t*)m, blocks_cnt);

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
	uint64_t length = LITTLE_ENDIAN64(s * 8);
	memcpy(last_blocks + last_blocks_size - sizeof(uint64_t), &length, sizeof(uint64_t));

	// hash process the last blocks
	__md4_transform(H, (uint32_t*)last_blocks, last_blocks_size / 64);

	// compose the digest
	((uint32_t*)d)[0] = LITTLE_ENDIAN32(H[0]);
	((uint32_t*)d)[1] = LITTLE_ENDIAN32(H[1]);
	((uint32_t*)d)[2] = LITTLE_ENDIAN32(H[2]);
	((uint32_t*)d)[3] = LITTLE_ENDIAN32(H[3]);
}


