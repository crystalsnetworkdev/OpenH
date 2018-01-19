
#include <openhl/sha/sha1.h>

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))               // CH function (4.1)
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z))) // MAJ function (4.1)
#define PARITY(x, y, z) ((x) ^ (y) ^ (z))                      // PARITY function (4.1)

#define SHA1_HASH_STEP0(t) \
	T = ROTL32(a, 5) + CH(b, c, d) + e + 0x5a827999 + w[(t)];     \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP1(t) \
	T = ROTL32(a, 5) + PARITY(b, c, d) + e + 0x6ed9eba1 + w[(t)]; \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP2(t) \
	T = ROTL32(a, 5) + MAJ(b, c, d) + e + 0x8f1bbcdc + w[(t)];    \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

#define SHA1_HASH_STEP3(t) \
	T = ROTL32(a, 5) + PARITY(b, c, d) + e + 0xca62c1d6 + w[(t)]; \
	e = d;                                                        \
	d = c;                                                        \
	c = ROTL32(b, 30);                                            \
	b = a;                                                        \
	a = T;

void __sha1_transform(uint32_t* H, const uint32_t* blocks, const size_t blocks_cnt)
{
	// the message schedule
	uint32_t w[80];

	// the five working variables
	uint32_t a, b, c, d, e;

	// a temporary variable used in the hash loops
	uint32_t T;

	// process every block
	for(size_t i = 0; i < blocks_cnt; ++i)
	{
		// prepare the message schedule
		for(size_t t =  0; t < 16; ++t)
		{
			w[t] = BIG_ENDIAN32(blocks[i * 16 + t]);
		}

		for(size_t t = 16; t < 80; ++t)
		{
			w[t] = ROTL32(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
		}

		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];

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
		H[0] += a;
		H[1] += b;
		H[2] += c;
		H[3] += d;
		H[4] += e;
	}
}

void sha1(uint8_t* d, const uint8_t* m, const size_t s)
{
	// set the initial hash value
	uint32_t H[5];
	H[0] = 0x67452301;
	H[1] = 0xefcdab89;
	H[2] = 0x98badcfe;
	H[3] = 0x10325476;
	H[4] = 0xc3d2e1f0;

	// compute the number of blocks
	size_t blocks_cnt = s / 64;

	// hash process for each block
	__sha1_transform(H, (uint32_t*)m, blocks_cnt);

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
	__sha1_transform(H, (uint32_t*)last_blocks, last_blocks_size / 64);

	// compose the digest
	((uint32_t*)d)[0] = BIG_ENDIAN32(H[0]);
	((uint32_t*)d)[1] = BIG_ENDIAN32(H[1]);
	((uint32_t*)d)[2] = BIG_ENDIAN32(H[2]);
	((uint32_t*)d)[3] = BIG_ENDIAN32(H[3]);
	((uint32_t*)d)[4] = BIG_ENDIAN32(H[4]);
}


