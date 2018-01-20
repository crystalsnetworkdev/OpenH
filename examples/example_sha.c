
#include <stdio.h>

#include "openhl/sha.h"

// The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents. We live on a placid island of ignorance in the midst of black seas of infinity, and it was not meant that we should voyage far. The sciences, each straining in its own direction, have hitherto harmed us little; but some day the piecing together of dissociated knowledge will open up such terrifying vistas of reality, and of our frightful position therein, that we shall either go mad from the revelation or flee from the deadly light into the peace and safety of a new dark age. Theosophists have guessed at the awesome grandeur of the cosmic cycle wherein our world and human race form transient incidents. They have hinted at strange survivals in terms which would freeze the blood if not masked by a bland optimism. But it is not from them that there came the single glimpse of forbidden aeons which chills me when I think of it and maddens me when I dream of it. That glimpse, like all dread glimpses of truth, flashed out from an accidental piecing together of separated things—in this case an old newspaper item and the notes of a dead professor. I hope that no one else will accomplish this piecing out; certainly, if I live, I shall never knowingly supply a link in so hideous a chain. I think that the professor, too, intended to keep silent regarding the part he knew, and that he would have destroyed his notes had not sudden death seized him.

static const uint8_t Message[1470] =
	"The most merciful thing in the world, I think, is the inability of the human mind to correlate all its contents. "
	"We live on a placid island of ignorance in the midst of black seas of infinity, and it was not meant that we should voyage far. "
	"The sciences, each straining in its own direction, have hitherto harmed us little; "
	"but some day the piecing together of dissociated knowledge will open up such terrifying vistas of reality, "
	"and of our frightful position therein, that we shall either go mad from the revelation or flee from the deadly light into the peace and safety of a new dark age. "
	"Theosophists have guessed at the awesome grandeur of the cosmic cycle wherein our world and human race form transient incidents. "
	"They have hinted at strange survivals in terms which would freeze the blood if not masked by a bland optimism. "
	"But it is not from them that there came the single glimpse of forbidden aeons which chills me when I think of it and maddens me when I dream of it. "
	"That glimpse, like all dread glimpses of truth, flashed out from an accidental piecing together of separated things—in this case an old newspaper item and the notes of a dead professor. "
	"I hope that no one else will accomplish this piecing out; certainly, if I live, I shall never knowingly supply a link in so hideous a chain. "
	"I think that the professor, too, intended to keep silent regarding the part he knew, and that he would have destroyed his notes had not sudden death seized him.";

void print_digest(const uint8_t* digest, size_t size)
{
	for(size_t i = 0; i < size; ++i)
	{
		printf("%02x", digest[i]);
	}

	printf("\n");
}

int main(int argc, char* argv[])
{
	// 57ee682c6684aa8c8684f4e5ace5a44b688eef4a
	{
		uint8_t digest[SHA1_DIGEST_SIZE];

		sha1(digest, Message, sizeof(Message));

		printf("SHA-1       : ");

		print_digest(digest, SHA1_DIGEST_SIZE);
	}

	// 237979924d5c88812052a4699cc37c4cb4c4d3d5fb60ca84ca93a607152f4b2e
	{
		uint8_t digest[SHA256_DIGEST_SIZE];

		sha256(digest, Message, sizeof(Message));

		printf("SHA-256     : ");

		print_digest(digest, SHA256_DIGEST_SIZE);
	}

	// 8808cd59128c58534523de858115092d6d08aa03e96758495c16f3ca
	{
		uint8_t digest[SHA224_DIGEST_SIZE];

		sha224(digest, Message, sizeof(Message));

		printf("SHA-224     : ");

		print_digest(digest, SHA224_DIGEST_SIZE);
	}

	// 555f92af04069fddb65e80449b9046d871b923494e7d51cf748595a574be7f6f630e9172acb10e4826efce5e97841d2602695cc7bd66e262fe92bdd8172688c6
	{
		uint8_t digest[SHA512_DIGEST_SIZE];

		sha512(digest, Message, sizeof(Message));

		printf("SHA-512     : ");

		print_digest(digest, SHA512_DIGEST_SIZE);
	}

	// dadb9dbd987fe35fa144370888b2486db83d8dd2aa6674c3812b9b691319534dd18e980ec3f32415e42f771e35912953
	{
		uint8_t digest[SHA384_DIGEST_SIZE];

		sha384(digest, Message, sizeof(Message));

		printf("SHA-384     : ");

		print_digest(digest, SHA384_DIGEST_SIZE);
	}

	// ee7f117562ef30f817a70e185688ddb2113629c9c14b8805c5ba1a86f1452c4b
	{
		uint8_t digest[SHA256_DIGEST_SIZE];

		sha512_256(digest, Message, sizeof(Message));

		printf("SHA-512/256 : ");

		print_digest(digest, SHA256_DIGEST_SIZE);
	}

	// 4919e48395c49b6c5a6b06e1f36fb12e3d935f3188e8f429edeafbc0
	{
		uint8_t digest[SHA224_DIGEST_SIZE];

		sha512_224(digest, Message, sizeof(Message));

		printf("SHA-512/224 : ");

		print_digest(digest, SHA224_DIGEST_SIZE);
	}

	// cb5e3161f13371fc4a0168398a8390414aa7c4af15f797d52659b81b
	{
		uint8_t digest[SHA3_224_DIGEST_SIZE];

		sha3_224(digest, Message, sizeof(Message));

		printf("SHA3-224    : ");

		print_digest(digest, SHA3_224_DIGEST_SIZE);
	}

	// 6328565230f982516aa6d83acce7f332f9d53f93536c3b611636a539a5ae635d
	{
		uint8_t digest[SHA3_256_DIGEST_SIZE];

		sha3_256(digest, Message, sizeof(Message));

		printf("SHA3-256    : ");

		print_digest(digest, SHA3_256_DIGEST_SIZE);
	}

	// 79196a37bea5f07fc4da6e0c4aaac0892bd28e7686c86ce64cc6ce3b1e1602d54f9f71ba760cbba8841ddd0e9756a47f
	{
		uint8_t digest[SHA3_384_DIGEST_SIZE];

		sha3_384(digest, Message, sizeof(Message));

		printf("SHA3-384    : ");

		print_digest(digest, SHA3_384_DIGEST_SIZE);
	}

	// 0ace04f37a201219a04d273ee464fda10e498b7016a471c7994c10f8d7bc06fd07fd0d5685e98df1b721336e21446cffe7694a235d4b81201fdbb0ae3afcb3a0
	{
		uint8_t digest[SHA3_512_DIGEST_SIZE];

		sha3_512(digest, Message, sizeof(Message));

		printf("SHA3-512    : ");

		print_digest(digest, SHA3_512_DIGEST_SIZE);
	}

	// 75c9ee6529509a85e36ff1c934673362
	{
		uint8_t digest[16];

		shake128(digest, Message, sizeof(Message), sizeof(digest));

		printf("SHAKE128    : ");

		print_digest(digest, sizeof(digest));
	}

	// 55127d24d4c7c89869cf5cbefa86acde
	{
		uint8_t digest[16];

		shake256(digest, Message, sizeof(Message), sizeof(digest));

		printf("SHAKE256    : ");

		print_digest(digest, sizeof(digest));
	}

	return 0;
}

