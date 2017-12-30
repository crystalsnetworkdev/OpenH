
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

	return 0;
}

