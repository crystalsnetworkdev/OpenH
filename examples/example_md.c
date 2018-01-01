
#include <stdio.h>

#include "openhl/md.h"

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
	// 5c7f8672e958cc90da362fcf5d43c2a1
	{
		uint8_t digest[MD5_DIGEST_SIZE];

		md5(digest, Message, sizeof(Message));

		printf("MD5      : ");

		print_digest(digest, MD5_DIGEST_SIZE);
	}

	return 0;
}

