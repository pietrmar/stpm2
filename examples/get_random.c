#include <stdio.h>

#include <stpm2.h>
#include <stpm2_log.h>

#define NUM_RANDOM_BYTES 32

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret;
	uint8_t random_bytes[NUM_RANDOM_BYTES];

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		printf("stpm2_init() failed\n");
		return 1;
	}

	ret = stpm2_get_random(&ctx, random_bytes, NUM_RANDOM_BYTES);
	if (ret < 0) {
		printf("stpm2_get_random() failed\n");
		return 1;
	}

	LOG_HEXDUMP(STPM2_LOG_LEVEL_INFO,
			"Random bytes",
			random_bytes,
			NUM_RANDOM_BYTES);

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		printf("stpm2_free() failed\n");
		return 1;
	}

	return 0;
}
