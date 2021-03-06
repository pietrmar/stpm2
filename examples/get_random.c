#include <stdio.h>

#include <stpm2.h>
#include <stpm2_log.h>

#define NUM_RANDOM_BYTES 32

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret = 0;
	uint8_t random_bytes[NUM_RANDOM_BYTES];

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_init() failed");
		return 1;
	}

	ret = stpm2_get_random(&ctx, random_bytes, NUM_RANDOM_BYTES);
	if (ret < 0) {
		LOG_ERROR("stpm2_get_random() failed");
		ret = 1;
		goto cleanup;
	}

	printf("Random bytes: \n");
	for (int i = 0; i < NUM_RANDOM_BYTES; i++) {
		printf("0x%02x ", random_bytes[i]);
	}
	printf("\n");

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		ret = 1;
	}

	return ret;
}

