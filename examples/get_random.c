#include <stdio.h>

#include <stpm2.h>

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret;
	uint8_t random_bytes[16];

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		printf("stpm2_init() failed\n");
		return 1;
	}

	ret = stpm2_get_random(&ctx, random_bytes, 16);
	if (ret < 0) {
		printf("stpm2_get_random() failed\n");
		return 1;
	}

	for (int i = 0; i < 16; i++) {
		printf("0x%02x ", random_bytes[i]);
	}

	printf("\n");

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		printf("stpm2_free() failed\n");
		return 1;
	}

	return 0;
}
