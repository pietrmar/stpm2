#include <stdio.h>
#include <string.h>

#include <stpm2.h>

int main(int argc, char *argv[])
{
	const char *teststring = "This is a test!";
	stpm2_context ctx;
	int ret;
	uint8_t outbuf[64];

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		printf("stpm2_init() failed\n");
		return 1;
	}


	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA1, (const uint8_t *)teststring, strlen(teststring), outbuf, sizeof(outbuf));
	if (ret < 0) {
		printf("stpm2_hash() failed\n");
		return 1;
	}

	size_t i;
	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");


	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA256, (const uint8_t *)teststring, strlen(teststring), outbuf, sizeof(outbuf));
	if (ret < 0) {
		printf("stpm2_hash() failed\n");
		return 1;
	}

	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");

	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA384, (const uint8_t *)teststring, strlen(teststring), outbuf, sizeof(outbuf));
	if (ret < 0) {
		printf("stpm2_hash() failed\n");
		return 1;
	}

	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");

	/* NOTE: this might fail on some TPMs since they do not implement sha512 (like the simulator) */
	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA512, (const uint8_t *)teststring, strlen(teststring), outbuf, sizeof(outbuf));
	if (ret < 0) {
		printf("stpm2_hash() failed\n");
		return 1;
	}

	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");

	return 0;

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		printf("stpm2_free() failed\n");
		return 1;
	}

	return 0;
}
