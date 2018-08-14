#include <stdio.h>
#include <string.h>

#include <stpm2.h>
#include <stpm2_log.h>

int main(int argc, char *argv[])
{
	const char *testdata = "This is a teststring!";
	stpm2_context ctx;
	int ret;
	uint8_t outbuf[64];

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_init() failed");
		return 1;
	}

	printf("Data to hash: %s\n", testdata);

	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA1, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_ERROR("stpm2_hash() failed");
		return 1;
	}

	size_t i;
	printf("SHA1 hash: ");
	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");


	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA256, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_ERROR("stpm2_hash() failed\n");
		return 1;
	}

	printf("SHA256 hash: ");
	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");

	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA384, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_ERROR("stpm2_hash() failed\n");
		return 1;
	}

	printf("SHA384 hash: ");
	for (i = 0; i < ret; i++) {
		printf("%02x", outbuf[i]);
	}
	printf("\n");

	/* NOTE: this might fail on some TPMs since they do not implement sha512 (like the simulator) */
	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA512, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_INFO("stpm2_hash() failed, this was most likely to be expected");
	} else {
		printf("SHA512 hash: ");
		for (i = 0; i < ret; i++) {
			printf("%02x", outbuf[i]);
		}
		printf("\n");
	}

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed\n");
		return 1;
	}

	return 0;
}
