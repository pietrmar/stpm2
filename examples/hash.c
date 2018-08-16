#include <stdio.h>
#include <string.h>

#include <stpm2.h>
#include <stpm2_log.h>

static void print_hash(const char *header, uint8_t *buf, int size)
{
	printf("header");
	for (int i = 0; i < size; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	const char *testdata = "This is a teststring!";
	stpm2_context ctx;
	int ret = 0;
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
		ret = 1;
		goto cleanup;
	}
	print_hash("SHA1 hash: ", outbuf, ret);


	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA256, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_ERROR("stpm2_hash() failed\n");
		ret = 1;
		goto cleanup;
	}
	print_hash("SHA256 hash: ", outbuf, ret);

	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA384, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_ERROR("stpm2_hash() failed\n");
		ret = 1;
		goto cleanup;
	}
	print_hash("SHA384 hash: ", outbuf, ret);

	/* NOTE: this might fail on some TPMs since they do not implement sha512 (like the simulator) */
	ret = stpm2_hash(&ctx, STPM2_HASH_ALG_SHA512, (const uint8_t *)testdata, strlen(testdata), outbuf, sizeof(outbuf));
	if (ret < 0) {
		LOG_INFO("stpm2_hash() failed, this was most likely to be expected");
		ret = 1;
		goto cleanup;
	}
	print_hash("SHA512 hash: ", outbuf, ret);

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed\n");
		ret = 1;
	}

	return ret;
}

