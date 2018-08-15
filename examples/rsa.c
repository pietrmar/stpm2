#include <stdio.h>

#include <stpm2.h>
#include <stpm2_log.h>

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret;

	ret = stpm2_init(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_init() failed");
		return 1;
	}

	ret = stpm2_create_rsa_2048(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_create_rsa_2048() failed");
		ret = 1;
		goto cleanup;
	}

	ret = stpm2_export_pubkey_pem(&ctx, "/tmp/pubkey.pem");
	if (ret < 0) {
		LOG_ERROR("stpm2_export_pubkey_pem() failed");
		ret = -1;
		goto cleanup;
	}

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		return 1;
	}

	return ret;
}
