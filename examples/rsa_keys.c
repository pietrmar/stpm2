#include <stdio.h>

#include <stpm2.h>
#include <stpm2_log.h>

int main(int argc, char *argv[])
{
	stpm2_context ctx;
	int ret = 0;

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
		ret = 1;
		goto cleanup;
	}

	ret = stpm2_export_key(&ctx, "/tmp/key.bin");
	if (ret < 0) {
		LOG_ERROR("stpm2_export_key() failed");
		ret = 1;
		goto cleanup;
	}

	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		return 1;
	}

	/* Re-start a new STPM2 session (all keys are flushed at this point) */
	ret = stpm2_init(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_init() failed");
		return 1;
	}

	/* Load the key which was exported in the previous session */
	ret = stpm2_load_key(&ctx, "/tmp/key.bin");
	if (ret < 0) {
		LOG_ERROR("stpm2_load_key() failed");
		ret = 1;
		goto cleanup;
	}

	ret = stpm2_export_pubkey_pem(&ctx, "/tmp/pubkey2.pem");
	if (ret < 0) {
		LOG_ERROR("stpm2_export_pubkey_pem() failed");
		ret = 1;
		goto cleanup;
	}

	ret = stpm2_export_key(&ctx, "/tmp/key2.bin");
	if (ret < 0) {
		LOG_ERROR("stpm2_export_key() failed");
		ret = 1;
		goto cleanup;
	}

	/*
	 * At this point the pubkey and the full key have been re-exported,
	 * the checksums should be the same.
	 *   md5sum /tmp/pubkey*.pem
	 *   md5sum /tmp/key*.bin
	 */

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		ret = 1;
	}

	return ret;
}

