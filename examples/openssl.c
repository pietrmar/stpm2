#include <stdio.h>

#include <stpm2.h>
#include <stpm2_log.h>

static void print_usage(void)
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "\texample_openssl <genkey>\n");
	fprintf(stderr, "\texample_openssl <decrypt>\n");

}

static int generate_key(void)
{
	int ret;
	stpm2_context ctx;

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

	printf("RSA key has been generated and written to /tmp/key.bin and /tmp/pubkey.pem\n");
	printf("The pubkey.pem can be used with OpenSSL:\n");
	printf("\topenssl rsautl -pubin -inkey /tmp/pubkey.pem -encrypt > /tmp/ciphertext.bin\n");
	printf("To decrypt run:\n");
	printf("\texample_openssl decrypt\n");
	printf("The decrypted output will be in /tmp/plaintext.bin\n");

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		ret = 1;
	}

	return ret;
}

static int decrypt(void)
{
	stpm2_context ctx;
	int ret;
	FILE *f;
	uint8_t input[STPM2_RSA_ENC_MESSAGE_SIZE];
	uint8_t output[STPM2_RSA_ENC_MESSAGE_SIZE];
	size_t output_size;

	f = fopen("/tmp/ciphertext.bin", "r");
	if (f == NULL) {
		LOG_ERROR("failed to open /tmp/ciphertext.bin\n");
		return 1;
	}

	/* TODO: error and size checking */
	fread(input, 1, sizeof(input), f);
	fclose(f);

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

	ret = stpm2_rsa_decrypt(&ctx, input, sizeof(input), (uint8_t *)output, sizeof(output), &output_size);
	if (ret < 0) {
		LOG_ERROR("stpm2_rsa_decrypt() failed");
		ret = 1;
		goto cleanup;
	}

	f = fopen("/tmp/plaintext.bin", "w");
	if (f == NULL) {
		LOG_ERROR("failed to open /tmp/plaintext.bin for writing");
		ret = 1;
		goto cleanup;
	}

	/* TODO: error and size checking */
	fwrite(output, 1, output_size, f);
	fclose(f);

	printf("Decrypted message has been written to /tmp/plaintext.bin\n");

cleanup:
	ret = stpm2_free(&ctx);
	if (ret < 0) {
		LOG_ERROR("stpm2_free() failed");
		ret = 1;
	}

	return ret;
}

int main(int argc, char *argv[])
{
	int ret = 0;

	if (argc < 2) {
		print_usage();
		return 1;
	}

	if (!strcmp(argv[1], "genkey")) {
		ret = generate_key();
	} else if (!strcmp(argv[1], "decrypt")) {
		ret = decrypt();
	} else {
		print_usage();
		return 1;
	}

	return ret;
}

