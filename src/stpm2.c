#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <stpm2.h>
#include <tpm2_utils.h>

static int init_tcit(stpm2_context *ctx)
{
	/*
	 * Use tabrmd for now, which is the access broker, so this should work
	 * with the simulator as well as the real device over SPI as long as an
	 * access broker is properly running.
	 */
	const char *tcti_so = "libtss2-tcti-tabrmd.so.0";

	ctx->tcti_so_handle = dlopen(tcti_so, RTLD_LAZY);
	if (!ctx->tcti_so_handle) {
		fprintf(stderr, "Failed to load %s\n", tcti_so);
		return -1;
	}

	TSS2_TCTI_INFO_FUNC infofn = (TSS2_TCTI_INFO_FUNC)dlsym(ctx->tcti_so_handle, TSS2_TCTI_INFO_SYMBOL);
	if (!infofn) {
		fprintf(stderr, "Could not find synbol %s in %s\n", TSS2_TCTI_INFO_SYMBOL, tcti_so);
		return -1;
	}

	const TSS2_TCTI_INFO *info = infofn();
	TSS2_TCTI_INIT_FUNC init = info->init;

	size_t size;
	TSS2_RC ret = init(NULL, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tcti init failed\n");
		return -1;
	}

	ctx->tcti_ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
	if (ctx->tcti_ctx == NULL) {
		return -1;
	}

	ret = init(ctx->tcti_ctx, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		fprintf(stderr, "tcti init failed\n");
		return -1;
	}

	return 0;
}

int stpm2_init(stpm2_context *ctx)
{
	TSS2_RC ret;
	TSS2_ABI_VERSION abi_version = {
		.tssCreator = 1,
		.tssFamily = 2,
		.tssLevel = 1,
		.tssVersion = 108,
	};

	/* Allocate system ctx */
	size_t ctx_size = Tss2_Sys_GetContextSize(0);

	ctx->sys_ctx = (TSS2_SYS_CONTEXT *)calloc(1, ctx_size);
	if (ctx->sys_ctx == NULL) {
		return -1;
	}

	/* TODO: handle errors */
	init_tcit(ctx);

	ret = Tss2_Sys_Initialize(ctx->sys_ctx, ctx_size, ctx->tcti_ctx, &abi_version);
	if (ret != TPM2_RC_SUCCESS) {
		return -1;
	}

	return 0;
}

int stpm2_free(stpm2_context *ctx)
{
	/* TODO: implement me */
	return 0;
}

int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size)
{
	/*TODO: check size of output buffer, the TPM2 can only deliver a limited number of random bytes on one call. */
	TPM2B_DIGEST random_bytes = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

	TSS2_RC ret = TSS2_RETRY_EXP(Tss2_Sys_GetRandom(ctx->sys_ctx, NULL, size, &random_bytes, NULL));
	if (ret != TPM2_RC_SUCCESS) {
		return -1;
	}

	size_t i;
	for(i = 0; i < size; i++) {
		buf[i] = random_bytes.buffer[i];
	}

	return 0;
}

static TPMI_ALG_HASH stpm2_to_tpmi_alg(stpm2_hash_alg alg)
{
	switch(alg) {
	case STPM2_HASH_ALG_SHA1:
		return TPM2_ALG_SHA1;
	case STPM2_HASH_ALG_SHA256:
		return TPM2_ALG_SHA256;
	case STPM2_HASH_ALG_SHA384:
		return TPM2_ALG_SHA384;
	case STPM2_HASH_ALG_SHA512:
		return TPM2_ALG_SHA512;
	}
}

int stpm2_hash(stpm2_context *ctx, stpm2_hash_alg alg, const uint8_t *buf, size_t size, uint8_t *outbuf, size_t outsize)
{
	/* TODO: handle input which is larger than TPM2_MAX_DIGEST_BUFFER */
	if (size > TPM2_MAX_DIGEST_BUFFER) {
		return -1;
	}

        TPM2B_MAX_BUFFER buffer = { .size = size };
	TPM2B_DIGEST result = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPMT_TK_HASHCHECK validation;

	memcpy(buffer.buffer, buf, size);

	TSS2_RC ret = TSS2_RETRY_EXP(Tss2_Sys_Hash(ctx->sys_ctx, NULL, &buffer, stpm2_to_tpmi_alg(alg), TPM2_RH_OWNER, &result, &validation, NULL));
	if (ret != TPM2_RC_SUCCESS) {
		return -1;
	}

	int i;
	for (i = 0; i < outsize && i < result.size; i++) {
		outbuf[i] = result.buffer[i];
	}

	return i;
}
