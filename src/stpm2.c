#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include <tss2/tss2_sys.h>
#include <stpm2.h>

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

	/* Allocate and init tcti ctx */
	/* TODO */

	return 0;
}

int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size)
{
	// TPM2B_DIGEST random_bytes = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

	// TSS2_RC rval = TSS2_RETRY_EXP(Tss2_Sys_GetRandom(sapi_context, NULL, size, &random_bytes, NULL));
#if 0
	size_t i;

	for(i = 0; i < size; i++) {
		buf[i] = 42;
	}

	return 0;
#endif
}

