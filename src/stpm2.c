#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include <tss2/tss2_sys.h>
#include <tss2/tss2_tpm2_types.h>
#include <tpm2_utils.h>
#include <tpm2_error.h>

#include <stpm2.h>
#include <stpm2_log.h>

static int init_tcit(stpm2_context *ctx)
{
	TRACE_ENTER();

	/*
	 * Tested with:
	 *  * libtss2-tcti-tabrmd.so.0 (access broker, which uses the simulator at the backend)
	 *  * libtss2-tcti-mssim.so.0  (simulator)
	 */
	const char *tcti_so = "libtss2-tcti-mssim.so.0";

	ctx->tcti_so_handle = dlopen(tcti_so, RTLD_LAZY);
	if (!ctx->tcti_so_handle) {
		LOG_ERROR("Failed to load %s", tcti_so);
		return -1;
	}

	TSS2_TCTI_INFO_FUNC infofn = (TSS2_TCTI_INFO_FUNC)dlsym(ctx->tcti_so_handle, TSS2_TCTI_INFO_SYMBOL);
	if (!infofn) {
		LOG_ERROR("Could not find synbol %s in %s\n", TSS2_TCTI_INFO_SYMBOL, tcti_so);
		return -1;
	}

	const TSS2_TCTI_INFO *info = infofn();
	TSS2_TCTI_INIT_FUNC init = info->init;

	size_t size;
	TSS2_RC ret = init(NULL, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init failed with %s", tpm2_error_str(ret));
		return -1;
	}

	ctx->tcti_ctx = (TSS2_TCTI_CONTEXT *)calloc(1, size);
	if (ctx->tcti_ctx == NULL) {
		LOG_ERROR("Failed to allocate tcti_ctx");
		return -1;
	}

	ret = init(ctx->tcti_ctx, &size, NULL);
	if (ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("tcti init call failed %s", tpm2_error_str(ret));
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

#define TSS2_CHECKED_CALL(__fn__, ...) do { \
		TSS2_RC ret = __fn__(__VA_ARGS__); \
		if (ret != TSS2_RC_SUCCESS) { \
			LOG_ERROR(#__fn__"() failed with %s", tpm2_error_str(ret)); \
			return -1; \
		} \
	} while(0)

#define TSS2_CHECKED_CALL_RETRY(__fn__, ...) do { \
		TSS2_RC ret = 0; \
		do { \
			TSS2_RC ret = __fn__(__VA_ARGS__); \
			if (ret != TSS2_RC_SUCCESS && tpm2_error_get(ret) != TPM2_RC_RETRY) { \
				LOG_ERROR(#__fn__"() failed with %s", tpm2_error_str(ret)); \
				return -1; \
			} \
		} while(tpm2_error_get(ret) == TPM2_RC_RETRY); \
	} while(0)

/* Based on access_broker_flush_all_unlocked() from https://github.com/tpm2-software/tpm2-abrmd.git */
static int stpm2_flush_context_range(stpm2_context *ctx, TPM2_RH first, TPM2_RH last)
{
	TRACE_ENTER();

	TPMS_CAPABILITY_DATA capability_data = { 0 };
	TPM2_HANDLE handle;
	size_t i;

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_GetCapability,
				ctx->sys_ctx,
				NULL,
				TPM2_CAP_HANDLES,
				first,
				last - first,
				NULL,
				&capability_data,
				NULL);

	for (i = 0; i < capability_data.data.handles.count; i++) {
		handle = capability_data.data.handles.handle[i];
		TSS2_CHECKED_CALL_RETRY(Tss2_Sys_FlushContext, ctx->sys_ctx, handle);
	}

	TRACE_LEAVE();
	return 0;
}

static int stpm2_flush_all(stpm2_context *ctx)
{
	TRACE_ENTER();

	if (stpm2_flush_context_range(ctx, TPM2_ACTIVE_SESSION_FIRST, TPM2_ACTIVE_SESSION_LAST) < 0) {
		LOG_ERROR("Failed to flush active sessions");
		return -1;
	}

	if (stpm2_flush_context_range(ctx, TPM2_LOADED_SESSION_FIRST, TPM2_LOADED_SESSION_LAST) < 0) {
		LOG_ERROR("Failed to flush loaded sessions");
		return -1;
	}

	if (stpm2_flush_context_range(ctx, TPM2_TRANSIENT_FIRST, TPM2_TRANSIENT_LAST) < 0) {
		LOG_ERROR("Failed to flush transient objects");
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

/*
 * This creates a primary key with the default settings that match tpm2_createprimary,
 * they key is stored inside the stpm2_context struct
 */
static int stpm2_create_primary(stpm2_context *ctx)
{
	TRACE_ENTER();
	TSS2L_SYS_AUTH_COMMAND sessions_cmd = {
		.count = 1,
		.auths = {{ .sessionHandle = TPM2_RS_PW }},
	};

	TSS2L_SYS_AUTH_RESPONSE sessions_rsp;

	TPM2B_SENSITIVE_CREATE	in_sensitive	= { 0 };
	TPM2B_DATA		outside_info	= { 0 };
	TPM2B_CREATION_DATA	creation_data	= { 0 };
	TPM2B_DIGEST		creation_hash	= TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPM2B_PUBLIC		in_public	= { 0 };
	TPMT_TK_CREATION	creation_ticket	= { 0 };
	TPM2B_NAME		name		= TPM2B_TYPE_INIT(TPM2B_NAME, name);
	TPML_PCR_SELECTION	creation_pcr	= { 0 };
	TPM2B_PUBLIC		out_public	= { 0 };

	in_public.publicArea.type = TPM2_ALG_RSA;
	in_public.publicArea.nameAlg = TPM2_ALG_SHA256;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_RESTRICTED;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_USERWITHAUTH;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_DECRYPT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDTPM;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_FIXEDPARENT;
	in_public.publicArea.objectAttributes |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
	in_public.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM2_ALG_AES;
	in_public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 256;
	in_public.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
	in_public.publicArea.parameters.rsaDetail.keyBits = 2048;

	ctx->primary_handle = 0;
	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_CreatePrimary,
				ctx->sys_ctx,
				TPM2_RH_OWNER,
				&sessions_cmd,
				&in_sensitive,
				&in_public,
				&outside_info,
				&creation_pcr,
				&ctx->primary_handle,
				&out_public,
				&creation_data,
				&creation_hash,
				&creation_ticket,
				&name,
				&sessions_rsp);

	LOG_INFO("Created primary key with handle 0x%X", ctx->primary_handle);

	LOG_HEXDUMP(STPM2_LOG_LEVEL_DEBUG,
			"Public RSA modulus",
			out_public.publicArea.unique.rsa.buffer,
			out_public.publicArea.unique.rsa.size);

	TRACE_LEAVE();
	return 0;
}

int stpm2_init(stpm2_context *ctx)
{
	TRACE_ENTER();

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
		LOG_ERROR("Failed to allocate sys_ctx");
		return -1;
	}

	if (init_tcit(ctx) < 0) {
		LOG_ERROR("init_tcit() failed");
		return -1;
	}

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Initialize, ctx->sys_ctx, ctx_size, ctx->tcti_ctx, &abi_version);

	/* we cannot use the TSS2_CHECKED_CALL_RETRY() macro here because Tss2_Sys_Startup() can return TPM2_RC_INITIALIZE */
	ret = TSS2_RETRY_EXP(Tss2_Sys_Startup(ctx->sys_ctx, TPM2_SU_CLEAR));
	if (ret != TPM2_RC_SUCCESS && ret != TPM2_RC_INITIALIZE) {
		LOG_ERROR("Tss2_Sys_Startup() failed with %s", tpm2_error_str(ret));
		return -1;
	}

	/* Flush all objects to have a clean state */
	if (stpm2_flush_all(ctx) < 0) {
		LOG_ERROR("stpm2_flush_all() failed");
		return -1;
	}

	/* Always create a primary key */
	if (stpm2_create_primary(ctx) < 0) {
		LOG_ERROR("Failed to create primary key");
		return -1;
	}

	TRACE_LEAVE();
	return 0;
}

int stpm2_free(stpm2_context *ctx)
{
	int ret = 0;
	TRACE_ENTER();

	/* Since we are freeing memory we do not want to exit on failure in any of the following functions */
	if (stpm2_flush_all(ctx) < 0) {
		LOG_ERROR("stpm2_flush_all() failed");
		ret = -1;
	}

	TSS2_RC tss2_ret = Tss2_Sys_Shutdown(ctx->sys_ctx, NULL, TPM2_SU_CLEAR, NULL);
	if (tss2_ret != TPM2_RC_SUCCESS) {
		LOG_ERROR("Tss2_Sys_Shutdown() failed with %s", tpm2_error_str(tss2_ret));
		ret = -1;
	}

	Tss2_Sys_Finalize(ctx->sys_ctx);
	free(ctx->sys_ctx);
	ctx->sys_ctx = NULL;

	Tss2_Tcti_Finalize(ctx->tcti_ctx);
	free(ctx->tcti_ctx);
	ctx->tcti_ctx = NULL;

	if (dlclose(ctx->tcti_so_handle) != 0) {
		LOG_ERROR("dlclose() failed");
		ret = -1;
	}
	ctx->tcti_so_handle = NULL;

	TRACE_LEAVE();
	return ret;
}

int stpm2_get_random(stpm2_context *ctx, uint8_t *buf, size_t size)
{
	TRACE_ENTER();
	/*TODO: check size of output buffer, the TPM2 can only deliver a limited number of random bytes on one call. */
	TPM2B_DIGEST random_bytes = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_GetRandom, ctx->sys_ctx, NULL, size, &random_bytes, NULL);

	size_t i;
	for(i = 0; i < size; i++) {
		buf[i] = random_bytes.buffer[i];
	}

	TRACE_LEAVE();
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
	default:
		LOG_ERROR("Unknown hash algorithm specified");
		return TPM2_ALG_NULL;
	}
}

int stpm2_hash(stpm2_context *ctx, stpm2_hash_alg alg, const uint8_t *buf, size_t size, uint8_t *outbuf, size_t outsize)
{
	TRACE_ENTER();
	/* TODO: handle input which is larger than TPM2_MAX_DIGEST_BUFFER */
	if (size > TPM2_MAX_DIGEST_BUFFER) {
		LOG_ERROR("stpm2_hash() only supports buffers of up to %zu bytes", TPM2_MAX_DIGEST_BUFFER);
		return -1;
	}

        TPM2B_MAX_BUFFER buffer = { .size = size };
	TPM2B_DIGEST result = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
	TPMT_TK_HASHCHECK validation;

	memcpy(buffer.buffer, buf, size);

	TSS2_CHECKED_CALL_RETRY(Tss2_Sys_Hash, ctx->sys_ctx, NULL, &buffer, stpm2_to_tpmi_alg(alg), TPM2_RH_OWNER, &result, &validation, NULL);

	int i;
	for (i = 0; i < outsize && i < result.size; i++) {
		outbuf[i] = result.buffer[i];
	}

	TRACE_LEAVE();
	return i;
}

